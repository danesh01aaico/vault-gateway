//go:build e2e

// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package e2e contains end-to-end / integration tests for the vault-gateway.
// Every file in this package is guarded by the `e2e` build tag so the suite is
// excluded from the default `go test ./...` run. Execute it explicitly with:
//
//	go test -tags=e2e ./e2e/...
//
// The core flow in this file (and vault_test.go) is fully self-contained: it
// stands up an in-process gateway wired to fakes/fake servers and needs no
// external services, so it runs unconditionally in CI. The cloud suites
// (aws_test.go, azure_test.go) skip unless their endpoint env vars are set.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/internal/auth"
	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/server"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// roleName is the role exercised by the in-process end-to-end flow.
const roleName = "opus-workloads"

// fakeBackend is an in-memory backend.SecretBackend. A path present in secrets
// resolves to its map; any other path returns ErrSecretNotFound. healthy
// toggles HealthCheck behaviour.
type fakeBackend struct {
	secrets map[string]map[string]string
	healthy bool
}

var _ backend.SecretBackend = (*fakeBackend)(nil)

func (f *fakeBackend) GetSecret(_ context.Context, path string) (map[string]string, error) {
	v, ok := f.secrets[path]
	if !ok {
		return nil, backend.ErrSecretNotFound
	}
	// Return a copy: the handler scrubs the returned map after writing.
	out := make(map[string]string, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out, nil
}

func (f *fakeBackend) HealthCheck(_ context.Context) error {
	if !f.healthy {
		return backend.ErrBackendUnavailable
	}
	return nil
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Close() error { return nil }

// fakeValidator is an auth.TokenValidator that always authenticates the JWT as a
// fixed identity (namespace "opus-apps", service account "web", uid "uid-123").
type fakeValidator struct{}

var _ auth.TokenValidator = (*fakeValidator)(nil)

func (fakeValidator) ValidateK8sJWT(_ context.Context, _ string) (*auth.Identity, error) {
	return &auth.Identity{
		ServiceAccount:    "web",
		ServiceAccountUID: "uid-123",
		Namespace:         "opus-apps",
	}, nil
}

// gateway bundles a running in-process gateway and a client for driving it.
type gateway struct {
	server *httptest.Server
	client *http.Client
	role   string
}

// newGateway builds a full in-process gateway around b: fake validator, real
// TokenStore + RBAC, real handlers/router/middleware, served over plain HTTP via
// httptest. It is the shared harness used by both e2e_test.go and vault_test.go.
func newGateway(t *testing.T, b backend.SecretBackend) *gateway {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tokens := auth.NewTokenStore(0)
	rbac := auth.NewRBAC(map[string]auth.Role{
		roleName: {
			AllowedNamespaces:      []string{"opus-apps"},
			AllowedServiceAccounts: []string{"*"},
			AllowedPaths:           []string{"opus/*"},
		},
	})

	handlers := api.NewHandlers(api.Config{
		Backend:             b,
		Validator:           fakeValidator{},
		Tokens:              tokens,
		RBAC:                rbac,
		Logger:              logger,
		DefaultTokenTTL:     time.Hour,
		BackendHealthCheck:  true,
		BackendCheckTimeout: 2 * time.Second,
		ClusterID:           "e2e-cluster",
	})

	router := server.NewRouter(handlers)
	mw := server.NewMiddleware(
		logger,
		nil,   // metrics
		1<<20, // max body
		false, // tlsEnabled
		config.RateLimitConfig{Enabled: false},
		config.CORSConfig{Enabled: false},
	)

	srv := httptest.NewServer(mw.Chain(router))
	t.Cleanup(srv.Close)

	return &gateway{server: srv, client: srv.Client(), role: roleName}
}

// login performs the kubernetes login flow and returns the issued client token.
func (g *gateway) login(t *testing.T) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"jwt": "x", "role": g.role})
	resp, err := g.client.Post(g.server.URL+"/v1/auth/kubernetes/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var auth vaultresponse.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	if auth.Auth == nil || auth.Auth.ClientToken == "" {
		t.Fatalf("login returned no client token: %+v", auth.Auth)
	}
	return auth.Auth.ClientToken
}

// readSecret issues GET /v1/secret/data/<path> with the given token and returns
// the raw response for the caller to assert on.
func (g *gateway) readSecret(t *testing.T, path, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, g.server.URL+"/v1/secret/data/"+path, nil)
	if err != nil {
		t.Fatalf("build read request: %v", err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	return resp
}

// decodeErrors reads a Vault-shaped error envelope from resp.
func decodeErrors(t *testing.T, resp *http.Response) []string {
	t.Helper()
	var e vaultresponse.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return e.Errors
}

// TestEndToEndVaultEnvFlow exercises the full vault-env request flow against an
// in-process gateway with no external dependencies.
func TestEndToEndVaultEnvFlow(t *testing.T) {
	be := &fakeBackend{
		healthy: true,
		secrets: map[string]map[string]string{
			"opus/workflow-engine": {"db_password": "s3cr3t"},
		},
	}
	g := newGateway(t, be)

	// 1. Health.
	t.Run("health", func(t *testing.T) {
		resp, err := g.client.Get(g.server.URL + "/v1/sys/health")
		if err != nil {
			t.Fatalf("health request: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health status = %d, want 200", resp.StatusCode)
		}
		var h vaultresponse.HealthResponse
		if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
			t.Fatalf("decode health: %v", err)
		}
		if !h.Initialized || h.Sealed {
			t.Fatalf("health initialized=%v sealed=%v, want true/false", h.Initialized, h.Sealed)
		}
	})

	// 2. Login.
	token := g.login(t)

	// 3. Authorized read of the seeded secret.
	t.Run("read_authorized", func(t *testing.T) {
		resp := g.readSecret(t, "opus/workflow-engine", token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read status = %d, want 200", resp.StatusCode)
		}
		var s vaultresponse.SecretResponse
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			t.Fatalf("decode secret: %v", err)
		}
		if got := s.Data.Data["db_password"]; got != "s3cr3t" {
			t.Fatalf("data.data.db_password = %q, want %q", got, "s3cr3t")
		}
		if len(s.Data.Data) != 1 {
			t.Fatalf("data.data has %d keys, want 1: %+v", len(s.Data.Data), s.Data.Data)
		}

		// Assert the exact JSON field shape vault-env depends on.
		resp2 := g.readSecret(t, "opus/workflow-engine", token)
		defer resp2.Body.Close()
		raw, _ := io.ReadAll(resp2.Body)
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("unmarshal envelope: %v", err)
		}
		if _, ok := envelope["data"]; !ok {
			t.Fatalf("response missing top-level \"data\": %s", raw)
		}
		var dataObj map[string]json.RawMessage
		if err := json.Unmarshal(envelope["data"], &dataObj); err != nil {
			t.Fatalf("unmarshal data: %v", err)
		}
		if _, ok := dataObj["data"]; !ok {
			t.Fatalf("response missing data.data: %s", raw)
		}
		if _, ok := dataObj["metadata"]; !ok {
			t.Fatalf("response missing data.metadata: %s", raw)
		}
	})

	// 4. Bogus token -> 403 permission denied.
	t.Run("read_bogus_token", func(t *testing.T) {
		resp := g.readSecret(t, "opus/workflow-engine", "deadbeef-not-a-real-token")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		errs := decodeErrors(t, resp)
		if len(errs) != 1 || errs[0] != "permission denied" {
			t.Fatalf("errors = %v, want [\"permission denied\"]", errs)
		}
	})

	// 5. Valid token, unauthorized path -> 403 permission denied.
	t.Run("read_unauthorized_path", func(t *testing.T) {
		resp := g.readSecret(t, "other/secret", token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		errs := decodeErrors(t, resp)
		if len(errs) != 1 || errs[0] != "permission denied" {
			t.Fatalf("errors = %v, want [\"permission denied\"]", errs)
		}
	})

	// 6. Valid token, allowed-but-missing path -> 404 secret not found.
	t.Run("read_not_found", func(t *testing.T) {
		resp := g.readSecret(t, "opus/missing", token)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		errs := decodeErrors(t, resp)
		if len(errs) != 1 || errs[0] != "secret not found" {
			t.Fatalf("errors = %v, want [\"secret not found\"]", errs)
		}
	})
}

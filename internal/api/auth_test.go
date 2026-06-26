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

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vault-gateway/vault-gateway/internal/auth"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

var (
	hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// fakeValidator is an auth.TokenValidator test double returning a canned
// identity or error.
type fakeValidator struct {
	identity *auth.Identity
	err      error
}

func (f *fakeValidator) ValidateK8sJWT(_ context.Context, _ string) (*auth.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	// Return a copy so the handler's mutation of Role does not bleed across calls.
	id := *f.identity
	return &id, nil
}

// testRBAC builds an RBAC with a single "web" role bound to the opus namespace.
func testRBAC() *auth.RBAC {
	return auth.NewRBAC(map[string]auth.Role{
		"web": {
			AllowedNamespaces:      []string{"opus"},
			AllowedServiceAccounts: []string{"web-sa"},
			AllowedPaths:           []string{"opus/*", "opus/**"},
		},
	})
}

func testIdentity() *auth.Identity {
	return &auth.Identity{
		ServiceAccount:    "web-sa",
		ServiceAccountUID: "uid-1234",
		Namespace:         "opus",
	}
}

func loginBody(t *testing.T, jwt, role string) io.Reader {
	t.Helper()
	b, err := json.Marshal(loginRequest{JWT: jwt, Role: role})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	return bytes.NewReader(b)
}

func decodeAuth(t *testing.T, rr *httptest.ResponseRecorder) vaultresponse.AuthResponse {
	t.Helper()
	var ar vaultresponse.AuthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &ar); err != nil {
		t.Fatalf("unmarshal auth response: %v (body=%q)", err, rr.Body.String())
	}
	return ar
}

func TestK8sLoginSuccess(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	m := metrics.New()
	h := NewHandlers(Config{
		Validator:       &fakeValidator{identity: testIdentity()},
		Tokens:          tokens,
		RBAC:            testRBAC(),
		Metrics:         m,
		DefaultTokenTTL: 30 * time.Minute,
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, "jwt-token", "web"))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rr.Code, rr.Body.String())
	}
	ar := decodeAuth(t, rr)
	if ar.Auth == nil {
		t.Fatal("Auth is nil")
	}
	a := ar.Auth
	if !hex64Re.MatchString(a.ClientToken) {
		t.Errorf("ClientToken = %q, want 64 hex chars", a.ClientToken)
	}
	if !hex40Re.MatchString(a.Accessor) {
		t.Errorf("Accessor = %q, want 40 hex chars", a.Accessor)
	}
	if len(a.Policies) != 2 || a.Policies[0] != "default" || a.Policies[1] != "web" {
		t.Errorf("Policies = %v, want [default web]", a.Policies)
	}
	if a.Metadata["role"] != "web" ||
		a.Metadata["service_account_name"] != "web-sa" ||
		a.Metadata["service_account_namespace"] != "opus" ||
		a.Metadata["service_account_uid"] != "uid-1234" {
		t.Errorf("Metadata = %v", a.Metadata)
	}
	if a.LeaseDuration != int((30*time.Minute)/time.Second) {
		t.Errorf("LeaseDuration = %d, want %d", a.LeaseDuration, int((30*time.Minute)/time.Second))
	}
	if a.TokenType != "service" {
		t.Errorf("TokenType = %q, want service", a.TokenType)
	}
	if !a.Orphan {
		t.Error("Orphan = false, want true")
	}

	// The issued token must verify in the store with the role set.
	id, err := tokens.VerifyToken(a.ClientToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if id.Role != "web" || id.Namespace != "opus" || id.ServiceAccount != "web-sa" {
		t.Errorf("verified identity = %+v", id)
	}

	if got := testutil.ToFloat64(m.AuthRequests.WithLabelValues("success", "web")); got != 1 {
		t.Errorf("auth success counter = %v, want 1", got)
	}
}

func TestK8sLoginMalformedJSON(t *testing.T) {
	h := NewHandlers(Config{
		Validator: &fakeValidator{identity: testIdentity()},
		Tokens:    auth.NewTokenStore(0),
		RBAC:      testRBAC(),
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", bytes.NewReader([]byte("{not json")))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestK8sLoginMissingFields(t *testing.T) {
	h := NewHandlers(Config{
		Validator: &fakeValidator{identity: testIdentity()},
		Tokens:    auth.NewTokenStore(0),
		RBAC:      testRBAC(),
	})

	for _, tc := range []struct {
		name, jwt, role string
	}{
		{"missing jwt", "", "web"},
		{"missing role", "jwt", ""},
		{"missing both", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, tc.jwt, tc.role))
			h.K8sLoginHandler(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
		})
	}
}

func TestK8sLoginInvalidToken(t *testing.T) {
	m := metrics.New()
	h := NewHandlers(Config{
		Validator: &fakeValidator{err: auth.ErrInvalidToken},
		Tokens:    auth.NewTokenStore(0),
		RBAC:      testRBAC(),
		Metrics:   m,
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, "bad-jwt", "web"))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	er := decodeError(t, rr)
	if len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want exactly [permission denied]", er.Errors)
	}
	if got := testutil.ToFloat64(m.AuthRequests.WithLabelValues("failure", "web")); got != 1 {
		t.Errorf("auth failure counter = %v, want 1", got)
	}
}

func TestK8sLoginRBACDenied(t *testing.T) {
	// Identity is valid, but the binding does not permit this namespace/SA.
	wrong := &auth.Identity{ServiceAccount: "other-sa", Namespace: "other-ns"}
	h := NewHandlers(Config{
		Validator: &fakeValidator{identity: wrong},
		Tokens:    auth.NewTokenStore(0),
		RBAC:      testRBAC(),
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, "jwt", "web"))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	er := decodeError(t, rr)
	if len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want [permission denied]", er.Errors)
	}
}

func TestK8sLoginUnknownRole(t *testing.T) {
	h := NewHandlers(Config{
		Validator: &fakeValidator{identity: testIdentity()},
		Tokens:    auth.NewTokenStore(0),
		RBAC:      testRBAC(),
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, "jwt", "nonexistent"))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want [permission denied]", er.Errors)
	}
}

func TestK8sLoginPerRoleTTL(t *testing.T) {
	h := NewHandlers(Config{
		Validator:       &fakeValidator{identity: testIdentity()},
		Tokens:          auth.NewTokenStore(0),
		RBAC:            testRBAC(),
		DefaultTokenTTL: 30 * time.Minute,
		RoleTokenTTL:    map[string]time.Duration{"web": 5 * time.Minute},
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/kubernetes/login", loginBody(t, "jwt", "web"))
	h.K8sLoginHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	ar := decodeAuth(t, rr)
	if want := int((5 * time.Minute) / time.Second); ar.Auth.LeaseDuration != want {
		t.Errorf("LeaseDuration = %d, want %d (per-role override)", ar.Auth.LeaseDuration, want)
	}
}

// TestK8sLoginFullRoundTrip exercises the handler through an httptest.Server.
func TestK8sLoginFullRoundTrip(t *testing.T) {
	h := NewHandlers(Config{
		Validator:       &fakeValidator{identity: testIdentity()},
		Tokens:          auth.NewTokenStore(0),
		RBAC:            testRBAC(),
		DefaultTokenTTL: 10 * time.Minute,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/kubernetes/login", h.K8sLoginHandler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/auth/kubernetes/login", "application/json", loginBody(t, "jwt", "web"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var ar vaultresponse.AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ar.Auth == nil || !hex64Re.MatchString(ar.Auth.ClientToken) {
		t.Fatalf("unexpected auth response: %+v", ar.Auth)
	}
}

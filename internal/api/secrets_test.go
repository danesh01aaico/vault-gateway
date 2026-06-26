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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vault-gateway/vault-gateway/internal/auth"
	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// newSecretMux wires the SecretReadHandler under a ServeMux so r.PathValue
// ("path") is populated exactly as in production routing.
func newSecretMux(h *Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secret/data/{path...}", h.SecretReadHandler)
	return mux
}

// issueToken mints a token in the store for the web-sa identity bound to "web".
func issueWebToken(t *testing.T, tokens *auth.TokenStore) string {
	t.Helper()
	id := auth.Identity{
		ServiceAccount:    "web-sa",
		ServiceAccountUID: "uid-1234",
		Namespace:         "opus",
		Role:              "web",
	}
	tok, _, err := tokens.IssueToken(id, 30*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	return tok
}

func decodeSecret(t *testing.T, body []byte) vaultresponse.SecretResponse {
	t.Helper()
	var sr vaultresponse.SecretResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatalf("unmarshal secret response: %v (body=%q)", err, string(body))
	}
	return sr
}

func TestSecretReadSuccess(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{name: "aws", data: map[string]string{"username": "admin", "password": "s3cret"}}
	m := metrics.New()
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: m})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req.Header.Set("X-Vault-Token", tok)
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rr.Code, rr.Body.String())
	}
	sr := decodeSecret(t, rr.Body.Bytes())
	want := map[string]string{"username": "admin", "password": "s3cret"}
	if !reflect.DeepEqual(sr.Data.Data, want) {
		t.Errorf("data.data = %v, want %v", sr.Data.Data, want)
	}
	if sr.Data.Metadata.Version != 1 {
		t.Errorf("metadata.version = %d, want 1", sr.Data.Metadata.Version)
	}
	if got := testutil.ToFloat64(m.SecretRequests.WithLabelValues("success", "aws")); got != 1 {
		t.Errorf("secret success counter = %v, want 1", got)
	}
}

func TestSecretReadMissingToken(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	be := &mockBackend{data: map[string]string{"k": "v"}}
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: metrics.New()})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	// No X-Vault-Token header.
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want [permission denied]", er.Errors)
	}
	if be.getCalled {
		t.Error("backend GetSecret should not be called for invalid token")
	}
}

func TestSecretReadInvalidToken(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	be := &mockBackend{data: map[string]string{"k": "v"}}
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: metrics.New()})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req.Header.Set("X-Vault-Token", "deadbeef")
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want [permission denied]", er.Errors)
	}
}

// TestSecretReadPathDeniedSameAsInvalid asserts the denied-by-RBAC body is
// byte-identical to the invalid-token body so neither leaks which check failed.
func TestSecretReadPathDeniedSameAsInvalid(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{data: map[string]string{"k": "v"}}
	m := metrics.New()
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: m})

	// "other/path" is not in the role's AllowedPaths.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/other/path", nil)
	req.Header.Set("X-Vault-Token", tok)
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	deniedBody := rr.Body.String()

	// Compare to an invalid-token response.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req2.Header.Set("X-Vault-Token", "deadbeef")
	newSecretMux(h).ServeHTTP(rr2, req2)
	if rr2.Body.String() != deniedBody {
		t.Errorf("path-denied body %q != invalid-token body %q", deniedBody, rr2.Body.String())
	}
	if be.getCalled {
		t.Error("backend GetSecret should not be called when RBAC denies")
	}
	if got := testutil.ToFloat64(m.SecretRequests.WithLabelValues("denied", "mock")); got != 2 {
		t.Errorf("secret denied counter = %v, want 2", got)
	}
}

func TestSecretReadNotFound(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{name: "aws", getErr: backend.ErrSecretNotFound}
	m := metrics.New()
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: m})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req.Header.Set("X-Vault-Token", tok)
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "secret not found" {
		t.Fatalf("errors = %v, want [secret not found]", er.Errors)
	}
	if got := testutil.ToFloat64(m.SecretRequests.WithLabelValues("not_found", "aws")); got != 1 {
		t.Errorf("not_found counter = %v, want 1", got)
	}
}

func TestSecretReadBackendUnavailable(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{name: "aws", getErr: backend.ErrBackendUnavailable}
	m := metrics.New()
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: m})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req.Header.Set("X-Vault-Token", tok)
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
	if got := testutil.ToFloat64(m.SecretRequests.WithLabelValues("error", "aws")); got != 1 {
		t.Errorf("error counter = %v, want 1", got)
	}
}

func TestSecretReadBackendGenericError(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{name: "aws", getErr: errors.New("kaboom")}
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: metrics.New()})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/opus/web", nil)
	req.Header.Set("X-Vault-Token", tok)
	newSecretMux(h).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "backend error" {
		t.Fatalf("errors = %v, want [backend error]", er.Errors)
	}
}

func TestSecretReadPathTraversal(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{data: map[string]string{"k": "v"}}
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: metrics.New()})

	rr := httptest.NewRecorder()
	// A ServeMux would clean "opus/../etc" before dispatch, so set the path
	// value directly to drive it straight into validatePath as production would
	// see a traversal payload.
	req := httptest.NewRequest(http.MethodGet, "/v1/secret/data/x", nil)
	req.SetPathValue("path", "opus/../etc")
	req.Header.Set("X-Vault-Token", tok)
	h.SecretReadHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%q)", rr.Code, rr.Body.String())
	}
	if er := decodeError(t, rr); len(er.Errors) != 1 || er.Errors[0] != "invalid secret path" {
		t.Fatalf("errors = %v, want [invalid secret path]", er.Errors)
	}
}

func TestValidatePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid", "opus/web", false},
		{"valid single", "opus", false},
		{"empty", "", true},
		{"traversal", "opus/../etc", true},
		{"dotdot bare", "..", true},
		{"null byte", "opus/\x00bad", true},
		{"control char", "opus/\x01bad", true},
		{"del char", "opus/\x7fbad", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePath(tc.path)
			if tc.wantErr && err == nil {
				t.Errorf("validatePath(%q) = nil, want error", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validatePath(%q) = %v, want nil", tc.path, err)
			}
		})
	}
}

func TestSecretReadFullRoundTrip(t *testing.T) {
	tokens := auth.NewTokenStore(0)
	tok := issueWebToken(t, tokens)
	be := &mockBackend{name: "aws", data: map[string]string{"api_key": "xyz"}}
	h := NewHandlers(Config{Backend: be, Tokens: tokens, RBAC: testRBAC(), Metrics: metrics.New()})

	srv := httptest.NewServer(newSecretMux(h))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/secret/data/opus/web", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Vault-Token", tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var sr vaultresponse.SecretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr.Data.Data["api_key"] != "xyz" {
		t.Errorf("data = %v, want api_key=xyz", sr.Data.Data)
	}
}

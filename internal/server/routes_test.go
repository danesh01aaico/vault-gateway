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

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/internal/auth"
)

// stubBackend is a configurable SecretBackend test double shared across the
// server package tests.
type stubBackend struct {
	name        string
	healthErr   error
	getSecret   map[string]string
	getErr      error
	closeErr    error
	healthCalls int
	closed      bool
}

func (b *stubBackend) GetSecret(_ context.Context, _ string) (map[string]string, error) {
	return b.getSecret, b.getErr
}

func (b *stubBackend) HealthCheck(_ context.Context) error {
	b.healthCalls++
	return b.healthErr
}

func (b *stubBackend) Name() string {
	if b.name == "" {
		return "stub"
	}
	return b.name
}

func (b *stubBackend) Close() error {
	b.closed = true
	return b.closeErr
}

// fakeValidator is a TokenValidator test double.
type fakeValidator struct {
	identity *auth.Identity
	err      error
}

func (v *fakeValidator) ValidateK8sJWT(_ context.Context, _ string) (*auth.Identity, error) {
	return v.identity, v.err
}

// newTestHandlers builds a minimal but functional *api.Handlers.
func newTestHandlers() *api.Handlers {
	roles := map[string]auth.Role{
		"reader": {
			AllowedNamespaces:      []string{"default"},
			AllowedServiceAccounts: []string{"app"},
			AllowedPaths:           []string{"*"},
		},
	}
	return api.NewHandlers(api.Config{
		Backend:   &stubBackend{name: "stub", getSecret: map[string]string{"k": "v"}},
		Validator: &fakeValidator{identity: &auth.Identity{}},
		Tokens:    auth.NewTokenStore(100),
		RBAC:      auth.NewRBAC(roles),
		Logger:    testLogger(),
	})
}

func TestNewRouterUnknownPath404(t *testing.T) {
	mux := NewRouter(newTestHandlers())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/no/such/path", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"errors":["not found"]}` {
		t.Errorf("body = %q", got)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
}

func TestNewRouterMatchedRoutes(t *testing.T) {
	mux := NewRouter(newTestHandlers())

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/sys/health"},
		{http.MethodGet, "/v1/sys/seal-status"},
		{http.MethodPost, "/v1/auth/kubernetes/login"},
		{http.MethodGet, "/v1/secret/data/myapp/config"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			mux.ServeHTTP(rr, req)
			// The route must be matched (not the 404 fallback).
			if rr.Code == http.StatusNotFound {
				t.Errorf("route %s %s returned 404; expected to be matched", tc.method, tc.path)
			}
		})
	}
}

func TestNewRouterMethodMismatch(t *testing.T) {
	mux := NewRouter(newTestHandlers())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/sys/health", nil))

	// The catch-all "/" pattern registered by NewRouter matches any path the
	// method-specific patterns do not, so a wrong-method request to a known
	// path falls through to notFoundHandler (404) rather than the bare-mux 405.
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (catch-all fallback) for wrong method", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"errors":["not found"]}` {
		t.Errorf("body = %q", got)
	}
}

func TestNotFoundHandler(t *testing.T) {
	rr := httptest.NewRecorder()
	notFoundHandler(rr, httptest.NewRequest(http.MethodGet, "/anything", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"errors":["not found"]}` {
		t.Errorf("body = %q", got)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
}

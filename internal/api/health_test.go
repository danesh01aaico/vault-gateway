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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vault-gateway/vault-gateway/internal/version"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// mockBackend is a configurable backend.SecretBackend test double shared across
// the api package tests.
type mockBackend struct {
	name        string
	data        map[string]string
	getErr      error
	healthErr   error
	closeErr    error
	getCalled   bool
	healthCalls int
}

func (m *mockBackend) GetSecret(_ context.Context, _ string) (map[string]string, error) {
	m.getCalled = true
	if m.getErr != nil {
		return nil, m.getErr
	}
	// Return a fresh copy so the handler's clearMap does not mutate our fixture.
	out := make(map[string]string, len(m.data))
	for k, v := range m.data {
		out[k] = v
	}
	return out, nil
}

func (m *mockBackend) HealthCheck(_ context.Context) error {
	m.healthCalls++
	return m.healthErr
}

func (m *mockBackend) Name() string {
	if m.name == "" {
		return "mock"
	}
	return m.name
}

func (m *mockBackend) Close() error { return m.closeErr }

func decodeHealth(t *testing.T, rr *httptest.ResponseRecorder) vaultresponse.HealthResponse {
	t.Helper()
	var hr vaultresponse.HealthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &hr); err != nil {
		t.Fatalf("unmarshal health: %v (body=%q)", err, rr.Body.String())
	}
	return hr
}

func TestHealthHandlerNoBackendCheck(t *testing.T) {
	h := NewHandlers(Config{ClusterID: "cluster-xyz"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	h.HealthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	hr := decodeHealth(t, rr)
	if !hr.Initialized {
		t.Error("Initialized = false, want true")
	}
	if hr.Sealed {
		t.Error("Sealed = true, want false")
	}
	if hr.Version != version.UserAgent() {
		t.Errorf("Version = %q, want %q", hr.Version, version.UserAgent())
	}
	if hr.ClusterID != "cluster-xyz" {
		t.Errorf("ClusterID = %q, want cluster-xyz", hr.ClusterID)
	}
	if hr.ServerTimeUTC <= 0 {
		t.Errorf("ServerTimeUTC = %d, want > 0", hr.ServerTimeUTC)
	}
}

func TestHealthHandlerBackendHealthy(t *testing.T) {
	be := &mockBackend{name: "aws"}
	h := NewHandlers(Config{Backend: be, BackendHealthCheck: true})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	h.HealthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if be.healthCalls != 1 {
		t.Errorf("HealthCheck calls = %d, want 1", be.healthCalls)
	}
	if hr := decodeHealth(t, rr); hr.Sealed {
		t.Error("Sealed = true, want false")
	}
}

func TestHealthHandlerBackendUnhealthy(t *testing.T) {
	be := &mockBackend{name: "aws", healthErr: errors.New("dial timeout")}
	h := NewHandlers(Config{Backend: be, BackendHealthCheck: true})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/health", nil)
	h.HealthHandler(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	if hr := decodeHealth(t, rr); !hr.Sealed {
		t.Error("Sealed = false, want true")
	}
}

func TestSealStatusHandler(t *testing.T) {
	h := NewHandlers(Config{ClusterID: "cluster-xyz"})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sys/seal-status", nil)
	h.SealStatusHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var sr vaultresponse.SealStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &sr); err != nil {
		t.Fatalf("unmarshal seal status: %v", err)
	}
	if sr.Sealed {
		t.Error("Sealed = true, want false")
	}
	if !sr.Initialized {
		t.Error("Initialized = false, want true")
	}
	if sr.ClusterID != "cluster-xyz" {
		t.Errorf("ClusterID = %q, want cluster-xyz", sr.ClusterID)
	}
}

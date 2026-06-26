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
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

func TestBuildTLSConfigMinVersion(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TLS.MinVersion = "1.2"

	tc := buildTLSConfig(cfg)
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS12 %#x", tc.MinVersion, tls.VersionTLS12)
	}
	if tc.CipherSuites != nil {
		t.Errorf("CipherSuites = %v, want nil with no configured suites", tc.CipherSuites)
	}
}

func TestBuildTLSConfigMinVersion13(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TLS.MinVersion = "1.3"

	tc := buildTLSConfig(cfg)
	if tc.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %#x, want TLS13 %#x", tc.MinVersion, tls.VersionTLS13)
	}
}

func TestMapCipherSuites(t *testing.T) {
	const valid = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

	// A valid name resolves to its ID.
	out := mapCipherSuites([]string{valid})
	if len(out) != 1 {
		t.Fatalf("got %d suites, want 1", len(out))
	}
	if out[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Errorf("suite id = %#x, want %#x", out[0], tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	}

	// Unknown names are ignored.
	mixed := mapCipherSuites([]string{valid, "TLS_NOT_A_REAL_SUITE"})
	if len(mixed) != 1 {
		t.Errorf("unknown name not ignored: got %d suites, want 1", len(mixed))
	}

	// Empty input yields nil.
	if got := mapCipherSuites(nil); got != nil {
		t.Errorf("mapCipherSuites(nil) = %v, want nil", got)
	}
	if got := mapCipherSuites([]string{}); got != nil {
		t.Errorf("mapCipherSuites([]) = %v, want nil", got)
	}
	// Only-unknown names yield nil (no allocations appended).
	if got := mapCipherSuites([]string{"NOPE"}); got != nil {
		t.Errorf("mapCipherSuites(unknown only) = %v, want nil", got)
	}
}

func TestBuildTLSConfigWithCipherSuites(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.TLS.MinVersion = "1.2"
	cfg.Server.TLS.CipherSuites = []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "bogus"}

	tc := buildTLSConfig(cfg)
	if len(tc.CipherSuites) != 1 || tc.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Errorf("CipherSuites = %v, want only the valid suite", tc.CipherSuites)
	}
}

// metricsTestConfig returns a config suitable for metricsMux tests.
func metricsTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Metrics.Enabled = true
	cfg.Metrics.Path = "/metrics"
	cfg.HealthCheck.BackendCheckTimeout = config.Duration(time.Second)
	return cfg
}

func TestMetricsMuxHealthz(t *testing.T) {
	cfg := metricsTestConfig()
	mux := metricsMux(cfg, metrics.New(), &stubBackend{}, testLogger())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Errorf("body = %q, want ok", rr.Body.String())
	}
}

func TestMetricsMuxReadyzHealthy(t *testing.T) {
	cfg := metricsTestConfig()
	be := &stubBackend{}
	mux := metricsMux(cfg, metrics.New(), be, testLogger())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if be.healthCalls != 1 {
		t.Errorf("HealthCheck calls = %d, want 1", be.healthCalls)
	}
}

func TestMetricsMuxReadyzUnhealthy(t *testing.T) {
	cfg := metricsTestConfig()
	be := &stubBackend{healthErr: errors.New("backend down")}
	mux := metricsMux(cfg, metrics.New(), be, testLogger())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestMetricsMuxMetricsEndpoint(t *testing.T) {
	cfg := metricsTestConfig()
	m := metrics.New()
	m.SetInfo("1.0.0", "stub", "go1.22")
	mux := metricsMux(cfg, m, &stubBackend{}, testLogger())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "vault_gateway_info") {
		t.Errorf("metrics body missing vault_gateway_info")
	}
}

func TestMetricsMuxMetricsDisabled(t *testing.T) {
	cfg := metricsTestConfig()
	cfg.Metrics.Enabled = false
	mux := metricsMux(cfg, metrics.New(), &stubBackend{}, testLogger())

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	// With metrics disabled the path is not registered; the mux returns 404.
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when metrics disabled", rr.Code)
	}
}

// newServerTestConfig builds a minimal valid config for constructing a Server.
func newServerTestConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 18200
	cfg.Server.ReadTimeout = config.Duration(5 * time.Second)
	cfg.Server.WriteTimeout = config.Duration(5 * time.Second)
	cfg.Server.IdleTimeout = config.Duration(30 * time.Second)
	cfg.Server.ShutdownGracePeriod = config.Duration(2 * time.Second)
	cfg.Server.TLS.MinVersion = "1.2"
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 19090
	cfg.Metrics.Path = "/metrics"
	cfg.HealthCheck.BackendCheckTimeout = config.Duration(time.Second)
	return cfg
}

func TestNewServer(t *testing.T) {
	cfg := newServerTestConfig()
	m := metrics.New()
	be := &stubBackend{}
	mw := NewMiddleware(testLogger(), m, 1<<20, false, config.RateLimitConfig{}, config.CORSConfig{})
	handler := NewRouter(newTestHandlers())

	srv := New(cfg, testLogger(), handler, mw, m, be)
	if srv == nil {
		t.Fatal("New returned nil")
	}
	if srv.api == nil || srv.metricsSrv == nil {
		t.Fatal("New did not wire both servers")
	}
	if srv.api.Addr != "127.0.0.1:18200" {
		t.Errorf("api addr = %q, want 127.0.0.1:18200", srv.api.Addr)
	}
	if srv.metricsSrv.Addr != "127.0.0.1:19090" {
		t.Errorf("metrics addr = %q, want 127.0.0.1:19090", srv.metricsSrv.Addr)
	}
	if srv.limiters == nil {
		t.Error("limiters not wired from middleware")
	}
}

func TestServerStartGracefulShutdown(t *testing.T) {
	cfg := newServerTestConfig()
	// Use distinct high ports unlikely to conflict.
	cfg.Server.Port = 18211
	cfg.Metrics.Port = 19191
	cfg.Server.ShutdownGracePeriod = config.Duration(2 * time.Second)

	m := metrics.New()
	be := &stubBackend{}
	mw := NewMiddleware(testLogger(), m, 1<<20, false, config.RateLimitConfig{}, config.CORSConfig{})
	srv := New(cfg, testLogger(), NewRouter(newTestHandlers()), mw, m, be)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	// Give the listeners a moment to come up, then trigger graceful shutdown.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:19191/healthz")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start returned error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return within shutdown grace period")
	}

	// Backend Close should have been invoked during shutdown.
	if !be.closed {
		t.Error("backend Close not called during shutdown")
	}
}

func TestStatusRecorderFlush(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr, status: http.StatusOK}
	// httptest.ResponseRecorder implements http.Flusher; Flush must not panic.
	rec.Flush()
	if !rr.Flushed {
		t.Error("underlying recorder was not flushed")
	}
}

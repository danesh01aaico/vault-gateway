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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// testLogger returns a logger that discards output.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestMiddleware constructs a Middleware with discarded logs and the given
// options.
func newTestMiddleware(t *testing.T, m *metrics.Metrics, maxBody int64, tlsEnabled bool, rl config.RateLimitConfig, cors config.CORSConfig) *Middleware {
	t.Helper()
	return NewMiddleware(testLogger(), m, maxBody, tlsEnabled, rl, cors)
}

// okHandler is a trivial next handler writing a body with 200.
func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
}

func TestSecurityHeadersAlwaysSet(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})
	h := mw.securityHeaders(okHandler("body"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rr.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should be absent without TLS, got %q", got)
	}
}

func TestSecurityHeadersHSTSWhenTLS(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, true, config.RateLimitConfig{}, config.CORSConfig{})
	h := mw.securityHeaders(okHandler("body"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rr.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Errorf("HSTS = %q, want set when TLS enabled", got)
	}
}

func TestRequestIDGenerated(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})

	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = api.RequestID(r.Context())
	})
	h := mw.requestID(next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	hdr := rr.Header().Get("X-Request-Id")
	if !uuidV4Re.MatchString(hdr) {
		t.Errorf("X-Request-Id %q is not a valid UUIDv4", hdr)
	}
	if len(hdr) != 36 {
		t.Errorf("X-Request-Id length = %d, want 36", len(hdr))
	}
	if seen != hdr {
		t.Errorf("context request id %q != header %q", seen, hdr)
	}
}

func TestRequestIDPreservedFromHeader(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})

	const existing = "client-supplied-id"
	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = api.RequestID(r.Context())
	})
	h := mw.requestID(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", existing)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Request-Id"); got != existing {
		t.Errorf("X-Request-Id = %q, want preserved %q", got, existing)
	}
	if seen != existing {
		t.Errorf("context request id = %q, want %q", seen, existing)
	}
}

func TestNewUUIDv4(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id := newUUIDv4()
		if !uuidV4Re.MatchString(id) {
			t.Fatalf("newUUIDv4 returned invalid value %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("newUUIDv4 returned duplicate value %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestLoggingStatusRecorderExplicitStatus(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	})
	h := mw.logging(next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rr.Code)
	}
	if rr.Body.String() != "created" {
		t.Errorf("body = %q, want created", rr.Body.String())
	}
}

func TestLoggingStatusRecorderDefault200(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})
	h := mw.logging(okHandler("hi"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if rr.Body.String() != "hi" {
		t.Errorf("body = %q, want hi", rr.Body.String())
	}
}

func TestStatusRecorderWriteHeaderLatched(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr, status: http.StatusOK}
	rec.WriteHeader(http.StatusTeapot)
	rec.WriteHeader(http.StatusInternalServerError) // ignored: already wrote
	if rec.status != http.StatusTeapot {
		t.Errorf("recorded status = %d, want 418", rec.status)
	}
}

func TestRateLimitExceeded(t *testing.T) {
	m := metrics.New()
	rl := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1}
	mw := newTestMiddleware(t, m, 0, false, rl, config.CORSConfig{})
	h := mw.rateLimitMiddleware(okHandler("ok"))

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		return req
	}

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, newReq())
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, newReq())
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rr2.Code)
	}
	if got := strings.TrimSpace(rr2.Body.String()); got != `{"errors":["rate limit exceeded"]}` {
		t.Errorf("429 body = %q", got)
	}
	if rr2.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rr2.Header().Get("Content-Type"))
	}
	if v := testutil.ToFloat64(m.RateLimitExceeded); v != 1 {
		t.Errorf("RateLimitExceeded = %v, want 1", v)
	}
}

func TestRateLimitIndependentPerIP(t *testing.T) {
	rl := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1}
	mw := newTestMiddleware(t, nil, 0, false, rl, config.CORSConfig{})
	h := mw.rateLimitMiddleware(okHandler("ok"))

	serve := func(addr string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := serve("1.1.1.1:100"); code != http.StatusOK {
		t.Fatalf("IP A first = %d, want 200", code)
	}
	if code := serve("2.2.2.2:100"); code != http.StatusOK {
		t.Fatalf("IP B first = %d, want 200 (independent bucket)", code)
	}
	if code := serve("1.1.1.1:100"); code != http.StatusTooManyRequests {
		t.Fatalf("IP A second = %d, want 429", code)
	}
}

func TestRateLimitDisabled(t *testing.T) {
	rl := config.RateLimitConfig{Enabled: false, RequestsPerSecond: 1, Burst: 1}
	mw := newTestMiddleware(t, nil, 0, false, rl, config.CORSConfig{})
	h := mw.rateLimitMiddleware(okHandler("ok"))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.9:1"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (disabled)", i, rr.Code)
		}
	}
}

func TestMaxBodyOversizeReadError(t *testing.T) {
	mw := newTestMiddleware(t, nil, 10, false, config.RateLimitConfig{}, config.CORSConfig{})

	var readErr error
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	})
	h := mw.maxBody(next)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 50)))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr == nil {
		t.Fatal("expected read error for oversized body, got nil")
	}
}

func TestMaxBodySmallPasses(t *testing.T) {
	mw := newTestMiddleware(t, nil, 10, false, config.RateLimitConfig{}, config.CORSConfig{})

	var data []byte
	var readErr error
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		data, readErr = io.ReadAll(r.Body)
	})
	h := mw.maxBody(next)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello"))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr != nil {
		t.Fatalf("unexpected read error: %v", readErr)
	}
	if string(data) != "hello" {
		t.Errorf("body = %q, want hello", string(data))
	}
}

func TestRecoverFromPanic(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := mw.recover(next)

	rr := httptest.NewRecorder()
	// Must not propagate the panic.
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"errors":["internal server error"]}` {
		t.Errorf("body = %q", got)
	}
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rr.Header().Get("Content-Type"))
	}
}

func TestCORSDisabled(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{Enabled: false})
	h := mw.corsMiddleware(okHandler("ok"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://ok.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty when disabled", got)
	}
}

func TestCORSAllowedOrigin(t *testing.T) {
	cors := config.CORSConfig{Enabled: true, AllowedOrigins: []string{"https://ok.example"}}
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, cors)
	h := mw.corsMiddleware(okHandler("ok"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://ok.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://ok.example" {
		t.Errorf("Access-Control-Allow-Origin = %q, want echoed origin", got)
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	cors := config.CORSConfig{Enabled: true, AllowedOrigins: []string{"https://ok.example"}}
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, cors)
	h := mw.corsMiddleware(okHandler("ok"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for disallowed origin", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	cors := config.CORSConfig{Enabled: true, AllowedOrigins: []string{"https://ok.example"}}
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, cors)
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	h := mw.corsMiddleware(next)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://ok.example")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rr.Code)
	}
	if called {
		t.Error("next handler should not be called for preflight")
	}
}

func TestChainIntegration(t *testing.T) {
	mw := newTestMiddleware(t, nil, 0, false, config.RateLimitConfig{}, config.CORSConfig{})
	h := mw.Chain(okHandler("handler-body"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:9999"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Body.String() != "handler-body" {
		t.Errorf("body = %q, want handler-body", rr.Body.String())
	}
	if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing security header in full chain")
	}
	if !uuidV4Re.MatchString(rr.Header().Get("X-Request-Id")) {
		t.Errorf("X-Request-Id = %q, want valid UUIDv4 in full chain", rr.Header().Get("X-Request-Id"))
	}
}

func TestIPLimiterSetCleanup(t *testing.T) {
	s := newIPLimiterSet(rate.Limit(10), 5)

	// Fresh entries should not be removed.
	s.allow("a")
	s.allow("b")
	if removed := s.cleanup(10 * time.Minute); removed != 0 {
		t.Errorf("cleanup removed %d fresh entries, want 0", removed)
	}

	// Force entries to be stale by backdating lastUse, then cleanup removes them.
	s.mu.Lock()
	for _, l := range s.items {
		l.lastUse = time.Now().Add(-time.Hour)
	}
	s.mu.Unlock()
	if removed := s.cleanup(time.Minute); removed != 2 {
		t.Errorf("cleanup removed %d stale entries, want 2", removed)
	}
	if removed := s.cleanup(time.Minute); removed != 0 {
		t.Errorf("second cleanup removed %d, want 0", removed)
	}
}

func TestSourceIP(t *testing.T) {
	cases := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"xff single", "203.0.113.5", "10.0.0.1:55", "203.0.113.5"},
		{"xff multi-hop", "203.0.113.5, 10.0.0.2, 10.0.0.3", "10.0.0.1:55", "203.0.113.5"},
		{"remote addr host:port", "", "198.51.100.7:443", "198.51.100.7"},
		{"remote addr no port", "", "198.51.100.8", "198.51.100.8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := sourceIP(req); got != tc.want {
				t.Errorf("sourceIP = %q, want %q", got, tc.want)
			}
		})
	}
}

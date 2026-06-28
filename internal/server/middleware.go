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
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// Middleware holds shared dependencies for the HTTP middleware chain.
type Middleware struct {
	logger       *slog.Logger
	metrics      *metrics.Metrics
	maxBodyBytes int64
	tlsEnabled   bool
	rateLimit    config.RateLimitConfig
	cors         config.CORSConfig
	limiters     *ipLimiterSet
}

// NewMiddleware constructs the middleware set.
func NewMiddleware(logger *slog.Logger, m *metrics.Metrics, maxBody int64, tlsEnabled bool, rl config.RateLimitConfig, cors config.CORSConfig) *Middleware {
	if logger == nil {
		logger = slog.Default()
	}
	return &Middleware{
		logger:       logger,
		metrics:      m,
		maxBodyBytes: maxBody,
		tlsEnabled:   tlsEnabled,
		rateLimit:    rl,
		cors:         cors,
		limiters:     newIPLimiterSet(rate.Limit(rl.RequestsPerSecond), rl.Burst),
	}
}

// Chain applies the middleware in the documented order (outermost first):
// recovery -> request ID -> logging -> rate limit -> max body -> CORS ->
// security headers -> handler.
func (m *Middleware) Chain(next http.Handler) http.Handler {
	h := next
	h = m.securityHeaders(h)
	h = m.corsMiddleware(h)
	h = m.maxBody(h)
	h = m.rateLimitMiddleware(h)
	h = m.logging(h)
	h = m.requestID(h)
	h = m.recover(h)
	return h
}

// statusRecorder captures the response status for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

// Flush implements http.Flusher when the underlying writer supports it.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// recover catches panics, logs the stack, and returns a generic 500. The stack
// trace is never sent to the client.
func (m *Middleware) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				m.logger.Error("panic recovered",
					"error", rec,
					"path", r.URL.Path,
					"request_id", api.RequestID(r.Context()),
					"stack", string(debug.Stack()),
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = encodeError(w, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestID generates a UUIDv4 request ID, exposes it via X-Request-Id, and
// stores it in the request context.
func (m *Middleware) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newUUIDv4()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := api.WithRequestID(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logging records method, path, status, and duration. Sensitive headers such
// as X-Vault-Token are never logged.
func (m *Middleware) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", api.RequestID(r.Context()),
			"src_ip", sourceIP(r),
		)
	})
}

// rateLimitMiddleware enforces a per-source-IP token bucket.
func (m *Middleware) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.rateLimit.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := sourceIP(r)
		if !m.limiters.allow(ip) {
			if m.metrics != nil {
				m.metrics.RateLimitExceeded.Inc()
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = encodeError(w, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxBody caps the request body size.
func (m *Middleware) maxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.maxBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, m.maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware applies a restrictive CORS policy when enabled. The wildcard
// origin is never used.
func (m *Middleware) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.cors.Enabled {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, m.cors.AllowedOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
				w.Header().Set("Access-Control-Allow-Headers", "X-Vault-Token, Content-Type")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets defensive response headers on every response. Secrets
// must never be cached by intermediaries, hence Cache-Control: no-store.
func (m *Middleware) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		// Gateway serves only JSON — no scripts, styles, frames, or media.
		h.Set("Content-Security-Policy", "default-src 'none'")
		if m.tlsEnabled {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// sourceIP extracts the client IP, honoring a single X-Forwarded-For hop.
func sourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// encodeError writes a Vault-shaped error body. Header/status are set by the
// caller.
func encodeError(w http.ResponseWriter, msg string) error {
	// Small, allocation-light JSON without pulling encoding/json into the hot
	// panic path is unnecessary; reuse the typed encoder for correctness.
	return writeJSONBody(w, vaultresponse.ErrorResponse{Errors: []string{msg}})
}

// ipLimiterSet is a concurrency-safe set of per-IP rate limiters with periodic
// cleanup of stale entries.
type ipLimiterSet struct {
	limit rate.Limit
	burst int
	mu    sync.Mutex
	items map[string]*ipLimiter
}

type ipLimiter struct {
	limiter *rate.Limiter
	lastUse time.Time
}

func newIPLimiterSet(limit rate.Limit, burst int) *ipLimiterSet {
	if burst <= 0 {
		burst = 1
	}
	return &ipLimiterSet{
		limit: limit,
		burst: burst,
		items: make(map[string]*ipLimiter),
	}
}

func (s *ipLimiterSet) allow(ip string) bool {
	s.mu.Lock()
	l, ok := s.items[ip]
	if !ok {
		l = &ipLimiter{limiter: rate.NewLimiter(s.limit, s.burst)}
		s.items[ip] = l
	}
	l.lastUse = time.Now()
	s.mu.Unlock()
	return l.limiter.Allow()
}

// cleanup removes limiter entries unused for longer than maxIdle.
func (s *ipLimiterSet) cleanup(maxIdle time.Duration) int {
	cutoff := time.Now().Add(-maxIdle)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for ip, l := range s.items {
		if l.lastUse.Before(cutoff) {
			delete(s.items, ip)
			removed++
		}
	}
	return removed
}

// newUUIDv4 generates a RFC 4122 version 4 UUID using crypto/rand.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic and extremely rare; fall back to
		// a clearly-marked value rather than panicking in the request path.
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}

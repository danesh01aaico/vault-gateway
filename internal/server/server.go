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

// Package server wires the middleware chain, routes, TLS, and the separate
// metrics/health side server, and manages graceful shutdown.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// Server bundles the API server and the metrics/health side server.
type Server struct {
	cfg        *config.Config
	logger     *slog.Logger
	api        *http.Server
	metricsSrv *http.Server
	backend    backend.SecretBackend
	limiters   *ipLimiterSet
}

// New constructs a Server from its dependencies. The handler is the fully
// built API mux; mw is the middleware applied to it.
func New(cfg *config.Config, logger *slog.Logger, handler http.Handler, mw *Middleware, m *metrics.Metrics, be backend.SecretBackend) *Server {
	apiSrv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Server.Port)),
		Handler:           mw.Chain(handler),
		ReadTimeout:       cfg.Server.ReadTimeout.Std(),
		WriteTimeout:      cfg.Server.WriteTimeout.Std(),
		IdleTimeout:       cfg.Server.IdleTimeout.Std(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if cfg.Server.TLS.Enabled {
		apiSrv.TLSConfig = buildTLSConfig(cfg)
	}

	metricsSrv := &http.Server{
		Addr:              net.JoinHostPort(cfg.Server.Host, fmt.Sprint(cfg.Metrics.Port)),
		Handler:           metricsMux(cfg, m, be, logger),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return &Server{
		cfg:        cfg,
		logger:     logger,
		api:        apiSrv,
		metricsSrv: metricsSrv,
		backend:    be,
		limiters:   mw.limiters,
	}
}

// buildTLSConfig assembles the crypto/tls config from the gateway config.
func buildTLSConfig(cfg *config.Config) *tls.Config {
	tc := &tls.Config{
		MinVersion: cfg.TLSMinVersion(),
	}
	if suites := mapCipherSuites(cfg.Server.TLS.CipherSuites); len(suites) > 0 {
		tc.CipherSuites = suites
	}
	return tc
}

// mapCipherSuites resolves cipher suite names to their crypto/tls IDs, ignoring
// unknown names. An empty result means "use Go's secure defaults".
func mapCipherSuites(names []string) []uint16 {
	if len(names) == 0 {
		return nil
	}
	byName := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		byName[cs.Name] = cs.ID
	}
	var out []uint16
	for _, n := range names {
		if id, ok := byName[n]; ok {
			out = append(out, id)
		}
	}
	return out
}

// metricsMux builds the side server: /metrics, /healthz, /readyz.
func metricsMux(cfg *config.Config, m *metrics.Metrics, be backend.SecretBackend, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	if cfg.Metrics.Enabled && m != nil {
		mux.Handle(cfg.Metrics.Path, promhttp.HandlerFor(m.Registry(), promhttp.HandlerOpts{}))
	}
	// Liveness: always healthy if the process is serving.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	// Readiness: healthy only if the backend is reachable.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), cfg.HealthCheck.BackendCheckTimeout.Std())
		defer cancel()
		if be != nil {
			if err := be.HealthCheck(ctx); err != nil {
				logger.WarnContext(ctx, "readiness check failed", "error", err.Error())
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready\n"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

// Start launches both servers and the rate-limiter cleanup loop. It blocks
// until one server fails or ctx is canceled, then performs graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("metrics/health server listening", "addr", s.metricsSrv.Addr)
		if err := s.metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	go func() {
		if s.cfg.Server.TLS.Enabled {
			s.logger.Info("API server listening (TLS)", "addr", s.api.Addr)
			err := s.api.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("api server: %w", err)
			}
			return
		}
		s.logger.Warn("API server listening WITHOUT TLS (development only)", "addr", s.api.Addr)
		if err := s.api.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api server: %w", err)
		}
	}()

	stopCleanup := s.startLimiterCleanup()
	defer stopCleanup()

	select {
	case <-ctx.Done():
		return s.shutdown()
	case err := <-errCh:
		_ = s.shutdown()
		return err
	}
}

// startLimiterCleanup runs a periodic cleanup of stale per-IP limiters and
// returns a stop function.
func (s *Server) startLimiterCleanup() func() {
	if s.limiters == nil {
		return func() {}
	}
	ticker := time.NewTicker(5 * time.Minute)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				s.limiters.cleanup(10 * time.Minute)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(done) }
}

// shutdown drains both servers within the configured grace period.
func (s *Server) shutdown() error {
	grace := s.cfg.Server.ShutdownGracePeriod.Std()
	s.logger.Info("shutting down", "grace_period", grace.String())
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	apiErr := s.api.Shutdown(ctx)
	metricsErr := s.metricsSrv.Shutdown(ctx)
	if s.backend != nil {
		if err := s.backend.Close(); err != nil {
			s.logger.Warn("backend close error", "error", err.Error())
		}
	}
	return errors.Join(apiErr, metricsErr)
}

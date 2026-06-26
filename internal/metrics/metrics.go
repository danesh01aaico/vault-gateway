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

// Package metrics registers and exposes the Prometheus metrics emitted by the
// gateway. All metrics are registered on a dedicated registry so tests can
// construct isolated instances without colliding on the global default
// registry.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics bundles every collector the gateway reports. Construct one with New
// and pass it through to the components that record into it.
type Metrics struct {
	registry *prometheus.Registry

	AuthRequests      *prometheus.CounterVec
	SecretRequests    *prometheus.CounterVec
	CacheHits         *prometheus.CounterVec
	CacheMisses       *prometheus.CounterVec
	RateLimitExceeded prometheus.Counter
	SecretDuration    *prometheus.HistogramVec
	AuthDuration      prometheus.Histogram
	HealthCheckDur    *prometheus.HistogramVec
	ActiveTokens      prometheus.Gauge
	CacheEntries      *prometheus.GaugeVec
	Info              *prometheus.GaugeVec
}

// New constructs a Metrics with a fresh registry and all collectors
// registered.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		AuthRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vault_gateway_auth_requests_total",
			Help: "Total Kubernetes login attempts by status and role.",
		}, []string{"status", "role"}),
		SecretRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vault_gateway_secret_requests_total",
			Help: "Total secret read requests by status and backend.",
		}, []string{"status", "backend"}),
		CacheHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vault_gateway_cache_hits_total",
			Help: "Total backend cache hits.",
		}, []string{"backend"}),
		CacheMisses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vault_gateway_cache_misses_total",
			Help: "Total backend cache misses.",
		}, []string{"backend"}),
		RateLimitExceeded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vault_gateway_rate_limit_exceeded_total",
			Help: "Total requests rejected by the rate limiter.",
		}),
		SecretDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "vault_gateway_secret_request_duration_seconds",
			Help:    "Secret read latency by backend.",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"}),
		AuthDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vault_gateway_auth_request_duration_seconds",
			Help:    "Kubernetes login latency.",
			Buckets: prometheus.DefBuckets,
		}),
		HealthCheckDur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "vault_gateway_backend_health_check_duration_seconds",
			Help:    "Backend health check latency by backend.",
			Buckets: prometheus.DefBuckets,
		}, []string{"backend"}),
		ActiveTokens: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vault_gateway_active_tokens",
			Help: "Number of currently valid issued tokens.",
		}),
		CacheEntries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vault_gateway_cache_entries",
			Help: "Current number of cache entries by backend.",
		}, []string{"backend"}),
		Info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vault_gateway_info",
			Help: "Static build information; always 1.",
		}, []string{"version", "backend", "go_version"}),
	}

	reg.MustRegister(
		m.AuthRequests, m.SecretRequests, m.CacheHits, m.CacheMisses,
		m.RateLimitExceeded, m.SecretDuration, m.AuthDuration, m.HealthCheckDur,
		m.ActiveTokens, m.CacheEntries, m.Info,
	)
	return m
}

// Registry returns the underlying Prometheus registry for the HTTP handler.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// SetInfo records the static build-info gauge.
func (m *Metrics) SetInfo(version, backend, goVersion string) {
	m.Info.WithLabelValues(version, backend, goVersion).Set(1)
}

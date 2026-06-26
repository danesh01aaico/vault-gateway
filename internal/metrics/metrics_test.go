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

package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("New panicked: %v", r)
		}
	}()
	m := New()
	if m == nil {
		t.Fatal("New returned nil")
	}
	if m.Registry() == nil {
		t.Fatal("Registry() returned nil")
	}
}

func TestNewIsIsolated(t *testing.T) {
	// Constructing two instances must not collide on a global registry.
	_ = New()
	_ = New()
}

func TestAllCollectorsRecordWithoutPanic(t *testing.T) {
	m := New()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("recording panicked: %v", r)
		}
	}()
	m.AuthRequests.WithLabelValues("success", "reader").Inc()
	m.SecretRequests.WithLabelValues("success", "vault").Inc()
	m.CacheHits.WithLabelValues("vault").Inc()
	m.CacheMisses.WithLabelValues("vault").Inc()
	m.RateLimitExceeded.Inc()
	m.SecretDuration.WithLabelValues("vault").Observe(0.5)
	m.AuthDuration.Observe(0.25)
	m.HealthCheckDur.WithLabelValues("vault").Observe(0.1)
	m.ActiveTokens.Set(42)
	m.CacheEntries.WithLabelValues("vault").Set(7)
	m.Info.WithLabelValues("v1", "vault", "go1.24").Set(1)
}

func TestCounterValues(t *testing.T) {
	m := New()
	m.AuthRequests.WithLabelValues("success", "reader").Inc()
	m.AuthRequests.WithLabelValues("success", "reader").Inc()
	if got := testutil.ToFloat64(m.AuthRequests.WithLabelValues("success", "reader")); got != 2 {
		t.Errorf("AuthRequests = %v, want 2", got)
	}

	m.RateLimitExceeded.Add(3)
	if got := testutil.ToFloat64(m.RateLimitExceeded); got != 3 {
		t.Errorf("RateLimitExceeded = %v, want 3", got)
	}

	m.ActiveTokens.Set(11)
	if got := testutil.ToFloat64(m.ActiveTokens); got != 11 {
		t.Errorf("ActiveTokens = %v, want 11", got)
	}
}

func TestSetInfo(t *testing.T) {
	m := New()
	m.SetInfo("1.2.3", "vault", "go1.24")
	g := m.Info.WithLabelValues("1.2.3", "vault", "go1.24")
	if got := testutil.ToFloat64(g); got != 1 {
		t.Errorf("Info gauge = %v, want 1", got)
	}
}

func TestMetricNamesRegistered(t *testing.T) {
	m := New()
	// Exercise each collector so it appears in the gathered output.
	m.AuthRequests.WithLabelValues("success", "reader").Inc()
	m.SecretRequests.WithLabelValues("success", "vault").Inc()
	m.CacheHits.WithLabelValues("vault").Inc()
	m.CacheMisses.WithLabelValues("vault").Inc()
	m.RateLimitExceeded.Inc()
	m.ActiveTokens.Set(1)
	m.CacheEntries.WithLabelValues("vault").Set(1)
	m.SetInfo("v", "vault", "go")

	want := []string{
		"vault_gateway_auth_requests_total",
		"vault_gateway_secret_requests_total",
		"vault_gateway_cache_hits_total",
		"vault_gateway_cache_misses_total",
		"vault_gateway_rate_limit_exceeded_total",
		"vault_gateway_active_tokens",
		"vault_gateway_cache_entries",
		"vault_gateway_info",
	}
	for _, name := range want {
		if n := testutil.CollectAndCount(m.Registry(), name); n == 0 {
			t.Errorf("metric %q not registered/exported", name)
		}
	}
}

func TestGatherAndCompareCounter(t *testing.T) {
	m := New()
	m.CacheHits.WithLabelValues("vault").Inc()
	expected := `
# HELP vault_gateway_cache_hits_total Total backend cache hits.
# TYPE vault_gateway_cache_hits_total counter
vault_gateway_cache_hits_total{backend="vault"} 1
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(expected), "vault_gateway_cache_hits_total"); err != nil {
		t.Errorf("GatherAndCompare: %v", err)
	}
}

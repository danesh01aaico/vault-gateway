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

package main

import (
	"context"
	"testing"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/config"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

func testConfig() *config.Config {
	return &config.Config{
		Backend: config.BackendVault,
		Auth: config.AuthConfig{
			TokenTTL: config.Duration(time.Hour),
			Roles: map[string]config.RoleConfig{
				"opus-workloads": {
					AllowedNamespaces:      []string{"opus-apps"},
					AllowedServiceAccounts: []string{"*"},
					AllowedPaths:           []string{"opus/*"},
					TokenTTL:               config.Duration(30 * time.Minute),
				},
				"no-override": {
					AllowedNamespaces:      []string{"opus-system"},
					AllowedServiceAccounts: []string{"admin"},
					AllowedPaths:           []string{"*"},
				},
			},
		},
	}
}

func TestBuildRoles(t *testing.T) {
	roles := buildRoles(testConfig())
	if len(roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(roles))
	}
	r := roles["opus-workloads"]
	if len(r.AllowedNamespaces) != 1 || r.AllowedNamespaces[0] != "opus-apps" {
		t.Errorf("unexpected namespaces: %v", r.AllowedNamespaces)
	}
	if r.AllowedPaths[0] != "opus/*" {
		t.Errorf("unexpected paths: %v", r.AllowedPaths)
	}
}

func TestRoleTTLs(t *testing.T) {
	ttls := roleTTLs(testConfig())
	if got := ttls["opus-workloads"]; got != 30*time.Minute {
		t.Errorf("opus-workloads ttl = %v, want 30m", got)
	}
	if _, ok := ttls["no-override"]; ok {
		t.Errorf("role without a positive TTL should be omitted")
	}
}

func TestNewLogger(t *testing.T) {
	for _, lc := range []config.LoggingConfig{
		{Level: "debug", Format: "json"},
		{Level: "info", Format: "text"},
		{Level: "warn", Format: "json"},
		{Level: "error", Format: "text"},
		{Level: "", Format: ""},
	} {
		if l := newLogger(lc); l == nil {
			t.Errorf("newLogger(%+v) returned nil", lc)
		}
	}
}

func TestGenerateClusterID(t *testing.T) {
	a, b := generateClusterID(), generateClusterID()
	if len(a) != 32 {
		t.Errorf("cluster id length = %d, want 32 hex chars", len(a))
	}
	if a == b {
		t.Errorf("cluster ids should differ: %q == %q", a, b)
	}
}

func TestLogStartupBanner(t *testing.T) {
	// Should not panic.
	logStartupBanner(newLogger(config.LoggingConfig{}), testConfig())
}

func TestBuildBackendVault(t *testing.T) {
	// The vault backend with a static Token does not contact any network at
	// construction time, so this exercises the factory's vault branch offline.
	cfg := testConfig()
	cfg.Vault = config.VaultConfig{
		Address: "https://vault.example:8200",
		Token:   "test-token",
		Cache:   config.CacheConfig{Enabled: true, TTL: config.Duration(time.Minute)},
	}
	be, err := buildBackend(context.Background(), cfg, metrics.New(), newLogger(config.LoggingConfig{}))
	if err != nil {
		t.Fatalf("buildBackend(vault) error: %v", err)
	}
	defer func() { _ = be.Close() }()
	if be.Name() != "vault" {
		t.Errorf("backend name = %q, want vault", be.Name())
	}
}

func TestBuildBackendUnsupported(t *testing.T) {
	cfg := testConfig()
	cfg.Backend = "nope"
	if _, err := buildBackend(context.Background(), cfg, nil, newLogger(config.LoggingConfig{})); err == nil {
		t.Fatal("expected error for unsupported backend")
	}
}

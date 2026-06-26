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

package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// validRoles returns a minimal valid role map for in-code Config construction.
func validRoles() map[string]RoleConfig {
	return map[string]RoleConfig{
		"app": {
			AllowedNamespaces:      []string{"default"},
			AllowedServiceAccounts: []string{"app-sa"},
			AllowedPaths:           []string{"secret/data/*"},
		},
	}
}

// baseValidConfig builds an in-code Config that passes Validate (aws backend).
// Callers mutate fields to exercise individual validation rules.
func baseValidConfig() Config {
	c := Config{Backend: BackendAWS}
	c.applyDefaults()
	c.Auth.Roles = validRoles()
	return c
}

func TestLoadValidFixtures(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		cfg, err := Load(filepath.Join("testdata", "valid_aws.yaml"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backend != BackendAWS {
			t.Errorf("Backend = %q, want aws", cfg.Backend)
		}
		if cfg.Server.Port != 8200 {
			t.Errorf("Server.Port = %d, want 8200", cfg.Server.Port)
		}
		if cfg.AWS.Region != "us-east-1" {
			t.Errorf("AWS.Region = %q, want us-east-1", cfg.AWS.Region)
		}
		// 300s cache TTL must parse to 5 minutes.
		if got := cfg.AWS.Cache.TTL.Std(); got != 5*time.Minute {
			t.Errorf("AWS.Cache.TTL = %v, want 5m", got)
		}
		if !cfg.AWS.Cache.Enabled {
			t.Errorf("AWS.Cache.Enabled = false, want true")
		}
		role, ok := cfg.Auth.Roles["app"]
		if !ok {
			t.Fatalf("role 'app' missing")
		}
		if role.TokenTTL.Std() != 30*time.Minute {
			t.Errorf("role TokenTTL = %v, want 30m", role.TokenTTL.Std())
		}
	})

	t.Run("azure", func(t *testing.T) {
		cfg, err := Load(filepath.Join("testdata", "valid_azure.yaml"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backend != BackendAzure {
			t.Errorf("Backend = %q, want azure", cfg.Backend)
		}
		if cfg.Azure.VaultURL != "https://my-vault.vault.azure.net/" {
			t.Errorf("Azure.VaultURL = %q", cfg.Azure.VaultURL)
		}
		if cfg.Azure.NamingStrategy != "json" {
			t.Errorf("Azure.NamingStrategy = %q, want json", cfg.Azure.NamingStrategy)
		}
	})

	t.Run("vault", func(t *testing.T) {
		cfg, err := Load(filepath.Join("testdata", "valid_vault.yaml"))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Backend != BackendVault {
			t.Errorf("Backend = %q, want vault", cfg.Backend)
		}
		if cfg.Vault.Address != "https://vault.internal:8200" {
			t.Errorf("Vault.Address = %q", cfg.Vault.Address)
		}
		if cfg.Vault.Role != "gateway" {
			t.Errorf("Vault.Role = %q, want gateway", cfg.Vault.Role)
		}
		if cfg.Auth.TokenTTL.Std() != 2*time.Hour {
			t.Errorf("Auth.TokenTTL = %v, want 2h", cfg.Auth.TokenTTL.Std())
		}
		if cfg.Metrics.Port != 9091 {
			t.Errorf("Metrics.Port = %d, want 9091", cfg.Metrics.Port)
		}
	})
}

func TestLoadInvalidFixture(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "invalid.yaml"))
	if err == nil {
		t.Fatal("Load() of invalid.yaml succeeded, want error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "does_not_exist.yaml"))
	if err == nil {
		t.Fatal("Load() of missing file succeeded, want error")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("server: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() of malformed YAML succeeded, want error")
	}
}

func TestDefaultsApplied(t *testing.T) {
	// Minimal valid config: only backend + one role. Everything else defaulted.
	data := []byte(`
backend: aws
auth:
  roles:
    app:
      allowedNamespaces: [default]
      allowedServiceAccounts: [app-sa]
      allowedPaths: ["secret/data/*"]
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "min.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"Server.Port", cfg.Server.Port, 8200},
		{"Server.Host", cfg.Server.Host, "0.0.0.0"},
		{"Server.ReadTimeout", cfg.Server.ReadTimeout.Std(), 30 * time.Second},
		{"Server.WriteTimeout", cfg.Server.WriteTimeout.Std(), 30 * time.Second},
		{"Server.IdleTimeout", cfg.Server.IdleTimeout.Std(), 120 * time.Second},
		{"Server.MaxRequestBodySize", cfg.Server.MaxRequestBodySize, int64(1 << 20)},
		{"Server.ShutdownGracePeriod", cfg.Server.ShutdownGracePeriod.Std(), 15 * time.Second},
		{"Server.TLS.MinVersion", cfg.Server.TLS.MinVersion, "1.2"},
		{"Auth.TokenTTL", cfg.Auth.TokenTTL.Std(), 3600 * time.Second},
		{"Auth.TokenCleanupInterval", cfg.Auth.TokenCleanupInterval.Std(), 60 * time.Second},
		{"Auth.MaxTokensPerIdentity", cfg.Auth.MaxTokensPerIdentity, 100},
		{"Azure.NamingStrategy", cfg.Azure.NamingStrategy, "flat"},
		{"Vault.AuthPath", cfg.Vault.AuthPath, "kubernetes"},
		{"Logging.Level", cfg.Logging.Level, "info"},
		{"Logging.Format", cfg.Logging.Format, "json"},
		{"Metrics.Port", cfg.Metrics.Port, 9090},
		{"Metrics.Path", cfg.Metrics.Path, "/metrics"},
		{"HealthCheck.BackendCheckTimeout", cfg.HealthCheck.BackendCheckTimeout.Std(), 5 * time.Second},
		{"HealthCheck.BackendCheckInterval", cfg.HealthCheck.BackendCheckInterval.Std(), 30 * time.Second},
		{"RateLimit.RequestsPerSecond", cfg.RateLimit.RequestsPerSecond, float64(100)},
		{"RateLimit.Burst", cfg.RateLimit.Burst, 200},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid aws", func(c *Config) {}, false},
		{"empty backend", func(c *Config) { c.Backend = "" }, true},
		{"unsupported backend", func(c *Config) { c.Backend = "consul" }, true},
		{"server port zero", func(c *Config) { c.Server.Port = 0 }, true},
		{"server port too high", func(c *Config) { c.Server.Port = 70000 }, true},
		{"metrics port out of range", func(c *Config) { c.Metrics.Port = 0 }, true},
		{"server == metrics port", func(c *Config) { c.Metrics.Port = c.Server.Port }, true},
		{"no roles", func(c *Config) { c.Auth.Roles = nil }, true},
		{"role missing namespaces", func(c *Config) {
			r := c.Auth.Roles["app"]
			r.AllowedNamespaces = nil
			c.Auth.Roles["app"] = r
		}, true},
		{"role missing paths", func(c *Config) {
			r := c.Auth.Roles["app"]
			r.AllowedPaths = nil
			c.Auth.Roles["app"] = r
		}, true},
		{"role missing service accounts", func(c *Config) {
			r := c.Auth.Roles["app"]
			r.AllowedServiceAccounts = nil
			c.Auth.Roles["app"] = r
		}, true},
		{"non-positive readTimeout", func(c *Config) { c.Server.ReadTimeout = 0 }, true},
		{"negative writeTimeout", func(c *Config) { c.Server.WriteTimeout = Duration(-1) }, true},
		{"non-positive tokenTTL", func(c *Config) { c.Auth.TokenTTL = 0 }, true},
		// Azure backend cases.
		{"azure missing vaultURL", func(c *Config) {
			c.Backend = BackendAzure
			c.Azure.NamingStrategy = "flat"
		}, true},
		{"azure invalid namingStrategy", func(c *Config) {
			c.Backend = BackendAzure
			c.Azure.VaultURL = "https://v.vault.azure.net/"
			c.Azure.NamingStrategy = "nested"
		}, true},
		{"azure valid", func(c *Config) {
			c.Backend = BackendAzure
			c.Azure.VaultURL = "https://v.vault.azure.net/"
			c.Azure.NamingStrategy = "json"
		}, false},
		// Vault backend cases.
		{"vault missing address", func(c *Config) {
			c.Backend = BackendVault
			c.Vault.Role = "gw"
		}, true},
		{"vault missing role and token", func(c *Config) {
			c.Backend = BackendVault
			c.Vault.Address = "https://v:8200"
		}, true},
		{"vault valid with token", func(c *Config) {
			c.Backend = BackendVault
			c.Vault.Address = "https://v:8200"
			c.Vault.Token = "s.abc"
		}, false},
		// GCP backend cases.
		{"gcp missing projectID", func(c *Config) { c.Backend = BackendGCP }, true},
		{"gcp valid", func(c *Config) {
			c.Backend = BackendGCP
			c.GCP.ProjectID = "my-project"
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestTLSValidation(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	for _, f := range []string{certFile, keyFile} {
		if err := os.WriteFile(f, []byte("dummy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("enabled with missing files", func(t *testing.T) {
		c := baseValidConfig()
		c.Server.TLS.Enabled = true
		c.Server.TLS.CertFile = filepath.Join(dir, "nope-cert.pem")
		c.Server.TLS.KeyFile = filepath.Join(dir, "nope-key.pem")
		if err := c.Validate(); err == nil {
			t.Error("Validate() = nil, want error for missing cert/key")
		}
	})

	t.Run("enabled with empty cert path", func(t *testing.T) {
		c := baseValidConfig()
		c.Server.TLS.Enabled = true
		if err := c.Validate(); err == nil {
			t.Error("Validate() = nil, want error for empty cert path")
		}
	})

	t.Run("enabled with existing files", func(t *testing.T) {
		c := baseValidConfig()
		c.Server.TLS.Enabled = true
		c.Server.TLS.CertFile = certFile
		c.Server.TLS.KeyFile = keyFile
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil", err)
		}
	})

	versions := []struct {
		v        string
		accepted bool
	}{
		{"1.0", false},
		{"1.1", false},
		{"1.2", true},
		{"1.3", true},
		{"9.9", false},
	}
	for _, vt := range versions {
		t.Run("minVersion "+vt.v, func(t *testing.T) {
			c := baseValidConfig()
			c.Server.TLS.Enabled = true
			c.Server.TLS.CertFile = certFile
			c.Server.TLS.KeyFile = keyFile
			c.Server.TLS.MinVersion = vt.v
			err := c.Validate()
			if vt.accepted && err != nil {
				t.Errorf("Validate() = %v, want nil for version %s", err, vt.v)
			}
			if !vt.accepted && err == nil {
				t.Errorf("Validate() = nil, want error for version %s", vt.v)
			}
		})
	}
}

func TestTLSMinVersion(t *testing.T) {
	tests := []struct {
		v    string
		want uint16
	}{
		{"1.2", 0x0303},
		{"1.3", 0x0304},
		{"", 0x0303},      // default maps to 1.2
		{"bogus", 0x0303}, // parse fails -> falls back to 1.2
	}
	for _, tt := range tests {
		t.Run(tt.v, func(t *testing.T) {
			c := baseValidConfig()
			c.Server.TLS.MinVersion = tt.v
			if got := c.TLSMinVersion(); got != tt.want {
				t.Errorf("TLSMinVersion(%q) = %#x, want %#x", tt.v, got, tt.want)
			}
		})
	}
}

func TestDurationUnmarshalYAML(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		data := []byte(`
backend: aws
server:
  readTimeout: 30s
auth:
  roles:
    app:
      allowedNamespaces: [default]
      allowedServiceAccounts: [app-sa]
      allowedPaths: ["secret/data/*"]
`)
		cfg, err := parse(data)
		if err != nil {
			t.Fatalf("parse() error = %v", err)
		}
		if cfg.Server.ReadTimeout.Std() != 30*time.Second {
			t.Errorf("ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout.Std())
		}
	})

	t.Run("invalid duration string", func(t *testing.T) {
		data := []byte(`
backend: aws
server:
  readTimeout: "not-a-duration"
auth:
  roles:
    app:
      allowedNamespaces: [default]
      allowedServiceAccounts: [app-sa]
      allowedPaths: ["secret/data/*"]
`)
		if _, err := parse(data); err == nil {
			t.Error("parse() = nil, want error for invalid duration")
		}
	})

	t.Run("non-string scalar", func(t *testing.T) {
		data := []byte(`
backend: aws
server:
  readTimeout: [1, 2]
auth:
  roles:
    app:
      allowedNamespaces: [default]
      allowedServiceAccounts: [app-sa]
      allowedPaths: ["secret/data/*"]
`)
		if _, err := parse(data); err == nil {
			t.Error("parse() = nil, want error for non-string duration")
		}
	})
}

func TestCacheConfigToCache(t *testing.T) {
	cc := CacheConfig{
		Enabled:     true,
		TTL:         Duration(5 * time.Minute),
		MaxEntries:  250,
		NegativeTTL: Duration(20 * time.Second),
	}
	got := cc.ToCache()
	if !got.Enabled {
		t.Error("Enabled = false, want true")
	}
	if got.TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m", got.TTL)
	}
	if got.NegativeTTL != 20*time.Second {
		t.Errorf("NegativeTTL = %v, want 20s", got.NegativeTTL)
	}
	if got.MaxEntries != 250 {
		t.Errorf("MaxEntries = %d, want 250", got.MaxEntries)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	env := map[string]string{
		"VG_BACKEND":        "vault",
		"VG_SERVER_HOST":    "10.0.0.1",
		"VG_SERVER_PORT":    "9999",
		"VG_METRICS_PORT":   "9191",
		"VG_LOG_LEVEL":      "debug",
		"VG_LOG_FORMAT":     "text",
		"VG_TLS_CERT_FILE":  "/etc/cert.pem",
		"VG_TLS_KEY_FILE":   "/etc/key.pem",
		"VG_AWS_REGION":     "eu-west-1",
		"VG_AZURE_VAULTURL": "https://x.vault.azure.net/",
		"VG_VAULT_ADDRESS":  "https://vault:8200",
		"VG_VAULT_TOKEN":    "s.token",
		"VG_GCP_PROJECTID":  "proj-123",
	}
	lookup := func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}

	c := baseValidConfig()
	c.applyEnvOverrides(lookup)

	if c.Backend != "vault" {
		t.Errorf("Backend = %q, want vault", c.Backend)
	}
	if c.Server.Host != "10.0.0.1" {
		t.Errorf("Server.Host = %q", c.Server.Host)
	}
	if c.Server.Port != 9999 {
		t.Errorf("Server.Port = %d, want 9999", c.Server.Port)
	}
	if c.Metrics.Port != 9191 {
		t.Errorf("Metrics.Port = %d, want 9191", c.Metrics.Port)
	}
	if c.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q", c.Logging.Level)
	}
	if c.Logging.Format != "text" {
		t.Errorf("Logging.Format = %q", c.Logging.Format)
	}
	if c.Server.TLS.CertFile != "/etc/cert.pem" {
		t.Errorf("TLS.CertFile = %q", c.Server.TLS.CertFile)
	}
	if c.Server.TLS.KeyFile != "/etc/key.pem" {
		t.Errorf("TLS.KeyFile = %q", c.Server.TLS.KeyFile)
	}
	if c.AWS.Region != "eu-west-1" {
		t.Errorf("AWS.Region = %q", c.AWS.Region)
	}
	if c.Azure.VaultURL != "https://x.vault.azure.net/" {
		t.Errorf("Azure.VaultURL = %q", c.Azure.VaultURL)
	}
	if c.Vault.Address != "https://vault:8200" {
		t.Errorf("Vault.Address = %q", c.Vault.Address)
	}
	if c.Vault.Token != "s.token" {
		t.Errorf("Vault.Token = %q", c.Vault.Token)
	}
	if c.GCP.ProjectID != "proj-123" {
		t.Errorf("GCP.ProjectID = %q", c.GCP.ProjectID)
	}
}

func TestApplyEnvOverridesBadPortIgnored(t *testing.T) {
	env := map[string]string{
		"VG_SERVER_PORT":  "not-an-int",
		"VG_METRICS_PORT": "also-bad",
	}
	lookup := func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}

	c := baseValidConfig()
	origServer := c.Server.Port
	origMetrics := c.Metrics.Port
	c.applyEnvOverrides(lookup)

	if c.Server.Port != origServer {
		t.Errorf("Server.Port = %d, want unchanged %d", c.Server.Port, origServer)
	}
	if c.Metrics.Port != origMetrics {
		t.Errorf("Metrics.Port = %d, want unchanged %d", c.Metrics.Port, origMetrics)
	}
}

func TestApplyEnvOverridesEmptyLookup(t *testing.T) {
	// No env vars set: config must be untouched.
	lookup := func(string) (string, bool) { return "", false }
	c := baseValidConfig()
	c.applyEnvOverrides(lookup)
	if c.Backend != BackendAWS {
		t.Errorf("Backend = %q, want aws (unchanged)", c.Backend)
	}
}

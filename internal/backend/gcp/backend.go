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

// Package gcp implements the SecretBackend interface backed by Google Cloud
// Secret Manager. Credentials are resolved through Application Default
// Credentials (Workload Identity, the metadata server, or
// GOOGLE_APPLICATION_CREDENTIALS), so the gateway never holds static secrets.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// backendName is the identifier reported by Name and used as the metrics label.
const backendName = "gcp"

// healthProbeSecretID is the secret id accessed by HealthCheck. It is expected
// not to exist; a NotFound response proves the service is reachable.
const healthProbeSecretID = "vault-gateway-health-probe"

// Config is the GCP Secret Manager backend configuration. The config package
// populates it from the gateway's configuration file or environment.
type Config struct {
	// ProjectID is the Google Cloud project that owns the secrets.
	ProjectID string
	// SecretPrefix is prepended to every derived secret id to form a namespace.
	SecretPrefix string
	// Cache configures the in-memory secret cache embedded by the backend.
	Cache cache.Config
}

// smClient is the subset of the Secret Manager API the backend uses. The
// concrete *secretmanager.Client satisfies it; tests inject a fake.
type smClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// Backend is a GCP Secret Manager SecretBackend. It is safe for concurrent
// use: the client and the cache are both concurrency-safe.
type Backend struct {
	client    smClient
	cache     *cache.Cache
	projectID string
	prefix    string
	metric    *metrics.Metrics
	logger    *slog.Logger
}

// Ensure Backend satisfies the contract at compile time.
var _ backend.SecretBackend = (*Backend)(nil)

// New constructs a GCP Secret Manager backend. Credentials are resolved through
// Application Default Credentials. The metrics pointer may be nil, in which case
// metric recording is skipped. A nil logger falls back to slog.Default.
func New(ctx context.Context, cfg Config, m *metrics.Metrics, logger *slog.Logger) (backend.SecretBackend, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ProjectID == "" {
		return nil, fmt.Errorf("gcp: ProjectID is required")
	}

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: new secret manager client: %w", err)
	}

	b := &Backend{
		client:    client,
		cache:     cache.New(cfg.Cache),
		projectID: cfg.ProjectID,
		prefix:    cfg.SecretPrefix,
		metric:    m,
		logger:    logger,
	}
	b.logger.Info("gcp secret manager backend initialized",
		"project", cfg.ProjectID, "prefix", cfg.SecretPrefix)
	return b, nil
}

// newWithClient builds a Backend around a pre-constructed smClient. It exists
// for tests; production code uses New.
func newWithClient(client smClient, cfg Config, m *metrics.Metrics) *Backend {
	return &Backend{
		client:    client,
		cache:     cache.New(cfg.Cache),
		projectID: cfg.ProjectID,
		prefix:    cfg.SecretPrefix,
		metric:    m,
		logger:    slog.Default(),
	}
}

// secretID maps a Vault-style path to a GCP secret id. GCP secret ids must
// match [a-zA-Z0-9_-]+ and be at most 255 characters, so path separators "/"
// are replaced with "-" and the configured prefix is applied. Any other
// disallowed character is also replaced with "-".
func (b *Backend) secretID(path string) string {
	id := b.prefix + path
	id = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-':
			return r
		default:
			return '-'
		}
	}, id)
	if len(id) > 255 {
		id = id[:255]
	}
	return id
}

// resourceName returns the AccessSecretVersion resource name for the latest
// version of secretID.
func (b *Backend) resourceName(secretID string) string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/latest", b.projectID, secretID)
}

// GetSecret fetches the secret at path. The secret payload is expected to be a
// JSON object whose keys and values are strings. NotFound responses are cached
// negatively and surfaced as ErrSecretNotFound; any other error is wrapped as
// ErrBackendUnavailable.
func (b *Backend) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	id := b.secretID(path)

	if value, hit, isNegative := b.cache.Get(id); hit {
		b.recordCacheHit()
		if isNegative {
			return nil, backend.ErrSecretNotFound
		}
		return value, nil
	}
	b.recordCacheMiss()

	resp, err := b.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: b.resourceName(id),
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			b.cache.SetNegative(id)
			return nil, backend.ErrSecretNotFound
		}
		// The error message never contains secret payloads.
		b.logger.Warn("gcp access secret version failed", "path", path, "error", err)
		return nil, fmt.Errorf("gcp: access secret version: %w", backend.ErrBackendUnavailable)
	}

	var payload []byte
	if resp.GetPayload() != nil {
		payload = resp.GetPayload().GetData()
	}

	var result map[string]string
	if err := json.Unmarshal(payload, &result); err != nil || result == nil {
		b.logger.Warn("gcp secret payload is not a JSON string map", "path", path)
		return nil, fmt.Errorf("gcp: parse secret payload: %w", backend.ErrBackendUnavailable)
	}

	b.cache.Set(id, result)
	b.updateCacheEntries()
	return result, nil
}

// HealthCheck verifies connectivity by accessing a sentinel probe secret that
// is expected not to exist. A NotFound response proves the service is reachable
// and authorized; any other error indicates the backend is unavailable.
func (b *Backend) HealthCheck(ctx context.Context) error {
	_, err := b.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: b.resourceName(healthProbeSecretID),
	})
	if err == nil {
		return nil
	}
	if status.Code(err) == codes.NotFound {
		return nil
	}
	b.logger.Warn("gcp health check failed", "error", err)
	return fmt.Errorf("gcp: health check: %w", backend.ErrBackendUnavailable)
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return backendName }

// Close releases the underlying client's resources.
func (b *Backend) Close() error {
	if b.client != nil {
		_ = b.client.Close()
	}
	return nil
}

func (b *Backend) recordCacheHit() {
	if b.metric != nil {
		b.metric.CacheHits.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) recordCacheMiss() {
	if b.metric != nil {
		b.metric.CacheMisses.WithLabelValues(backendName).Inc()
	}
}

func (b *Backend) updateCacheEntries() {
	if b.metric != nil {
		b.metric.CacheEntries.WithLabelValues(backendName).Set(float64(b.cache.Len()))
	}
}

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

// Package aws implements the SecretBackend interface backed by AWS Secrets
// Manager. Credentials are resolved through the default AWS credential chain
// (IRSA, environment variables, or the EC2/ECS instance profile), so no static
// secrets are ever held by the gateway.
package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// backendName is the identifier reported by Name and used as the metrics label.
const backendName = "aws"

// Config is the AWS Secrets Manager backend configuration. The config package
// populates it from the gateway's configuration file or environment.
type Config struct {
	// Region is the AWS region to target (e.g. "us-east-1"). When empty the
	// SDK falls back to its own region resolution (env/shared config).
	Region string
	// SecretPrefix is prepended to every requested path to form the Secrets
	// Manager secret id. It is typically a namespace such as "prod/".
	SecretPrefix string
	// EndpointURL overrides the service endpoint, e.g. for LocalStack in tests.
	// Empty means the default AWS endpoint for the region.
	EndpointURL string
	// MaxRetries bounds SDK retry attempts. Zero leaves the SDK default.
	MaxRetries int
	// Cache configures the in-memory secret cache embedded by the backend.
	Cache cache.Config
}

// smClient is the subset of the Secrets Manager API the backend uses. The
// concrete *secretsmanager.Client satisfies it; tests inject a fake.
type smClient interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// Backend is an AWS Secrets Manager SecretBackend. It is safe for concurrent
// use: the SDK client and the cache are both concurrency-safe.
type Backend struct {
	client smClient
	cache  *cache.Cache
	prefix string
	metric *metrics.Metrics
	logger *slog.Logger
}

// Ensure Backend satisfies the contract at compile time.
var _ backend.SecretBackend = (*Backend)(nil)

// New constructs an AWS Secrets Manager backend. The metrics pointer may be nil,
// in which case metric recording is skipped. A nil logger falls back to
// slog.Default.
func New(ctx context.Context, cfg Config, m *metrics.Metrics, logger *slog.Logger) (backend.SecretBackend, error) {
	if logger == nil {
		logger = slog.Default()
	}

	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.MaxRetries > 0 {
		opts = append(opts, awsconfig.WithRetryMaxAttempts(cfg.MaxRetries))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws: load default config: %w", err)
	}

	client := secretsmanager.NewFromConfig(awsCfg, func(o *secretsmanager.Options) {
		if cfg.EndpointURL != "" {
			o.BaseEndpoint = awssdk.String(cfg.EndpointURL)
		}
	})

	b := &Backend{
		client: client,
		cache:  cache.New(cfg.Cache),
		prefix: cfg.SecretPrefix,
		metric: m,
		logger: logger,
	}
	b.logger.Info("aws secrets manager backend initialized",
		"region", cfg.Region, "prefix", cfg.SecretPrefix, "custom_endpoint", cfg.EndpointURL != "")
	return b, nil
}

// newWithClient builds a Backend around a pre-constructed smClient. It exists
// for tests; production code uses New.
//
//nolint:unparam // test-only helper; m is intentionally parameterized
func newWithClient(client smClient, cfg Config, m *metrics.Metrics) *Backend {
	return &Backend{
		client: client,
		cache:  cache.New(cfg.Cache),
		prefix: cfg.SecretPrefix,
		metric: m,
		logger: slog.Default(),
	}
}

// GetSecret fetches the secret at path. The Secrets Manager secret id is
// SecretPrefix+path. A JSON object secret is returned as its key-value pairs;
// any other SecretString is returned under the single key "value".
func (b *Backend) GetSecret(ctx context.Context, path string) (map[string]string, error) {
	id := b.prefix + path

	if value, hit, isNegative := b.cache.Get(id); hit {
		b.recordCacheHit()
		if isNegative {
			return nil, backend.ErrSecretNotFound
		}
		return value, nil
	}
	b.recordCacheMiss()

	out, err := b.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: awssdk.String(id),
	})
	if err != nil {
		var notFound *types.ResourceNotFoundException
		if errors.As(err, &notFound) {
			b.cache.SetNegative(id)
			return nil, backend.ErrSecretNotFound
		}
		// Never log the underlying error's payload beyond its message; the SDK
		// does not embed secret values in errors.
		b.logger.Warn("aws get secret failed", "path", path, "error", err)
		return nil, fmt.Errorf("aws: get secret: %w", backend.ErrBackendUnavailable)
	}

	result := parseSecret(out.SecretString)
	b.cache.Set(id, result)
	b.updateCacheEntries()
	return result, nil
}

// parseSecret decodes a SecretString. A JSON object decodes to its string
// key-value pairs; anything else (including invalid JSON or a nil pointer) is
// wrapped as {"value": <raw>}.
func parseSecret(secretString *string) map[string]string {
	raw := ""
	if secretString != nil {
		raw = *secretString
	}
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil && parsed != nil {
		return parsed
	}
	return map[string]string{"value": raw}
}

// HealthCheck verifies connectivity by listing a single secret.
func (b *Backend) HealthCheck(ctx context.Context) error {
	_, err := b.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
		MaxResults: awssdk.Int32(1),
	})
	if err != nil {
		b.logger.Warn("aws health check failed", "error", err)
		return fmt.Errorf("aws: health check: %w", backend.ErrBackendUnavailable)
	}
	return nil
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return backendName }

// Close releases resources. The SDK client needs no teardown.
func (b *Backend) Close() error { return nil }

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

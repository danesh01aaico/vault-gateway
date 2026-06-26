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

package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// fakeSM is a hand-rolled smClient whose behavior is driven by func fields.
type fakeSM struct {
	getFn     func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	listFn    func(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	getCalls  int
	listCalls int
}

func (f *fakeSM) GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.getCalls++
	return f.getFn(ctx, in, optFns...)
}

func (f *fakeSM) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	f.listCalls++
	return f.listFn(ctx, in, optFns...)
}

func cachedConfig() Config {
	return Config{
		Cache: cache.Config{
			Enabled:     true,
			TTL:         time.Minute,
			NegativeTTL: time.Minute,
			MaxEntries:  100,
		},
	}
}

func stringOutput(s string) *secretsmanager.GetSecretValueOutput {
	return &secretsmanager.GetSecretValueOutput{SecretString: awssdk.String(s)}
}

func TestGetSecret(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		wantValue map[string]string
		secretNil bool
	}{
		{
			name:      "json object parsed into key-value pairs",
			secret:    `{"username":"admin","password":"s3cr3t"}`,
			wantValue: map[string]string{"username": "admin", "password": "s3cr3t"},
		},
		{
			name:      "plain string wrapped under value key",
			secret:    "just-a-token",
			wantValue: map[string]string{"value": "just-a-token"},
		},
		{
			name:      "invalid json wrapped under value key",
			secret:    `{not-json`,
			wantValue: map[string]string{"value": `{not-json`},
		},
		{
			name:      "json array wrapped under value key",
			secret:    `["a","b"]`,
			wantValue: map[string]string{"value": `["a","b"]`},
		},
		{
			name:      "nil secret string yields empty value",
			secretNil: true,
			wantValue: map[string]string{"value": ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSM{
				getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
					if tc.secretNil {
						return &secretsmanager.GetSecretValueOutput{}, nil
					}
					return stringOutput(tc.secret), nil
				},
			}
			b := newWithClient(f, cachedConfig(), nil)

			got, err := b.GetSecret(context.Background(), "db")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !equalMaps(got, tc.wantValue) {
				t.Fatalf("value = %v, want %v", got, tc.wantValue)
			}
		})
	}
}

func TestGetSecretAppliesPrefix(t *testing.T) {
	var seenID string
	f := &fakeSM{
		getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			seenID = awssdk.ToString(in.SecretId)
			return stringOutput("v"), nil
		},
	}
	cfg := cachedConfig()
	cfg.SecretPrefix = "prod/"
	b := newWithClient(f, cfg, nil)

	if _, err := b.GetSecret(context.Background(), "db"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seenID != "prod/db" {
		t.Fatalf("secret id = %q, want %q", seenID, "prod/db")
	}
}

func TestGetSecretNotFound(t *testing.T) {
	f := &fakeSM{
		getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.ResourceNotFoundException{}
		},
	}
	b := newWithClient(f, cachedConfig(), nil)

	_, err := b.GetSecret(context.Background(), "missing")
	if !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("error = %v, want ErrSecretNotFound", err)
	}
}

func TestGetSecretBackendError(t *testing.T) {
	f := &fakeSM{
		getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, errors.New("network down")
		},
	}
	b := newWithClient(f, cachedConfig(), nil)

	_, err := b.GetSecret(context.Background(), "db")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("error = %v, want ErrBackendUnavailable", err)
	}
}

func TestGetSecretCacheHitAvoidsSecondCall(t *testing.T) {
	f := &fakeSM{
		getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return stringOutput(`{"k":"v"}`), nil
		},
	}
	b := newWithClient(f, cachedConfig(), nil)

	first, err := b.GetSecret(context.Background(), "db")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := b.GetSecret(context.Background(), "db")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if f.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1 (second served from cache)", f.getCalls)
	}
	if !equalMaps(first, second) {
		t.Fatalf("cached value %v != original %v", second, first)
	}

	// Returned maps must be independent clones; mutating one must not affect
	// the next read.
	second["k"] = "tampered"
	third, err := b.GetSecret(context.Background(), "db")
	if err != nil {
		t.Fatalf("third call: %v", err)
	}
	if third["k"] != "v" {
		t.Fatalf("cache returned mutated value: %v", third)
	}
}

func TestGetSecretNegativeCache(t *testing.T) {
	f := &fakeSM{
		getFn: func(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
			return nil, &types.ResourceNotFoundException{}
		},
	}
	b := newWithClient(f, cachedConfig(), nil)

	for i := 0; i < 3; i++ {
		_, err := b.GetSecret(context.Background(), "missing")
		if !errors.Is(err, backend.ErrSecretNotFound) {
			t.Fatalf("call %d: error = %v, want ErrSecretNotFound", i, err)
		}
	}
	if f.getCalls != 1 {
		t.Fatalf("getCalls = %d, want 1 (subsequent served from negative cache)", f.getCalls)
	}
}

func TestHealthCheck(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		f := &fakeSM{
			listFn: func(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
				if awssdk.ToInt32(in.MaxResults) != 1 {
					t.Fatalf("MaxResults = %d, want 1", awssdk.ToInt32(in.MaxResults))
				}
				return &secretsmanager.ListSecretsOutput{}, nil
			},
		}
		b := newWithClient(f, cachedConfig(), nil)
		if err := b.HealthCheck(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("error wrapped as unavailable", func(t *testing.T) {
		f := &fakeSM{
			listFn: func(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
				return nil, errors.New("boom")
			},
		}
		b := newWithClient(f, cachedConfig(), nil)
		err := b.HealthCheck(context.Background())
		if !errors.Is(err, backend.ErrBackendUnavailable) {
			t.Fatalf("error = %v, want ErrBackendUnavailable", err)
		}
	})
}

func TestNameAndClose(t *testing.T) {
	b := newWithClient(&fakeSM{}, cachedConfig(), nil)
	if b.Name() != "aws" {
		t.Fatalf("Name() = %q, want aws", b.Name())
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
}

func equalMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

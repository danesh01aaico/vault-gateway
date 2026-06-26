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

package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/cache"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// fakeClient is a func-field implementation of smClient for tests.
type fakeClient struct {
	accessFn func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	closeErr error
	calls    int
}

func (f *fakeClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	f.calls++
	return f.accessFn(ctx, req, opts...)
}

func (f *fakeClient) Close() error { return f.closeErr }

func accessResponse(data string) *secretmanagerpb.AccessSecretVersionResponse {
	return &secretmanagerpb.AccessSecretVersionResponse{
		Payload: &secretmanagerpb.SecretPayload{Data: []byte(data)},
	}
}

func enabledCache() cache.Config {
	return cache.Config{
		Enabled:     true,
		TTL:         time.Minute,
		NegativeTTL: time.Minute,
		MaxEntries:  100,
	}
}

func TestGetSecretJSONSuccess(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			want := "projects/proj/secrets/opus-workflow-engine/versions/latest"
			if req.GetName() != want {
				t.Errorf("resource name = %q, want %q", req.GetName(), want)
			}
			return accessResponse(`{"user":"alice","pass":"s3cret"}`), nil
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	got, err := b.GetSecret(context.Background(), "opus/workflow-engine")
	if err != nil {
		t.Fatalf("GetSecret returned error: %v", err)
	}
	if got["user"] != "alice" || got["pass"] != "s3cret" {
		t.Fatalf("unexpected secret: %v", got)
	}
}

func TestGetSecretNotFound(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "secret version not found")
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	_, err := b.GetSecret(context.Background(), "missing")
	if !errors.Is(err, backend.ErrSecretNotFound) {
		t.Fatalf("expected ErrSecretNotFound, got %v", err)
	}
}

func TestGetSecretBackendUnavailable(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.Unavailable, "backend down")
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	_, err := b.GetSecret(context.Background(), "any")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("expected ErrBackendUnavailable, got %v", err)
	}
}

func TestGetSecretInvalidJSON(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return accessResponse("not-json"), nil
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	_, err := b.GetSecret(context.Background(), "any")
	if !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("expected ErrBackendUnavailable for invalid JSON, got %v", err)
	}
}

func TestGetSecretCacheHit(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return accessResponse(`{"k":"v"}`), nil
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	if _, err := b.GetSecret(context.Background(), "p"); err != nil {
		t.Fatalf("first GetSecret error: %v", err)
	}
	if _, err := b.GetSecret(context.Background(), "p"); err != nil {
		t.Fatalf("second GetSecret error: %v", err)
	}
	if fc.calls != 1 {
		t.Fatalf("expected 1 client call due to cache hit, got %d", fc.calls)
	}
}

func TestGetSecretNegativeCacheHit(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "nope")
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, metrics.New())

	for i := 0; i < 2; i++ {
		if _, err := b.GetSecret(context.Background(), "gone"); !errors.Is(err, backend.ErrSecretNotFound) {
			t.Fatalf("expected ErrSecretNotFound, got %v", err)
		}
	}
	if fc.calls != 1 {
		t.Fatalf("expected 1 client call due to negative cache hit, got %d", fc.calls)
	}
}

func TestSecretIDMapping(t *testing.T) {
	b := newWithClient(&fakeClient{}, Config{ProjectID: "proj", SecretPrefix: "prod-"}, metrics.New())
	if got := b.secretID("opus/workflow-engine"); got != "prod-opus-workflow-engine" {
		t.Fatalf("secretID = %q, want prod-opus-workflow-engine", got)
	}
}

func TestHealthCheckNotFoundIsHealthy(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.NotFound, "no probe")
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj"}, metrics.New())
	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("expected healthy on NotFound, got %v", err)
	}
}

func TestHealthCheckUnavailable(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, status.Error(codes.Unavailable, "down")
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj"}, metrics.New())
	if err := b.HealthCheck(context.Background()); !errors.Is(err, backend.ErrBackendUnavailable) {
		t.Fatalf("expected ErrBackendUnavailable, got %v", err)
	}
}

func TestNameAndClose(t *testing.T) {
	fc := &fakeClient{}
	b := newWithClient(fc, Config{ProjectID: "proj"}, metrics.New())
	if b.Name() != "gcp" {
		t.Fatalf("Name = %q, want gcp", b.Name())
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
}

func TestNilMetricsSafe(t *testing.T) {
	fc := &fakeClient{
		accessFn: func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return accessResponse(`{"k":"v"}`), nil
		},
	}
	b := newWithClient(fc, Config{ProjectID: "proj", Cache: enabledCache()}, nil)
	if _, err := b.GetSecret(context.Background(), "p"); err != nil {
		t.Fatalf("GetSecret with nil metrics: %v", err)
	}
}

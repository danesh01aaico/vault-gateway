//go:build e2e

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

package e2e

import (
	"context"
	"os"
	"testing"

	awsbackend "github.com/vault-gateway/vault-gateway/internal/backend/aws"
	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// TestAWSBackendIntegration exercises the real AWS Secrets Manager backend
// against a LocalStack endpoint (or any AWS-compatible endpoint). It is a guarded
// integration test: it SKIPS unless AWS_E2E_ENDPOINT is set, so the default
// `go test -tags=e2e ./e2e/...` run needs no cloud credentials.
//
// Required env vars to enable:
//
//	AWS_E2E_ENDPOINT      Secrets Manager endpoint URL (e.g. http://localhost:4566 for LocalStack).
//	AWS_E2E_REGION        AWS region (default "us-east-1" if unset).
//	E2E_AWS_SECRET        Secret id/name to read (must already exist at the endpoint).
//
// LocalStack also honours the standard AWS credential chain; export
// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (LocalStack accepts "test"/"test").
func TestAWSBackendIntegration(t *testing.T) {
	endpoint := os.Getenv("AWS_E2E_ENDPOINT")
	if endpoint == "" {
		t.Skip("set AWS_E2E_ENDPOINT to run")
	}

	region := os.Getenv("AWS_E2E_REGION")
	if region == "" {
		region = "us-east-1"
	}
	secretName := os.Getenv("E2E_AWS_SECRET")
	if secretName == "" {
		t.Skip("set E2E_AWS_SECRET to run the AWS read assertion")
	}

	b, err := awsbackend.New(context.Background(), awsbackend.Config{
		Region:      region,
		EndpointURL: endpoint,
		Cache:       cache.Config{Enabled: false},
	}, nil, nil)
	if err != nil {
		t.Fatalf("construct aws backend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	data, err := b.GetSecret(context.Background(), secretName)
	if err != nil {
		t.Fatalf("GetSecret(%q): %v", secretName, err)
	}
	if len(data) == 0 {
		t.Fatalf("GetSecret(%q) returned no key-value pairs", secretName)
	}
	t.Logf("aws secret %q resolved %d key(s)", secretName, len(data))
}

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

	azurebackend "github.com/vault-gateway/vault-gateway/internal/backend/azure"
	"github.com/vault-gateway/vault-gateway/internal/cache"
)

// TestAzureBackendIntegration exercises the real Azure Key Vault backend against
// a live Key Vault. It is a guarded integration test: it SKIPS unless
// AZURE_E2E_VAULT_URL is set, so the default `go test -tags=e2e ./e2e/...` run
// needs no Azure credentials.
//
// Required env vars to enable:
//
//	AZURE_E2E_VAULT_URL   Key Vault DNS endpoint (e.g. https://my-vault.vault.azure.net/).
//	E2E_AZURE_PATH        Path to read (must already exist in the vault).
//	AZURE_E2E_STRATEGY    Naming strategy "flat" or "json" (default "flat").
//
// Authentication uses DefaultAzureCredential, so supply credentials via the
// standard chain (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET,
// workload identity, or `az login`).
func TestAzureBackendIntegration(t *testing.T) {
	vaultURL := os.Getenv("AZURE_E2E_VAULT_URL")
	if vaultURL == "" {
		t.Skip("set AZURE_E2E_VAULT_URL to run")
	}

	path := os.Getenv("E2E_AZURE_PATH")
	if path == "" {
		t.Skip("set E2E_AZURE_PATH to run the Azure read assertion")
	}
	strategy := os.Getenv("AZURE_E2E_STRATEGY")
	if strategy == "" {
		strategy = "flat"
	}

	b, err := azurebackend.New(context.Background(), azurebackend.Config{
		VaultURL:       vaultURL,
		NamingStrategy: strategy,
		Cache:          cache.Config{Enabled: false},
	}, nil, nil)
	if err != nil {
		t.Fatalf("construct azure backend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}

	data, err := b.GetSecret(context.Background(), path)
	if err != nil {
		t.Fatalf("GetSecret(%q): %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("GetSecret(%q) returned no key-value pairs", path)
	}
	t.Logf("azure path %q resolved %d key(s)", path, len(data))
}

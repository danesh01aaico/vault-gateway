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

// Package backend defines the SecretBackend abstraction that all cloud-native
// secret stores implement, plus the sentinel errors handlers translate into
// Vault-compatible HTTP status codes.
package backend

import (
	"context"
	"errors"
)

// Sentinel errors returned by backend implementations. Handlers map these to
// HTTP status codes: ErrSecretNotFound -> 404, ErrBackendUnavailable -> 502.
var (
	// ErrSecretNotFound indicates the requested path does not exist.
	ErrSecretNotFound = errors.New("secret not found")
	// ErrBackendUnavailable indicates the backend could not be reached.
	ErrBackendUnavailable = errors.New("backend unavailable")
)

// SecretBackend is the interface every secret store (AWS, Azure, Vault, GCP)
// implements. Implementations must be safe for concurrent use.
type SecretBackend interface {
	// GetSecret retrieves all key-value pairs at the given path. It returns
	// ErrSecretNotFound if the path does not exist and ErrBackendUnavailable
	// if the backend cannot be reached.
	GetSecret(ctx context.Context, path string) (map[string]string, error)

	// HealthCheck verifies backend connectivity.
	HealthCheck(ctx context.Context) error

	// Name returns the backend identifier for logging and metrics.
	Name() string

	// Close releases any resources held by the backend.
	Close() error
}

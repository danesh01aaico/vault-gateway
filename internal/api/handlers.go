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

package api

import (
	"log/slog"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/auth"
	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/metrics"
)

// Handlers bundles the dependencies shared by all API handlers. Construct one
// with NewHandlers and register its methods via the server routes.
type Handlers struct {
	backend   backend.SecretBackend
	validator auth.TokenValidator
	tokens    *auth.TokenStore
	rbac      *auth.RBAC
	metrics   *metrics.Metrics
	logger    *slog.Logger

	defaultTokenTTL time.Duration
	roleTokenTTL    map[string]time.Duration

	backendHealthCheck  bool
	backendCheckTimeout time.Duration
	clusterID           string

	now func() time.Time
}

// Config carries the construction parameters for Handlers.
type Config struct {
	Backend             backend.SecretBackend
	Validator           auth.TokenValidator
	Tokens              *auth.TokenStore
	RBAC                *auth.RBAC
	Metrics             *metrics.Metrics
	Logger              *slog.Logger
	DefaultTokenTTL     time.Duration
	RoleTokenTTL        map[string]time.Duration
	BackendHealthCheck  bool
	BackendCheckTimeout time.Duration
	ClusterID           string
}

// NewHandlers builds the API handler set. logger nil falls back to the default.
func NewHandlers(c Config) *Handlers {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := c.BackendCheckTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Handlers{
		backend:             c.Backend,
		validator:           c.Validator,
		tokens:              c.Tokens,
		rbac:                c.RBAC,
		metrics:             c.Metrics,
		logger:              logger,
		defaultTokenTTL:     c.DefaultTokenTTL,
		roleTokenTTL:        c.RoleTokenTTL,
		backendHealthCheck:  c.BackendHealthCheck,
		backendCheckTimeout: timeout,
		clusterID:           c.ClusterID,
		now:                 time.Now,
	}
}

// ttlForRole returns the configured token TTL for role, or the default.
func (h *Handlers) ttlForRole(role string) time.Duration {
	if ttl, ok := h.roleTokenTTL[role]; ok && ttl > 0 {
		return ttl
	}
	return h.defaultTokenTTL
}

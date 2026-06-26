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
	"context"
	"net/http"

	"github.com/vault-gateway/vault-gateway/internal/version"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// HealthHandler implements GET /v1/sys/health. When backend health checking is
// enabled and the backend is unreachable, it returns 503 with a Vault-shaped
// health body reporting the gateway as sealed.
func (h *Handlers) HealthHandler(w http.ResponseWriter, r *http.Request) {
	sealed := false
	status := http.StatusOK

	if h.backendHealthCheck && h.backend != nil {
		ctx, cancel := context.WithTimeout(r.Context(), h.backendCheckTimeout)
		defer cancel()
		if err := h.backend.HealthCheck(ctx); err != nil {
			sealed = true
			status = http.StatusServiceUnavailable
			h.logger.WarnContext(r.Context(), "backend health check failed",
				"backend", h.backendName(), "error", err.Error(),
				"request_id", RequestID(r.Context()))
		}
	}

	writeJSON(w, status, vaultresponse.HealthResponse{
		Initialized:                true,
		Sealed:                     sealed,
		Standby:                    false,
		PerformanceStandby:         false,
		ReplicationPerformanceMode: "disabled",
		ReplicationDRMode:          "disabled",
		ServerTimeUTC:              h.now().UTC().Unix(),
		Version:                    version.UserAgent(),
		ClusterName:                "vault-gateway",
		ClusterID:                  h.clusterID,
	})
}

// SealStatusHandler implements GET /v1/sys/seal-status. The gateway has no seal
// concept, so it always reports unsealed and initialized.
func (h *Handlers) SealStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, vaultresponse.SealStatusResponse{
		Type:        "shamir",
		Initialized: true,
		Sealed:      false,
		T:           1,
		N:           1,
		Progress:    0,
		Nonce:       "",
		Version:     version.Version,
		BuildDate:   version.BuildDate,
		Migration:   false,
		ClusterName: "vault-gateway",
		ClusterID:   h.clusterID,
		StorageType: "gateway",
	})
}

func (h *Handlers) backendName() string {
	if h.backend == nil {
		return "none"
	}
	return h.backend.Name()
}

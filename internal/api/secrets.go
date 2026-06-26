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
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vault-gateway/vault-gateway/internal/backend"
	"github.com/vault-gateway/vault-gateway/internal/secretpath"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// SecretReadHandler implements GET /v1/secret/data/{path}. It verifies the
// X-Vault-Token, checks RBAC for the path, reads from the backend, and returns
// a Vault KV v2 response. Invalid tokens and unauthorized paths both return the
// same 403 so the response never reveals which check failed.
func (h *Handlers) SecretReadHandler(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	reqID := RequestID(r.Context())
	srcIP := clientIP(r)
	path := strings.TrimPrefix(r.PathValue("path"), "/")

	if err := validatePath(path); err != nil {
		writeError(w, http.StatusBadRequest, "invalid secret path")
		return
	}

	token := r.Header.Get("X-Vault-Token")
	identity, err := h.tokens.VerifyToken(token)
	if err != nil {
		h.audit("read", reqID, srcIP, "", "", "", path, "denied")
		h.observeSecret("denied", start)
		writePermissionDenied(w)
		return
	}

	if !h.rbac.CheckAccess(identity, path) {
		h.audit("read", reqID, srcIP, identity.Namespace, identity.ServiceAccount, identity.Role, path, "denied")
		h.observeSecret("denied", start)
		writePermissionDenied(w)
		return
	}

	data, err := h.backend.GetSecret(r.Context(), path)
	switch {
	case errors.Is(err, backend.ErrSecretNotFound):
		h.audit("read", reqID, srcIP, identity.Namespace, identity.ServiceAccount, identity.Role, path, "not_found")
		h.observeSecret("not_found", start)
		writeError(w, http.StatusNotFound, "secret not found")
		return
	case errors.Is(err, backend.ErrBackendUnavailable):
		h.audit("read", reqID, srcIP, identity.Namespace, identity.ServiceAccount, identity.Role, path, "error")
		h.observeSecret("error", start)
		h.logger.ErrorContext(r.Context(), "backend unavailable",
			"backend", h.backendName(), "path", path, "request_id", reqID, "error", err.Error())
		writeError(w, http.StatusBadGateway, "backend unavailable")
		return
	case err != nil:
		h.audit("read", reqID, srcIP, identity.Namespace, identity.ServiceAccount, identity.Role, path, "error")
		h.observeSecret("error", start)
		h.logger.ErrorContext(r.Context(), "backend error",
			"backend", h.backendName(), "path", path, "request_id", reqID, "error", err.Error())
		writeError(w, http.StatusBadGateway, "backend error")
		return
	}

	h.audit("read", reqID, srcIP, identity.Namespace, identity.ServiceAccount, identity.Role, path, "success")
	h.observeSecret("success", start)

	resp := vaultresponse.SecretResponse{
		RequestID: reqID,
		Data: vaultresponse.SecretData{
			Data: data,
			Metadata: vaultresponse.SecretMetadata{
				CreatedTime:  h.now().UTC().Format(time.RFC3339),
				DeletionTime: "",
				Destroyed:    false,
				Version:      1,
			},
		},
	}
	writeJSON(w, http.StatusOK, resp)

	// Best-effort scrub of the secret material from our copy after writing the
	// response. Go's GC makes this advisory, not a guarantee (documented in the
	// security model).
	clearMap(data)
}

func (h *Handlers) observeSecret(status string, start time.Time) {
	if h.metrics == nil {
		return
	}
	name := h.backendName()
	h.metrics.SecretRequests.WithLabelValues(status, name).Inc()
	h.metrics.SecretDuration.WithLabelValues(name).Observe(h.now().Sub(start).Seconds())
}

// validatePath enforces the hardened allowlist from the secretpath package:
// it rejects traversal, null bytes, control characters, shell metacharacters,
// over-long paths, and any rune outside the explicit allowlist.
func validatePath(path string) error {
	return secretpath.Validate(path)
}

// clearMap overwrites and deletes all entries from m (best-effort zeroing).
func clearMap(m map[string]string) {
	for k := range m {
		m[k] = ""
		delete(m, k)
	}
}

// clientIP extracts a best-effort source IP for audit logging, honoring a
// single X-Forwarded-For hop when present.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// audit emits a structured audit log line. It never includes secret values or
// tokens.
func (h *Handlers) audit(action, reqID, srcIP, namespace, sa, role, path, result string) {
	h.logger.Info("audit",
		"action", action,
		"request_id", reqID,
		"src_ip", srcIP,
		"namespace", namespace,
		"service_account", sa,
		"role", role,
		"path", path,
		"result", result,
	)
}

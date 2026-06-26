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
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// loginRequest is the body of POST /v1/auth/kubernetes/login.
type loginRequest struct {
	JWT  string `json:"jwt"`
	Role string `json:"role"`
}

// K8sLoginHandler implements POST /v1/auth/kubernetes/login. It validates the
// service-account JWT via the TokenReview API, verifies the role binding, and
// issues a short-lived client token. All authentication and authorization
// failures return an identical 403 "permission denied" so the response never
// reveals whether the role, namespace, or service account was at fault.
func (h *Handlers) K8sLoginHandler(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	reqID := RequestID(r.Context())

	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.observeAuth("failure", "", start)
		writeError(w, http.StatusBadRequest, "error reading request body")
		return
	}
	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		h.observeAuth("failure", "", start)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.JWT == "" || req.Role == "" {
		h.observeAuth("failure", req.Role, start)
		writeError(w, http.StatusBadRequest, "missing required fields: jwt and role")
		return
	}

	srcIP := clientIP(r)

	identity, err := h.validator.ValidateK8sJWT(r.Context(), req.JWT)
	if err != nil {
		h.audit("login", reqID, srcIP, "", "", req.Role, "", "failure")
		h.observeAuth("failure", req.Role, start)
		writePermissionDenied(w)
		return
	}

	// Verify the authenticated identity is permitted to assume the role.
	if !h.rbac.CheckBinding(req.Role, identity.Namespace, identity.ServiceAccount) {
		h.audit("login", reqID, srcIP, identity.Namespace, identity.ServiceAccount, req.Role, "", "failure")
		h.observeAuth("failure", req.Role, start)
		writePermissionDenied(w)
		return
	}
	identity.Role = req.Role

	ttl := h.ttlForRole(req.Role)
	token, accessor, err := h.tokens.IssueToken(*identity, ttl)
	if err != nil {
		h.audit("login", reqID, srcIP, identity.Namespace, identity.ServiceAccount, req.Role, "", "failure")
		h.observeAuth("failure", req.Role, start)
		// Token quota or RNG failure — generic denial, do not leak specifics.
		writePermissionDenied(w)
		return
	}

	if h.metrics != nil {
		h.metrics.ActiveTokens.Set(float64(h.tokens.TokenCount()))
	}
	h.audit("login", reqID, srcIP, identity.Namespace, identity.ServiceAccount, req.Role, "", "success")
	h.observeAuth("success", req.Role, start)

	writeJSON(w, http.StatusOK, vaultresponse.AuthResponse{
		RequestID: reqID,
		Auth: &vaultresponse.Auth{
			ClientToken:   token,
			Accessor:      accessor,
			Policies:      []string{"default", req.Role},
			TokenPolicies: []string{"default", req.Role},
			Metadata: map[string]string{
				"role":                      req.Role,
				"service_account_name":      identity.ServiceAccount,
				"service_account_namespace": identity.Namespace,
				"service_account_uid":       identity.ServiceAccountUID,
			},
			LeaseDuration: int(ttl / time.Second),
			Renewable:     false,
			EntityID:      "",
			TokenType:     "service",
			Orphan:        true,
		},
	})
}

func (h *Handlers) observeAuth(status, role string, start time.Time) {
	if h.metrics == nil {
		return
	}
	h.metrics.AuthRequests.WithLabelValues(status, role).Inc()
	h.metrics.AuthDuration.Observe(h.now().Sub(start).Seconds())
}

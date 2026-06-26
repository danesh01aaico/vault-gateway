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

package server

import (
	"encoding/json"
	"net/http"

	"github.com/vault-gateway/vault-gateway/internal/api"
	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// NewRouter builds the Vault-compatible API mux using Go 1.22+ method-based
// routing. Unknown paths return a Vault-shaped 404.
func NewRouter(h *api.Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/health", h.HealthHandler)
	mux.HandleFunc("GET /v1/sys/seal-status", h.SealStatusHandler)
	mux.HandleFunc("POST /v1/auth/kubernetes/login", h.K8sLoginHandler)
	mux.HandleFunc("GET /v1/secret/data/{path...}", h.SecretReadHandler)
	mux.HandleFunc("/", notFoundHandler)
	return mux
}

// notFoundHandler returns a Vault-compatible 404 for unmatched routes.
func notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = writeJSONBody(w, vaultresponse.ErrorResponse{Errors: []string{"not found"}})
}

// writeJSONBody encodes v as JSON to w. Status and headers must be set by the
// caller.
func writeJSONBody(w http.ResponseWriter, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

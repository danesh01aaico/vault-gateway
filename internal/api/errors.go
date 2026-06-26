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

// Package api implements the Vault-compatible HTTP handlers: health, seal
// status, Kubernetes login, and KV v2 secret reads. Response bodies match
// HashiCorp Vault's exact JSON shape so clients such as vault-env work
// unmodified.
package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

// contextKey is an unexported type for request-scoped context keys.
type contextKey string

const requestIDKey contextKey = "request_id"

// WithRequestID returns a child context carrying the request ID. Middleware
// sets this; handlers read it via RequestID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID from ctx, or "" if unset.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// Generic permission-denied message. Auth and authorization failures both use
// this identical message so the response never reveals which check failed.
const msgPermissionDenied = "permission denied"

// writeJSON serializes v as JSON with the given status code. The Content-Type
// and Cache-Control (no-store) headers are set by middleware, but we set
// Content-Type here too for direct handler tests.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Best effort: if encoding fails after WriteHeader there is nothing useful
	// left to send to the client.
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits a Vault-compatible error envelope: {"errors":[...]}.
func writeError(w http.ResponseWriter, status int, messages ...string) {
	if len(messages) == 0 {
		messages = []string{http.StatusText(status)}
	}
	writeJSON(w, status, vaultresponse.ErrorResponse{Errors: messages})
}

// writePermissionDenied emits the uniform 403 used for every auth/authorization
// failure.
func writePermissionDenied(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, msgPermissionDenied)
}

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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vault-gateway/vault-gateway/pkg/vaultresponse"
)

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) vaultresponse.ErrorResponse {
	t.Helper()
	var er vaultresponse.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil {
		t.Fatalf("unmarshal error response: %v (body=%q)", err, rr.Body.String())
	}
	return er
}

func TestWriteError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusBadGateway, "boom", "again")

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	er := decodeError(t, rr)
	if len(er.Errors) != 2 || er.Errors[0] != "boom" || er.Errors[1] != "again" {
		t.Fatalf("errors = %v, want [boom again]", er.Errors)
	}
}

func TestWriteErrorNoMessagesFallsBackToStatusText(t *testing.T) {
	rr := httptest.NewRecorder()
	writeError(rr, http.StatusInternalServerError)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	er := decodeError(t, rr)
	want := http.StatusText(http.StatusInternalServerError)
	if len(er.Errors) != 1 || er.Errors[0] != want {
		t.Fatalf("errors = %v, want [%q]", er.Errors, want)
	}
}

func TestWritePermissionDenied(t *testing.T) {
	rr := httptest.NewRecorder()
	writePermissionDenied(rr)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	er := decodeError(t, rr)
	if len(er.Errors) != 1 || er.Errors[0] != "permission denied" {
		t.Fatalf("errors = %v, want [permission denied]", er.Errors)
	}
}

func TestRequestIDRoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "abc-123")
	if got := RequestID(ctx); got != "abc-123" {
		t.Fatalf("RequestID = %q, want abc-123", got)
	}
}

func TestRequestIDEmptyContext(t *testing.T) {
	if got := RequestID(context.Background()); got != "" {
		t.Fatalf("RequestID = %q, want empty", got)
	}
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	writeJSON(rr, http.StatusTeapot, map[string]string{"hello": "world"})

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTeapot)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["hello"] != "world" {
		t.Fatalf("body = %v, want hello=world", got)
	}
}

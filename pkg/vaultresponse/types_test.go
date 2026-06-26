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

package vaultresponse

import (
	"encoding/json"
	"strings"
	"testing"
)

// mustMarshal returns the JSON encoding of v as a string.
func mustMarshal(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// assertContains fails if any wanted substring is missing from s.
func assertContains(t *testing.T, s string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("JSON %s\nmissing %q", s, w)
		}
	}
}

func TestHealthResponseFields(t *testing.T) {
	h := HealthResponse{
		Initialized:                true,
		Sealed:                     false,
		Standby:                    false,
		PerformanceStandby:         false,
		ReplicationPerformanceMode: "disabled",
		ReplicationDRMode:          "disabled",
		ServerTimeUTC:              1700000000,
		Version:                    "1.15.0",
		ClusterName:                "vault-cluster",
		ClusterID:                  "abc",
	}
	js := mustMarshal(t, h)
	assertContains(t, js,
		`"initialized"`, `"sealed"`, `"standby"`, `"performance_standby"`,
		`"replication_performance_mode"`, `"replication_dr_mode"`,
		`"server_time_utc"`, `"version"`, `"cluster_name"`, `"cluster_id"`)
}

func TestAuthResponseFields(t *testing.T) {
	a := AuthResponse{
		RequestID:     "req-1",
		LeaseID:       "",
		Renewable:     true,
		LeaseDuration: 3600,
		Auth: &Auth{
			ClientToken:   "s.token",
			Accessor:      "acc",
			Policies:      []string{"default"},
			TokenPolicies: []string{"default"},
			Metadata:      map[string]string{"role": "reader"},
			LeaseDuration: 3600,
			Renewable:     true,
			EntityID:      "ent",
			TokenType:     "service",
			Orphan:        true,
		},
	}
	js := mustMarshal(t, a)
	assertContains(t, js,
		`"request_id"`, `"lease_id"`, `"lease_duration"`, `"data"`,
		`"wrap_info"`, `"warnings"`, `"auth"`,
		`"client_token"`, `"accessor"`, `"policies"`, `"token_policies"`,
		`"metadata"`, `"entity_id"`, `"token_type"`, `"orphan"`)
}

func TestSecretResponseFields(t *testing.T) {
	s := SecretResponse{
		RequestID:     "req-2",
		LeaseDuration: 0,
		Data: SecretData{
			Data: map[string]string{"username": "admin", "password": "p"},
			Metadata: SecretMetadata{
				CreatedTime:    "2026-01-01T00:00:00Z",
				CustomMetadata: nil,
				DeletionTime:   "",
				Destroyed:      false,
				Version:        3,
			},
		},
	}
	js := mustMarshal(t, s)
	assertContains(t, js,
		`"request_id"`, `"lease_id"`, `"renewable"`, `"lease_duration"`,
		`"data"`, `"metadata"`, `"created_time"`, `"custom_metadata"`,
		`"deletion_time"`, `"destroyed"`, `"version"`, `"username"`)

	// Verify the KV v2 double-nested data.data shape.
	var generic map[string]interface{}
	if err := json.Unmarshal([]byte(js), &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	outer, ok := generic["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data not an object")
	}
	if _, ok := outer["data"].(map[string]interface{}); !ok {
		t.Errorf("data.data not present as object")
	}
	meta, ok := outer["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("data.metadata not an object")
	}
	if _, ok := meta["created_time"]; !ok {
		t.Errorf("data.metadata.created_time missing")
	}
}

func TestErrorResponseFields(t *testing.T) {
	e := ErrorResponse{Errors: []string{"permission denied"}}
	js := mustMarshal(t, e)
	assertContains(t, js, `"errors"`, `permission denied`)
}

func TestSealStatusResponseFields(t *testing.T) {
	s := SealStatusResponse{
		Type:         "shamir",
		Initialized:  true,
		Sealed:       false,
		T:            3,
		N:            5,
		Progress:     0,
		Nonce:        "",
		Version:      "1.15.0",
		BuildDate:    "2026-01-01",
		Migration:    false,
		ClusterName:  "vault",
		ClusterID:    "id",
		RecoverySeal: false,
		StorageType:  "raft",
	}
	js := mustMarshal(t, s)
	assertContains(t, js,
		`"type"`, `"initialized"`, `"sealed"`, `"t"`, `"n"`, `"progress"`,
		`"nonce"`, `"version"`, `"build_date"`, `"migration"`,
		`"cluster_name"`, `"cluster_id"`, `"recovery_seal"`, `"storage_type"`)
}

func TestRoundTripHealth(t *testing.T) {
	in := HealthResponse{Initialized: true, Sealed: true, Version: "1.15.0", ServerTimeUTC: 42}
	b, _ := json.Marshal(in)
	var out HealthResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round trip mismatch: %+v != %+v", out, in)
	}
}

func TestRoundTripSecret(t *testing.T) {
	in := SecretResponse{
		RequestID: "r",
		Data: SecretData{
			Data:     map[string]string{"k": "v"},
			Metadata: SecretMetadata{CreatedTime: "t", Version: 2},
		},
	}
	b, _ := json.Marshal(in)
	var out SecretResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Data.Data["k"] != "v" || out.Data.Metadata.Version != 2 || out.Data.Metadata.CreatedTime != "t" {
		t.Errorf("round trip mismatch: %+v", out)
	}
}

func TestRoundTripAuth(t *testing.T) {
	in := AuthResponse{RequestID: "r", Auth: &Auth{ClientToken: "tok", LeaseDuration: 60, Renewable: true}}
	b, _ := json.Marshal(in)
	var out AuthResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Auth == nil || out.Auth.ClientToken != "tok" || out.Auth.LeaseDuration != 60 {
		t.Errorf("round trip mismatch: %+v", out.Auth)
	}
}

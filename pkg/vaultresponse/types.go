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

// Package vaultresponse defines the HashiCorp Vault HTTP API response types
// that Vault Gateway emits. The JSON struct tags match Vault's exact field
// names so that clients such as Bank-Vaults' vault-env can parse responses
// without modification. These types are exported so downstream consumers and
// integration tests can assert on the response shape.
package vaultresponse

// ErrorResponse is Vault's standard error envelope. Every non-2xx response
// from the gateway uses this shape, e.g. {"errors":["permission denied"]}.
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// HealthResponse mirrors the body of GET /v1/sys/health.
type HealthResponse struct {
	Initialized                bool   `json:"initialized"`
	Sealed                     bool   `json:"sealed"`
	Standby                    bool   `json:"standby"`
	PerformanceStandby         bool   `json:"performance_standby"`
	ReplicationPerformanceMode string `json:"replication_performance_mode"`
	ReplicationDRMode          string `json:"replication_dr_mode"`
	ServerTimeUTC              int64  `json:"server_time_utc"`
	Version                    string `json:"version"`
	ClusterName                string `json:"cluster_name"`
	ClusterID                  string `json:"cluster_id"`
}

// SealStatusResponse mirrors the body of GET /v1/sys/seal-status.
type SealStatusResponse struct {
	Type         string `json:"type"`
	Initialized  bool   `json:"initialized"`
	Sealed       bool   `json:"sealed"`
	T            int    `json:"t"`
	N            int    `json:"n"`
	Progress     int    `json:"progress"`
	Nonce        string `json:"nonce"`
	Version      string `json:"version"`
	BuildDate    string `json:"build_date"`
	Migration    bool   `json:"migration"`
	ClusterName  string `json:"cluster_name"`
	ClusterID    string `json:"cluster_id"`
	RecoverySeal bool   `json:"recovery_seal"`
	StorageType  string `json:"storage_type"`
}

// Auth is the nested object inside an AuthResponse.
type Auth struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata"`
	LeaseDuration int               `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	EntityID      string            `json:"entity_id"`
	TokenType     string            `json:"token_type"`
	Orphan        bool              `json:"orphan"`
}

// AuthResponse mirrors the body of POST /v1/auth/kubernetes/login.
type AuthResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          *Auth       `json:"auth"`
}

// SecretMetadata is the KV v2 metadata block.
type SecretMetadata struct {
	CreatedTime    string      `json:"created_time"`
	CustomMetadata interface{} `json:"custom_metadata"`
	DeletionTime   string      `json:"deletion_time"`
	Destroyed      bool        `json:"destroyed"`
	Version        int         `json:"version"`
}

// SecretData is the KV v2 data block: the inner "data" map holds the secret
// key/value pairs and "metadata" holds version info.
type SecretData struct {
	Data     map[string]string `json:"data"`
	Metadata SecretMetadata    `json:"metadata"`
}

// SecretResponse mirrors the body of GET /v1/secret/data/{path} for KV v2.
type SecretResponse struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          SecretData  `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          interface{} `json:"auth"`
}

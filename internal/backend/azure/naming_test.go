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

package azure

import "testing"

func TestFlatSecretPrefix(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"simple", "opus/workflow-engine", "opus-workflow-engine--"},
		{"underscore in path", "opus/order_service", "opus-order-service--"},
		{"nested", "a/b/c", "a-b-c--"},
		{"single segment", "service", "service--"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flatSecretPrefix(tt.path); got != tt.want {
				t.Fatalf("flatSecretPrefix(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestFlatKeyName(t *testing.T) {
	tests := []struct {
		name string
		path string
		key  string
		want string
	}{
		{"underscore key", "opus/workflow-engine", "db_password", "opus-workflow-engine--db-password"},
		{"plain key", "opus/workflow-engine", "host", "opus-workflow-engine--host"},
		{"hyphen key", "svc", "api-key", "svc--api-key"},
		{"nested path", "a/b", "c_d", "a-b--c-d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flatKeyName(tt.path, tt.key)
			if got != tt.want {
				t.Fatalf("flatKeyName(%q, %q) = %q, want %q", tt.path, tt.key, got, tt.want)
			}
			if !validKVName(got) {
				t.Fatalf("flatKeyName produced invalid KV name %q", got)
			}
		})
	}
}

func TestFlatDecodeKey(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		secretName string
		wantKey    string
		wantOK     bool
	}{
		{"match underscore", "opus/workflow-engine", "opus-workflow-engine--db-password", "db_password", true},
		{"match plain", "opus/workflow-engine", "opus-workflow-engine--host", "host", true},
		{"wrong prefix", "opus/workflow-engine", "other-service--host", "", false},
		{"prefix only no key", "opus/workflow-engine", "opus-workflow-engine--", "", false},
		{"unrelated", "svc", "totally-different", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotOK := flatDecodeKey(tt.path, tt.secretName)
			if gotKey != tt.wantKey || gotOK != tt.wantOK {
				t.Fatalf("flatDecodeKey(%q, %q) = (%q, %v), want (%q, %v)",
					tt.path, tt.secretName, gotKey, gotOK, tt.wantKey, tt.wantOK)
			}
		})
	}
}

// TestFlatRoundTrip verifies that encoding a key and decoding it again recovers
// the canonical form (with '-' decoding to '_' per the documented convention).
func TestFlatRoundTrip(t *testing.T) {
	tests := []struct {
		path    string
		key     string
		decoded string
	}{
		{"opus/workflow-engine", "db_password", "db_password"},
		{"a/b/c", "host", "host"},
		// A key with an original hyphen round-trips to an underscore: this is
		// the documented ambiguity of the flat strategy.
		{"svc", "api-key", "api_key"},
	}
	for _, tt := range tests {
		name := flatKeyName(tt.path, tt.key)
		gotKey, ok := flatDecodeKey(tt.path, name)
		if !ok {
			t.Fatalf("flatDecodeKey(%q, %q) failed to match", tt.path, name)
		}
		if gotKey != tt.decoded {
			t.Fatalf("round trip of (%q,%q): got key %q, want %q", tt.path, tt.key, gotKey, tt.decoded)
		}
	}
}

func TestJSONSecretName(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"simple", "opus/workflow-engine", "opus--workflow-engine"},
		{"underscore", "opus/order_service", "opus--order-service"},
		{"nested", "a/b/c", "a--b--c"},
		{"single", "service", "service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonSecretName(tt.path)
			if got != tt.want {
				t.Fatalf("jsonSecretName(%q) = %q, want %q", tt.path, got, tt.want)
			}
			if !validKVName(got) {
				t.Fatalf("jsonSecretName produced invalid KV name %q", got)
			}
		})
	}
}

func TestValidKVName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"alnum", "abc123", true},
		{"hyphens", "a-b-c", true},
		{"double hyphen", "a--b", true},
		{"empty", "", false},
		{"slash", "a/b", false},
		{"underscore", "a_b", false},
		{"dot", "a.b", false},
		{"space", "a b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validKVName(tt.in); got != tt.want {
				t.Fatalf("validKVName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

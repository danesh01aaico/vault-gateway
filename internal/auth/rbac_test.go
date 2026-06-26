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

package auth

import "testing"

func TestMatchPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		// single-segment wildcard
		{"star matches one segment", "opus/*", "opus/web", true},
		{"star does not match two segments", "opus/*", "opus/a/b", false},
		{"star does not match missing segment", "opus/*", "opus", false},
		{"bare star matches single", "*", "foo", true},
		{"bare star rejects two", "*", "foo/bar", false},

		// recursive wildcard
		{"doublestar matches one", "opus/**", "opus/web", true},
		{"doublestar matches many", "opus/**", "opus/a/b", true},
		{"doublestar matches deep", "opus/**", "opus/a/b/c/d", true},
		{"doublestar needs at least one", "opus/**", "opus", false},
		{"bare doublestar matches one", "**", "foo", true},
		{"bare doublestar matches many", "**", "foo/bar/baz", true},

		// exact literals
		{"exact match", "opus/web", "opus/web", true},
		{"exact mismatch", "opus/web", "opus/api", false},
		{"exact prefix not enough", "opus/web", "opus/web/extra", false},

		// mixed
		{"star then literal", "opus/*/config", "opus/web/config", true},
		{"star then literal mismatch", "opus/*/config", "opus/web/secret", false},
		{"doublestar middle", "opus/**/config", "opus/a/b/config", true},
		{"doublestar middle direct", "opus/**/config", "opus/a/config", true},
		{"doublestar middle needs one", "opus/**/config", "opus/config", false},

		// trimming
		{"leading slash trimmed pattern", "/opus/web", "opus/web", true},
		{"trailing slash trimmed path", "opus/web", "opus/web/", true},
		{"both slashes trimmed", "/opus/*/", "/opus/web/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchPath(tt.pattern, tt.path); got != tt.want {
				t.Errorf("MatchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func testRBAC() *RBAC {
	return NewRBAC(map[string]Role{
		"reader": {
			AllowedNamespaces:      []string{"opus-apps", "opus-data"},
			AllowedServiceAccounts: []string{"web", "api"},
			AllowedPaths:           []string{"opus/web/*", "shared/**"},
		},
		"wildcard-sa": {
			AllowedNamespaces:      []string{"opus-apps"},
			AllowedServiceAccounts: []string{"*"},
			AllowedPaths:           []string{"opus/**"},
		},
	})
}

func TestRoleLookup(t *testing.T) {
	r := testRBAC()
	if _, ok := r.Role("reader"); !ok {
		t.Errorf("reader role should exist")
	}
	if _, ok := r.Role("missing"); ok {
		t.Errorf("missing role should not exist")
	}
}

func TestCheckBinding(t *testing.T) {
	r := testRBAC()
	tests := []struct {
		name string
		role string
		ns   string
		sa   string
		want bool
	}{
		{"allowed ns and sa", "reader", "opus-apps", "web", true},
		{"second allowed ns", "reader", "opus-data", "api", true},
		{"disallowed ns", "reader", "other", "web", false},
		{"disallowed sa", "reader", "opus-apps", "worker", false},
		{"unknown role", "ghost", "opus-apps", "web", false},
		{"wildcard sa any", "wildcard-sa", "opus-apps", "anything", true},
		{"wildcard sa wrong ns", "wildcard-sa", "other", "anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.CheckBinding(tt.role, tt.ns, tt.sa); got != tt.want {
				t.Errorf("CheckBinding(%q,%q,%q) = %v, want %v", tt.role, tt.ns, tt.sa, got, tt.want)
			}
		})
	}
}

func TestCheckAccess(t *testing.T) {
	r := testRBAC()
	tests := []struct {
		name     string
		identity *Identity
		path     string
		want     bool
	}{
		{"nil identity", nil, "opus/web/db", false},
		{"unknown role", &Identity{Role: "ghost", Namespace: "opus-apps", ServiceAccount: "web"}, "opus/web/db", false},
		{"disallowed namespace", &Identity{Role: "reader", Namespace: "other", ServiceAccount: "web"}, "opus/web/db", false},
		{"disallowed sa", &Identity{Role: "reader", Namespace: "opus-apps", ServiceAccount: "worker"}, "opus/web/db", false},
		{"allowed path first pattern", &Identity{Role: "reader", Namespace: "opus-apps", ServiceAccount: "web"}, "opus/web/db", true},
		{"allowed path second pattern recursive", &Identity{Role: "reader", Namespace: "opus-apps", ServiceAccount: "web"}, "shared/a/b/c", true},
		{"path not allowed", &Identity{Role: "reader", Namespace: "opus-apps", ServiceAccount: "web"}, "opus/api/db", false},
		{"wildcard sa role access", &Identity{Role: "wildcard-sa", Namespace: "opus-apps", ServiceAccount: "anyone"}, "opus/anything/deep", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.CheckAccess(tt.identity, tt.path); got != tt.want {
				t.Errorf("CheckAccess(%+v, %q) = %v, want %v", tt.identity, tt.path, got, tt.want)
			}
		})
	}
}

func TestCheckAccessNoPaths(t *testing.T) {
	r := NewRBAC(map[string]Role{
		"nopath": {
			AllowedNamespaces:      []string{"ns"},
			AllowedServiceAccounts: []string{"sa"},
			AllowedPaths:           nil,
		},
	})
	id := &Identity{Role: "nopath", Namespace: "ns", ServiceAccount: "sa"}
	if r.CheckAccess(id, "anything") {
		t.Errorf("CheckAccess with no allowed paths should be false")
	}
}

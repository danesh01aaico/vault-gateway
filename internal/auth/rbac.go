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

import "strings"

// Role is a resolved authorization policy bound to a role name.
type Role struct {
	AllowedNamespaces      []string
	AllowedServiceAccounts []string
	AllowedPaths           []string
}

// RBAC evaluates role bindings and path authorization. It is read-only after
// construction and therefore safe for concurrent use.
type RBAC struct {
	roles map[string]Role
}

// NewRBAC constructs an RBAC from the given role table.
func NewRBAC(roles map[string]Role) *RBAC {
	return &RBAC{roles: roles}
}

// Role returns the named role and whether it exists.
func (r *RBAC) Role(name string) (Role, bool) {
	role, ok := r.roles[name]
	return role, ok
}

// CheckBinding reports whether identity (namespace + service account) is
// permitted to assume the given role. It does not check paths.
func (r *RBAC) CheckBinding(role string, namespace, serviceAccount string) bool {
	rl, ok := r.roles[role]
	if !ok {
		return false
	}
	if !contains(rl.AllowedNamespaces, namespace) {
		return false
	}
	if !containsSA(rl.AllowedServiceAccounts, serviceAccount) {
		return false
	}
	return true
}

// CheckAccess reports whether identity may read the given secret path under its
// bound role. Both the role binding and the path glob must match.
func (r *RBAC) CheckAccess(identity *Identity, path string) bool {
	if identity == nil {
		return false
	}
	rl, ok := r.roles[identity.Role]
	if !ok {
		return false
	}
	if !contains(rl.AllowedNamespaces, identity.Namespace) {
		return false
	}
	if !containsSA(rl.AllowedServiceAccounts, identity.ServiceAccount) {
		return false
	}
	for _, pattern := range rl.AllowedPaths {
		if MatchPath(pattern, path) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// containsSA matches a service account against a list supporting the "*"
// wildcard (any service account).
func containsSA(list []string, sa string) bool {
	for _, item := range list {
		if item == "*" || item == sa {
			return true
		}
	}
	return false
}

// MatchPath reports whether path matches a glob pattern with these semantics,
// evaluated per "/"-delimited segment:
//
//   - "*"  matches exactly one segment.
//   - "**" matches one or more remaining segments (recursive).
//   - literal segments must match exactly.
//
// Examples: "opus/*" matches "opus/web" but not "opus/a/b"; "opus/**" matches
// both; "*" matches any single-segment path; "**" matches everything.
func MatchPath(pattern, path string) bool {
	pattern = strings.Trim(pattern, "/")
	path = strings.Trim(path, "/")
	return matchSegments(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchSegments(pat, seg []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// "**" must consume at least one segment and may consume the rest.
			if len(pat) == 1 {
				return len(seg) >= 1
			}
			// Try to match the remainder of the pattern at each suffix.
			for i := 1; i <= len(seg); i++ {
				if matchSegments(pat[1:], seg[i:]) {
					return true
				}
			}
			return false
		}
		if len(seg) == 0 {
			return false
		}
		if pat[0] != "*" && pat[0] != seg[0] {
			return false
		}
		pat = pat[1:]
		seg = seg[1:]
	}
	return len(seg) == 0
}

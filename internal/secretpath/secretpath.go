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

// Package secretpath provides hardened validation for secret paths before they
// are handed to a backend. It is applied at the API boundary AND, as
// defense-in-depth, at each backend's GetSecret entry point.
//
// The rules are a strict allowlist (deny by default) that is at least as strict
// as a shell-injection guard, even though Vault Gateway never shells out: every
// backend maps the path into an external identifier (an AWS secret id, an Azure
// KV name, a GCP secret id, or a Vault KV path), and a hostile path must never
// be able to alter the meaning of that identifier or escape its namespace.
package secretpath

import (
	"errors"
	"fmt"
)

// ErrInvalidPath indicates the secret path failed validation.
var ErrInvalidPath = errors.New("invalid secret path")

// MaxLength bounds a secret path. 256 matches common backend limits (and is no
// looser than vaultmux's item-name cap) while leaving room for prefixes.
const MaxLength = 256

// allowed reports whether r is permitted in a secret path segment. The set is
// an explicit allowlist: ASCII letters, digits, and the structural separators
// '-', '_', '.', '/' and ':'. Everything else — including all shell
// metacharacters, whitespace, control characters, and non-ASCII runes — is
// rejected.
func allowed(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '-' || r == '_' || r == '.' || r == '/' || r == ':':
		return true
	default:
		return false
	}
}

// Validate enforces the hardened allowlist on path. It rejects: empty paths,
// paths over MaxLength, null bytes, control characters, any rune outside the
// allowlist (this subsumes all shell metacharacters), path traversal ("..",
// any "." segment), absolute paths, and empty segments ("//").
func Validate(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrInvalidPath)
	}
	if len(path) > MaxLength {
		return fmt.Errorf("%w: path exceeds %d characters", ErrInvalidPath, MaxLength)
	}
	if path[0] == '/' {
		return fmt.Errorf("%w: absolute paths are not allowed", ErrInvalidPath)
	}
	if path[len(path)-1] == '/' {
		return fmt.Errorf("%w: trailing slash is not allowed", ErrInvalidPath)
	}

	for _, r := range path {
		if r == 0 {
			return fmt.Errorf("%w: contains null byte", ErrInvalidPath)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: contains control character", ErrInvalidPath)
		}
		if !allowed(r) {
			return fmt.Errorf("%w: contains forbidden character %q", ErrInvalidPath, r)
		}
	}

	// Reject traversal and empty segments by inspecting each "/"-segment.
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			seg := path[start:i]
			switch seg {
			case "":
				return fmt.Errorf("%w: empty path segment", ErrInvalidPath)
			case ".", "..":
				return fmt.Errorf("%w: path traversal segment %q", ErrInvalidPath, seg)
			}
			start = i + 1
		}
	}
	return nil
}

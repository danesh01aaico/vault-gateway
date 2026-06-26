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

import (
	"regexp"
	"strings"
)

// Azure Key Vault secret names may contain only alphanumeric characters and
// hyphens (1-127 characters). Vault paths and keys, however, routinely contain
// slashes and underscores. The naming helpers below translate between the two
// worlds for the two supported strategies.
//
// Encoding is necessarily lossy: both '/' and '_' collapse to '-'. The decode
// direction therefore relies on a documented convention rather than perfect
// reversibility. Callers that require exact round-tripping of arbitrary keys
// should prefer the "json" strategy, which stores the original keys verbatim
// inside the secret value.

// kvNamePattern is the set of characters Azure Key Vault permits in a secret
// name.
var kvNamePattern = regexp.MustCompile(`^[0-9a-zA-Z-]+$`)

// validKVName reports whether name is a syntactically valid Azure Key Vault
// secret name (non-empty, alphanumerics and hyphens only).
func validKVName(name string) bool {
	return kvNamePattern.MatchString(name)
}

// pathEncoder collapses the path separators Vault uses ('/' and '_') into the
// single hyphen Key Vault allows. It is used by the flat strategy for both the
// path component and the key component.
var pathEncoder = strings.NewReplacer("/", "-", "_", "-")

// jsonPathEncoder encodes a Vault path for the json strategy. A '/' becomes a
// double hyphen so that path boundaries remain visually distinct from in-segment
// hyphens; a '_' becomes a single hyphen.
var jsonPathEncoder = strings.NewReplacer("/", "--", "_", "-")

// flatEncodePath encodes a Vault path into the prefix portion of a flat secret
// name.
func flatEncodePath(path string) string {
	return pathEncoder.Replace(path)
}

// flatEncodeKey encodes a single key into the key portion of a flat secret name.
func flatEncodeKey(key string) string {
	return pathEncoder.Replace(key)
}

// flatSecretPrefix returns the Key Vault name prefix shared by every secret that
// belongs to path under the flat strategy. The trailing double hyphen separates
// the encoded path from the encoded key, e.g. path "opus/workflow-engine" yields
// "opus-workflow-engine--".
func flatSecretPrefix(path string) string {
	return flatEncodePath(path) + "--"
}

// flatKeyName returns the full Key Vault secret name for a single key of path
// under the flat strategy, e.g. ("opus/workflow-engine", "db_password") yields
// "opus-workflow-engine--db-password".
func flatKeyName(path, key string) string {
	return flatSecretPrefix(path) + flatEncodeKey(key)
}

// flatDecodeKey reverses flatKeyName: given the originating path and a Key Vault
// secret name, it returns the decoded key and reports whether secretName belongs
// to path (i.e. carries the expected prefix). Decoding follows the documented
// convention that every '-' inside the key segment maps back to '_'; original
// hyphens cannot be distinguished from encoded underscores or slashes.
func flatDecodeKey(path, secretName string) (key string, ok bool) {
	prefix := flatSecretPrefix(path)
	rest, found := strings.CutPrefix(secretName, prefix)
	if !found || rest == "" {
		return "", false
	}
	return strings.ReplaceAll(rest, "-", "_"), true
}

// jsonSecretName returns the single Key Vault secret name that holds the JSON
// object for path under the json strategy, e.g. path "opus/workflow-engine"
// yields "opus--workflow-engine".
func jsonSecretName(path string) string {
	return jsonPathEncoder.Replace(path)
}

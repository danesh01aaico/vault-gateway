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

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGoVersion(t *testing.T) {
	if GoVersion() != runtime.Version() {
		t.Fatalf("GoVersion() = %q, want %q", GoVersion(), runtime.Version())
	}
}

func TestString(t *testing.T) {
	s := String()
	for _, want := range []string{"vault-gateway", Version, GitCommit, BuildDate, GoVersion()} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}

func TestUserAgent(t *testing.T) {
	if got, want := UserAgent(), "vault-gateway/"+Version; got != want {
		t.Fatalf("UserAgent() = %q, want %q", got, want)
	}
}

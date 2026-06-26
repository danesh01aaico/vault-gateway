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

// Package version exposes build metadata that is injected at link time via
// -ldflags. See the Makefile and .goreleaser.yml for the exact flags.
package version

import (
	"fmt"
	"runtime"
)

// These variables are overridden at build time with -X linker flags.
var (
	// Version is the semantic version of the build (e.g. "1.0.0").
	Version = "dev"
	// GitCommit is the short git SHA the binary was built from.
	GitCommit = "unknown"
	// BuildDate is the RFC3339 UTC timestamp of the build.
	BuildDate = "unknown"
)

// GoVersion reports the Go runtime version the binary was compiled with.
func GoVersion() string {
	return runtime.Version()
}

// String returns a human readable, single-line version summary.
func String() string {
	return fmt.Sprintf("vault-gateway %s (commit=%s, built=%s, %s)",
		Version, GitCommit, BuildDate, GoVersion())
}

// UserAgent returns a value suitable for the User-Agent header and the Vault
// compatible `version` field, e.g. "vault-gateway/1.0.0".
func UserAgent() string {
	return "vault-gateway/" + Version
}

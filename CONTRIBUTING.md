# Contributing to Vault Gateway

Thanks for your interest in improving Vault Gateway! This document explains how to set up your environment, the workflow we follow, and the standards your changes need to meet.

By participating in this project you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Development setup

You need:

- **Go 1.25+** (`go version`)
- **make**
- **golangci-lint** (for linting; `make lint` will tell you if it is missing)
- **Docker** (optional, for building images and running backend emulators in tests)

Clone and build:

```bash
git clone https://github.com/vault-gateway/vault-gateway.git
cd vault-gateway

make build      # compiles the vault-gateway binary into ./bin
make test       # runs the unit test suite
make lint       # runs gofmt + golangci-lint
```

Run all checks before pushing:

```bash
make test lint
```

## Branch and PR workflow

1. **Fork** the repository and create a topic branch off `main`:
   ```bash
   git checkout -b feat/gcp-regional-secrets
   ```
2. Make focused commits. Keep unrelated changes in separate PRs.
3. Ensure `make test lint` passes locally.
4. Push your branch and open a Pull Request against `main`.
5. Fill in the PR description: what changed, why, and how it was tested. Link any related issue.
6. A maintainer will review. Address feedback by pushing additional commits (we squash on merge).

Keep PRs small and reviewable. Large refactors are easier to land when discussed in an issue first.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/). The commit subject drives the changelog.

```
<type>(<optional scope>): <short summary>

<optional body>

<optional footer(s)>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`.

Examples:

```
feat(backend): add GCP regional secret support
fix(auth): reject tokens with empty audience claim
docs(configuration): document VG_ env-var precedence
```

## DCO / sign-off

All commits must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). This certifies that you wrote the change or have the right to submit it under the project's license.

Add the sign-off automatically with the `-s` flag:

```bash
git commit -s -m "feat(cache): add negative TTL tuning"
```

This appends a line to your commit message:

```
Signed-off-by: Your Name <you@example.com>
```

PRs with unsigned commits will not be merged.

## Running tests

```bash
make test                                   # full unit suite
go test ./internal/backend/aws/...          # a single package
go test -run TestFlatNaming ./internal/backend/azure/...   # a single test
go test -race ./...                         # with the race detector
```

End-to-end tests live in `e2e/` and may require credentials or local backend emulators; see the comments in that directory.

## Coding standards

- **Formatting:** all code must be `gofmt`-clean. Run `gofmt -l .` (or `make lint`) — it must print nothing.
- **Linting:** `golangci-lint run` must pass with no new findings.
- **License header:** every `.go` file must begin with the Apache 2.0 header used throughout the codebase:

  ```go
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
  ```

- **No secret logging.** Never log secret values, tokens, or full backend payloads. Log paths, identities, and outcomes only.
- **Errors:** wrap with context (`fmt.Errorf("...: %w", err)`) and translate backend failures into the sentinel errors in `internal/backend` (`ErrSecretNotFound`, `ErrBackendUnavailable`).

## Adding a new backend

Backends implement the `SecretBackend` interface in `internal/backend/backend.go`:

```go
type SecretBackend interface {
    // GetSecret retrieves all key-value pairs at the given path. Return
    // ErrSecretNotFound if the path does not exist and ErrBackendUnavailable
    // if the backend cannot be reached.
    GetSecret(ctx context.Context, path string) (map[string]string, error)

    // HealthCheck verifies backend connectivity.
    HealthCheck(ctx context.Context) error

    // Name returns the backend identifier for logging and metrics.
    Name() string

    // Close releases any resources held by the backend.
    Close() error
}
```

To add one (e.g. `oraclevault`):

1. Create `internal/backend/<name>/backend.go` implementing `SecretBackend`.
2. Authenticate using **workload identity federation**, never static credentials.
3. Normalize results to `map[string]string`. If the store holds an opaque string, wrap it as `{"value": "..."}` to match the AWS/GCP convention.
4. Map any provider naming constraints in a dedicated `naming.go` with table-driven tests (see `internal/backend/azure/naming.go` for the pattern).
5. Translate "not found" to `ErrSecretNotFound` and connectivity failures to `ErrBackendUnavailable`.
6. Wire the backend into config selection and add a `<name>` config block (see [docs/configuration.md](./docs/configuration.md)).
7. Add unit tests and update the supported-backends table in [README.md](./README.md) and the deployment docs.

## Reporting bugs

Open an issue with:

- Vault Gateway version (`vault-gateway --version`)
- Backend in use and config (redact secrets and credentials)
- Steps to reproduce, expected vs actual behavior
- Relevant logs (remember: the gateway never logs secret values)

**Do not** file security vulnerabilities as public issues — follow [SECURITY.md](./SECURITY.md) instead.

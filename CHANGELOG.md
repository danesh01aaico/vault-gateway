# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (nothing yet)

## [0.1.0] - 2026-06-26

Initial public release.

### Added
- **Vault-compatible HTTP API** implementing the exact subset of endpoints that
  Bank-Vaults' `vault-env` requires: `POST /v1/auth/kubernetes/login`,
  `GET /v1/secret/data/{path}`, `GET /v1/sys/health`, and
  `GET /v1/sys/seal-status`. Responses match Vault's KV v2 and auth shapes.
- **Four pluggable secret backends**, selectable via `backend:` config:
  - AWS Secrets Manager (`aws`) with IRSA identity federation and a configurable
    secret prefix.
  - Azure Key Vault (`azure`) with Azure Workload Identity and `flat` / `json`
    naming strategies for Key Vault's name constraints.
  - HashiCorp Vault (`vault`) via Kubernetes auth, for in-cluster / airgapped
    deployments.
  - GCP Secret Manager (`gcp`) with GKE Workload Identity and
    `[a-zA-Z0-9_-]` name normalization.
- **Kubernetes authentication** that validates ServiceAccount JWTs through the
  TokenReview API and issues short-lived, in-memory, non-renewable client
  tokens (`crypto/rand`, constant-time comparison).
- **Role-based access control** with glob path matching (`*` = one segment,
  `**` = recursive) and namespace / ServiceAccount binding per role.
- **In-memory TTL cache** per backend with positive and negative caching,
  keyed by path (RBAC is always checked before cache lookup).
- **Prometheus metrics** exposed on `:9090` at `/metrics`.
- **TLS 1.2+** support with configurable cert/key, minimum version, and cipher
  suites; per-IP rate limiting; structured `slog` JSON audit logging.
- **Least-privilege Kubernetes RBAC** requiring only `tokenreviews.create`.
- **Helm chart** (`deploy/helm/vault-gateway`) for cluster deployment.
- Configuration via YAML file (`--config` / `VAULT_GATEWAY_CONFIG`) with
  `VG_`-prefixed environment-variable overrides.
- Documentation: architecture, authentication, configuration, security model,
  troubleshooting, and AWS / Azure / airgapped deployment guides.

[Unreleased]: https://github.com/vault-gateway/vault-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vault-gateway/vault-gateway/releases/tag/v0.1.0

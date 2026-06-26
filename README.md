# Vault Gateway

> A lightweight, API-compatible shim that exposes a subset of the HashiCorp Vault HTTP API and routes secret reads to cloud-native backends — so Bank-Vaults' `vault-env` can inject secrets into pods on any cloud, without ever writing a Kubernetes Secret to etcd.

[![Go Report Card](https://goreportcard.com/badge/github.com/vault-gateway/vault-gateway)](https://goreportcard.com/report/github.com/vault-gateway/vault-gateway)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/vault-gateway/vault-gateway)](https://go.dev/)
[![CI](https://img.shields.io/github/actions/workflow/status/vault-gateway/vault-gateway/ci.yml?branch=main)](https://github.com/vault-gateway/vault-gateway/actions)

---

## The problem

Kubernetes Secrets feel like the natural place to keep credentials, but they carry real risks:

- **base64 is not encryption.** A `Secret` is just base64-encoded data. Anyone with read access (or a copy of the manifest) has the plaintext.
- **etcd-at-rest exposure.** By default Secrets are stored unencrypted in etcd. Backups, snapshots, and disk images leak every credential in the cluster.
- **RBAC sprawl.** Granting workloads or operators access to Secrets is coarse-grained and easy to over-provision. A single broad `get secrets` role can read every credential in a namespace.
- **GitOps secret leakage.** Storing Secret manifests in Git (even "encrypted" ones) couples your secret lifecycle to your source history, and plaintext slips into commits, CI logs, and forks.

Meanwhile, most organizations already run a hardened, audited secret store — **AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or HashiCorp Vault**. The hard part is getting those secrets into pods without copying them into etcd first.

## The solution

[Bank-Vaults'](https://bank-vaults.dev/) `vault-env` mutating webhook is a clean answer: it rewrites a pod's entrypoint to fetch secrets from Vault at startup and inject them as environment variables — **no Kubernetes Secret object is ever created**. But it requires a running HashiCorp Vault.

**Vault Gateway** is the missing piece. It is a tiny, stateless service that speaks just enough of the Vault HTTP API to satisfy `vault-env`, and forwards every secret read to the cloud secret store you already operate. The result: daemonless secret injection, on any cloud or airgapped cluster, with zero secrets in etcd and **no real Vault to run**.

`vault-env` only ever calls three Vault endpoints. Vault Gateway implements exactly those (plus health):

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `POST` | `/v1/auth/kubernetes/login` | Validate a Kubernetes ServiceAccount JWT via the TokenReview API; return a Vault-compatible auth response with a `client_token`. |
| `GET`  | `/v1/secret/data/{path}` | Require `X-Vault-Token`; check RBAC; read from the configured backend; return a Vault KV v2 response. |
| `GET`  | `/v1/sys/health`, `/v1/sys/seal-status` | Vault-compatible health and seal status. |

## Architecture

```
                          Kubernetes cluster
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                        │
  │   ┌───────────────────────┐                                           │
  │   │  Bank-Vaults webhook  │  mutates pod spec at admission            │
  │   │  (vault-secrets-      │  injects vault-env + annotations          │
  │   │   webhook)            │                                           │
  │   └───────────┬───────────┘                                           │
  │               │                                                       │
  │               ▼                                                       │
  │   ┌───────────────────────────────┐                                  │
  │   │ Application Pod                │                                  │
  │   │  ┌─────────────────────────┐  │  1. login with projected SA JWT  │
  │   │  │ vault-env (init shim)   │──┼───────────────┐                  │
  │   │  │  reads vault:secret/... │  │  2. GET secret │                 │
  │   │  └─────────────────────────┘  │                │                 │
  │   └───────────────────────────────┘                │                 │
  │                                                     ▼                 │
  │                              ┌────────────────────────────────────┐  │
  │                              │            Vault Gateway            │  │
  │                              │  ┌──────────────────────────────┐  │  │
  │                              │  │ Vault-compatible HTTP API     │  │  │
  │                              │  │  /v1/auth/kubernetes/login    │  │  │
  │                              │  │  /v1/secret/data/{path}       │  │  │
  │                              │  │  /v1/sys/health               │  │  │
  │                              │  └───────────────┬──────────────┘  │  │
  │                              │   TokenReview │ RBAC │ TTL cache    │  │
  │                              │  ┌────────────▼─────────────────┐  │  │
  │                              │  │      Backend router          │  │  │
  │                              │  └──┬───────┬────────┬───────┬──┘  │  │
  │                              └─────┼───────┼────────┼───────┼─────┘  │
  └────────────────────────────────────┼───────┼────────┼───────┼────────┘
                                        ▼       ▼        ▼       ▼
                                   ┌────────┐┌───────┐┌──────┐┌───────┐
                                   │ AWS SM ││ Azure ││ HC   ││ GCP   │
                                   │        ││ KV    ││ Vault││ SM    │
                                   └────────┘└───────┘└──────┘└───────┘
                                   (identity federation — no static creds)
```

See [docs/architecture.md](./docs/architecture.md) for the full component and request-flow breakdown.

## Quick start

### Docker

```bash
docker run --rm \
  -p 8200:8200 -p 9090:9090 \
  -v "$(pwd)/config.yaml:/etc/vault-gateway/config.yaml:ro" \
  ghcr.io/vault-gateway/vault-gateway:latest \
  --config /etc/vault-gateway/config.yaml
```

### Helm

```bash
helm repo add vault-gateway https://vault-gateway.github.io/charts
helm repo update

helm install vault-gateway vault-gateway/vault-gateway \
  --namespace vault-gateway --create-namespace \
  --set backend=aws \
  --set aws.region=us-east-1 \
  --set aws.secretPrefix=opus/
```

### Binary

```bash
# Download from the releases page, then:
vault-gateway --config /etc/vault-gateway/config.yaml
```

You can also point at a config file with the `VAULT_GATEWAY_CONFIG` environment variable, and override any field with `VG_`-prefixed environment variables (e.g. `VG_BACKEND=azure`, `VG_SERVER_PORT=8200`). See [docs/configuration.md](./docs/configuration.md).

## Minimal `config.yaml`

```yaml
server:
  host: 0.0.0.0
  port: 8200
  tls:
    enabled: true
    certFile: /etc/vault-gateway/tls/tls.crt
    keyFile: /etc/vault-gateway/tls/tls.key
    minVersion: "1.2"

backend: aws

aws:
  region: us-east-1
  secretPrefix: opus/
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s
    maxEntries: 1024

auth:
  tokenTTL: 15m
  tokenCleanupInterval: 1m
  maxTokensPerIdentity: 32
  roles:
    workflow-engine:
      allowedNamespaces: ["opus"]
      allowedServiceAccounts: ["workflow-engine"]
      allowedPaths: ["opus/workflow-engine/*"]
      tokenTTL: 10m

logging:
  level: info
  format: json

metrics:
  enabled: true
  port: 9090
  path: /metrics

healthCheck:
  backendCheck: true
  backendCheckTimeout: 3s
  backendCheckInterval: 30s
```

## Supported backends

| Backend | `backend:` value | Identity federation | Secret format | Path mapping |
| ------- | ---------------- | ------------------- | ------------- | ------------ |
| AWS Secrets Manager | `aws` | IRSA (IAM Roles for Service Accounts) | JSON object (plain string → `{"value":"..."}`) | `secretPrefix` + path; `/` allowed, near-direct |
| Azure Key Vault | `azure` | Azure Workload Identity | `flat`: one KV secret per key; `json`: one KV secret per path | name-safe encoding (see below) |
| HashiCorp Vault | `vault` | Kubernetes auth (`authPath`/`role`) | KV v2 native | passthrough |
| GCP Secret Manager | `gcp` | GKE Workload Identity | JSON object (plain string → `{"value":"..."}`) | `[a-zA-Z0-9_-]+`, max 255 |

**Azure naming.** Key Vault secret names allow only alphanumerics and hyphens, with no nesting. The `flat` strategy maps path `opus/workflow-engine` + key `db_password` to the KV secret `opus-workflow-engine--db-password`. The `json` strategy stores one KV secret per path whose value is a JSON object.

**GCP naming.** Names must match `[a-zA-Z0-9_-]+` (max 255 chars), so `opus/workflow-engine` becomes `opus-workflow-engine`.

## Security model

- **No plaintext secrets in etcd** — secrets are streamed from the backend to the pod's process environment; no `Secret` object is created.
- **No static cloud credentials** — every backend authenticates via workload identity federation (IRSA / Azure Workload Identity / GKE Workload Identity / Vault k8s auth).
- **Least-privilege Kubernetes RBAC** — the gateway's only cluster permission is `tokenreviews.create`.
- **Short-lived, in-memory tokens** — issued with `crypto/rand`, compared in constant time, non-renewable, TTL-bounded, never persisted.
- **TLS 1.2+ required**, per-IP rate limiting, and structured audit logging (`slog` JSON).

Full details, trust boundaries, and an honest list of what the gateway does **not** protect against are in [docs/security-model.md](./docs/security-model.md).

## How it compares

| | **Vault Gateway** | Bank-Vaults + real Vault | External Secrets Operator | Secrets Store CSI Driver | Sealed Secrets |
| --- | :---: | :---: | :---: | :---: | :---: |
| Secrets in etcd? | **No** | No | **Yes** (syncs to `Secret`) | No (tmpfs mount) | **Yes** (decrypted `Secret`) |
| Requires running Vault? | **No** | Yes | No | No | No |
| Multi-cloud backends | **Yes** | via Vault | **Yes** | **Yes** | n/a (cluster-local) |
| Daemonless injection | **Yes** (init shim) | **Yes** (init shim) | No (controller) | No (CSI node driver) | No (controller) |
| Airgap friendly | **Yes** (Vault backend) | **Yes** | depends on provider | depends on provider | **Yes** |
| Injection target | env vars | env vars | `Secret` / env | mounted files | `Secret` |

## Documentation

- [Architecture](./docs/architecture.md) — components, request flow, cache and token lifecycle.
- [Authentication](./docs/authentication.md) — Kubernetes auth end to end, role bindings, token TTL.
- [Configuration](./docs/configuration.md) — every field, default, and env-var override.
- [Security model](./docs/security-model.md) — threat model, trust boundaries, RBAC.
- [Troubleshooting](./docs/troubleshooting.md) — common failures and fixes.
- Deployment guides: [AWS](./docs/deployment-aws.md) · [Azure](./docs/deployment-azure.md) · [Airgapped (in-cluster Vault)](./docs/deployment-airgapped.md)

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup, the PR workflow, commit conventions, and how to add a new backend, and review our [Code of Conduct](./CODE_OF_CONDUCT.md). Security issues should follow the process in [SECURITY.md](./SECURITY.md).

## License

Vault Gateway is licensed under the [Apache License 2.0](./LICENSE). Copyright 2026 The Vault Gateway Authors.

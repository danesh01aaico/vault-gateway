# Security model

This document describes what Vault Gateway protects against, what it explicitly
does **not** protect against, its trust boundaries, and the security properties
of its auth, RBAC, cache, and transport.

Related: [architecture](./architecture.md) · [authentication](./authentication.md) · [SECURITY.md](../SECURITY.md).

## What it protects against

- **No plaintext secrets in etcd.** Secrets are streamed from the backend to the
  pod's process environment by `vault-env`. No Kubernetes `Secret` object is
  created, so etcd (and its backups and snapshots) never holds the secret.
- **No static cloud credentials.** Every backend authenticates via workload
  identity federation — IRSA, Azure Workload Identity, GKE Workload Identity, or
  Vault Kubernetes auth. There is no long-lived key to leak.
- **Least-privilege Kubernetes RBAC.** The gateway's only cluster permission is
  `tokenreviews.create`. It cannot read `Secret`, `ConfigMap`, or any workload
  object. A compromised gateway cannot enumerate cluster secrets.
- **Fine-grained authorization.** Each issued token is bound to a role whose
  `allowedNamespaces`, `allowedServiceAccounts`, and `allowedPaths` (glob)
  constrain exactly which secrets the workload may read.
- **Audit trail.** Every login and secret read is logged (identity, path,
  outcome) as structured `slog` JSON — never the secret value.

## What it does NOT protect against

Being honest about the limits is part of the model:

- **A compromised node / kubelet can read projected SA tokens.** The projected
  ServiceAccount token lives on the node's filesystem (tmpfs) for mounting into
  the pod. Root on that node can read it and, within its audience and TTL,
  impersonate the workload to the gateway. Node compromise is outside the
  gateway's control; rely on node hardening, short token TTLs, and audience
  binding to limit blast radius.
- **The gateway sees plaintext secrets in transit.** By design it fetches the
  secret from the backend and returns it to `vault-env`. A compromised gateway
  process can observe the secrets it is asked to serve (only those a caller is
  authorized for, but plaintext nonetheless). Treat the gateway as sensitive and
  run it with the same care as any secret-handling component.
- **Plaintext in the application process.** Once injected, the secret is an
  environment variable in the app process — readable via `/proc`, crash dumps,
  or anything that can inspect that process. This is inherent to env-var
  injection, not specific to the gateway.
- **Best-effort memory zeroing.** Go is garbage-collected; secret bytes may
  linger in freed heap memory until reclaimed. The gateway avoids unnecessary
  copies and does not persist secrets, but cannot guarantee prompt zeroization.
- **Backend-side compromise.** The gateway inherits the security of the
  configured backend. If the backend or its IAM is compromised, so are the
  secrets.

## Trust boundaries

```
  ┌─────────────────────────────────────────────────────────────────┐
  │ Node (kubelet, container runtime) — TRUSTED for pods scheduled    │
  │  on it; can read projected SA tokens on its filesystem            │
  │                                                                   │
  │   ┌──────────────────────┐         ┌───────────────────────────┐ │
  │   │ App pod              │  TLS    │ Vault Gateway pod         │ │
  │   │  vault-env  ─────────┼────────►│  sees plaintext secrets   │ │
  │   │  (holds SA token,    │  1.2+   │  it is asked to serve     │ │
  │   │   then plaintext     │         │  (only authorized paths)  │ │
  │   │   env vars)          │         └─────────────┬─────────────┘ │
  │   └──────────────────────┘                       │ identity fed. │
  └───────────────────────────────────────────────────┼─────────────┘
                                                       │ (no static creds)
                          ┌────────────────────────────▼──────────────┐
                          │ External / in-cluster secret backend       │
                          │ AWS SM · Azure KV · GCP SM · HC Vault       │
                          └────────────────────────────────────────────┘
```

- **Pod ⇄ Gateway:** mutually over TLS; the pod proves identity with its
  projected SA token, the gateway proves identity with its server certificate.
- **Gateway ⇄ Backend:** workload identity federation; no shared static secret.
- **Gateway ⇄ Kubernetes API:** only `tokenreviews.create`.

## Authentication flow

See [authentication](./authentication.md) for the full walkthrough. In summary:
`vault-env` POSTs `{role, jwt}`; the gateway validates the JWT via TokenReview
(audience- and expiry-checked by Kubernetes), confirms the namespace and
ServiceAccount against the role, and issues a short-lived client token bound to
that identity and the role's allowed paths.

## RBAC model

- Roles are defined in config under `auth.roles.<name>`.
- A login is only granted if the authenticated namespace and ServiceAccount are
  in the role's `allowedNamespaces` / `allowedServiceAccounts` (each supports
  `*` = any).
- A secret read is only granted if the path matches one of the role's
  `allowedPaths` globs:
  - `*` matches exactly one path segment.
  - `**` matches any number of segments (recursive).
- Authorization failures return a deliberately generic `permission denied` (403)
  so callers cannot probe which paths exist.

## Token security properties

- **Cryptographically random.** Tokens are generated with `crypto/rand`.
- **Constant-time comparison.** Tokens are compared with `crypto/subtle` to avoid
  timing side channels.
- **Non-renewable.** `Renewable: false`; tokens cannot be extended. They only
  need to outlive the brief startup read burst.
- **TTL-bounded.** Expiry is `role.tokenTTL` (or `auth.tokenTTL`); a background
  sweeper removes expired tokens every `auth.tokenCleanupInterval`.
- **In-memory, per-instance.** Tokens are never written to disk or etcd and are
  not shared across replicas. A replica restart simply invalidates its tokens.
- **Capped per identity.** `auth.maxTokensPerIdentity` bounds concurrent tokens
  to limit abuse.

## Cache security

The cache is keyed by **path only**, which is safe because of strict ordering:

```
token verify  ──►  RBAC (allowedPaths)  ──►  cache lookup  ──►  backend
```

No request reaches the cache without first passing authentication **and**
authorization for that exact path. Two different identities authorized for the
same path see the same (correct) cached value; an identity not authorized for a
path never reaches the cache entry at all. Negative entries (not-found) are
cached with a separate, shorter `negativeTTL` to blunt enumeration while keeping
genuine 404s cheap. The trade-off is staleness: a rotated secret is served until
its entry expires — tune `ttl` accordingly (see
[troubleshooting](./troubleshooting.md#stale-cache-data)).

## TLS requirements

- TLS **1.2 minimum** (1.3 supported); weak ciphers disabled via
  `server.tls.cipherSuites`.
- The secret API must not be served as plaintext HTTP in production
  (`server.tls.enabled: true`).
- For Vault backends, the gateway verifies Vault's certificate against the
  configured `caCert`; `tlsSkipVerify` is for development only.

## Audit logging

Structured `slog` JSON records, per event, fields such as:

- `event` (e.g. `auth.login`, `secret.read`)
- `identity` (`<namespace>/<serviceaccount>`) and `role`
- `path` requested
- `outcome` (`granted`, `denied`, `not_found`, `backend_error`)
- `remote_ip`, `request_id`, `latency_ms`, `cache` (`hit`/`miss`)

Secret values, tokens, and full backend payloads are **never** logged.

## Compared to running real Vault

| Property | Vault Gateway | Real HashiCorp Vault |
| -------- | ------------- | -------------------- |
| Secrets in etcd | No | No |
| Stores secrets itself | No (delegates to backend) | Yes (is the store) |
| Operational surface | Tiny, stateless, 3 endpoints | Full Vault (seal/unseal, storage, replication) |
| Dynamic secrets, leases, PKI, transit | No | Yes |
| Multi-cloud backend | Yes (native) | via Vault secret engines |
| Suited for | Read-only secret injection via `vault-env` | Full secrets-management platform |

Vault Gateway is intentionally a narrow shim for the `vault-env` injection path,
not a Vault replacement. If you need dynamic secrets, leasing, PKI, or transit
encryption, run real Vault (and you can still front it with the gateway in the
[airgapped](./deployment-airgapped.md) topology).

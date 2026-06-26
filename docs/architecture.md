# Architecture

Vault Gateway is a single, stateless Go service that presents a Vault-compatible
HTTP API to Bank-Vaults' `vault-env` and forwards secret reads to a configured
cloud-native backend. This document describes its components, request flows,
and the lifecycle of the in-memory tokens it issues.

See also: [authentication](./authentication.md) · [configuration](./configuration.md) · [security model](./security-model.md).

## Component diagram

```
                          ┌───────────────────────────────────────────┐
                          │              Vault Gateway                 │
                          │                                            │
  HTTPS :8200             │   ┌────────────────────────────────────┐  │
 ───────────────────────► │   │            HTTP server             │  │
  (vault-env)             │   │   TLS 1.2+ · per-IP rate limiter   │  │
                          │   └───────────────┬────────────────────┘  │
                          │                   │ routes                 │
                          │   ┌───────────────▼────────────────────┐  │
                          │   │             Handlers               │  │
                          │   │  /v1/auth/kubernetes/login         │  │
                          │   │  /v1/secret/data/{path}            │  │
                          │   │  /v1/sys/health · seal-status      │  │
                          │   └───┬──────────┬───────────┬─────────┘  │
                          │       │          │           │            │
                          │  ┌────▼───┐  ┌───▼────┐  ┌───▼────────┐   │
                          │  │ Auth   │  │  RBAC  │  │   Cache    │   │
                          │  │ token  │  │ engine │  │ (per-back- │   │
                          │  │ store  │  │ (glob) │  │  end, TTL) │   │
                          │  └────┬───┘  └────────┘  └───┬────────┘   │
                          │       │ TokenReview          │ miss       │
                          │  ┌────▼─────────────┐   ┌────▼─────────┐  │
                          │  │ K8s API client   │   │ Backend      │  │
                          │  │ (tokenreviews)   │   │ router       │  │
                          │  └──────────────────┘   └────┬─────────┘  │
                          │                              │            │
                          └──────────────────────────────┼───────────┘
                                                          │
                  ┌──────────────┬──────────────┬─────────┴──────┐
                  ▼              ▼              ▼                ▼
            ┌──────────┐  ┌────────────┐  ┌──────────┐   ┌────────────┐
            │ AWS      │  │ Azure Key  │  │ HashiCorp│   │ GCP Secret │
            │ Secrets  │  │ Vault      │  │ Vault    │   │ Manager    │
            │ Manager  │  │            │  │          │   │            │
            └──────────┘  └────────────┘  └──────────┘   └────────────┘

  Metrics: Prometheus on :9090 /metrics   ·   Audit: slog JSON to stdout
```

The same diagram in SVG form: [images/architecture.svg](./images/architecture.svg).

### Components

| Component | Responsibility |
| --------- | -------------- |
| **HTTP server** | Terminates TLS (1.2+), applies per-IP rate limiting, routes requests. Honors `server.readTimeout`, `writeTimeout`, `idleTimeout`, `maxRequestBodySize`, and `shutdownGracePeriod`. |
| **Handlers** | Implement the four Vault-compatible endpoints and emit Vault-shaped JSON (`pkg/vaultresponse`). |
| **Auth token store** | In-memory map of issued client tokens → identity + expiry. Per instance; not shared. |
| **K8s API client** | Calls the TokenReview API to validate ServiceAccount JWTs. Backed by the `tokenreviews.create` RBAC permission. |
| **RBAC engine** | Matches the authenticated identity's role against the requested path using glob rules (`*`, `**`). |
| **Cache** | Per-backend in-memory TTL cache with positive and negative entries, keyed by path. |
| **Backend router** | Dispatches `GetSecret`/`HealthCheck` to the configured backend implementation. |
| **Backends** | AWS / Azure / Vault / GCP implementations of `backend.SecretBackend`. |

## Request flow: authentication (TokenReview)

`POST /v1/auth/kubernetes/login`

```
vault-env                Gateway                 Kubernetes API           Token store
   │                        │                          │                       │
   │  {role, jwt}           │                          │                       │
   ├───────────────────────►│                          │                       │
   │                        │  TokenReview(jwt)        │                       │
   │                        ├─────────────────────────►│                       │
   │                        │  authenticated:          │                       │
   │                        │   user=system:service-   │                       │
   │                        │   account:<ns>:<sa>      │                       │
   │                        │◄─────────────────────────┤                       │
   │                        │ resolve role; check       │                       │
   │                        │ allowedNamespaces +       │                       │
   │                        │ allowedServiceAccounts    │                       │
   │                        │ generate crypto/rand token│                       │
   │                        ├──────────────────────────┼──────────────────────►│
   │                        │                          │   store(token,         │
   │                        │                          │     identity, expiry)  │
   │  auth.client_token,    │                          │                       │
   │  lease_duration (TTL)  │                          │                       │
   │◄───────────────────────┤                          │                       │
```

1. `vault-env` POSTs `{ "role": "...", "jwt": "<projected SA token>" }`.
2. The gateway submits the JWT to the TokenReview API. Kubernetes validates the
   signature, audience, and expiry, and returns the authenticated username
   `system:serviceaccount:<namespace>:<serviceaccount>`.
3. The gateway looks up the named role and verifies the namespace and
   ServiceAccount are in the role's `allowedNamespaces` / `allowedServiceAccounts`.
4. On success it generates a token with `crypto/rand`, stores it in memory with
   the bound identity and an expiry (`role.tokenTTL` or `auth.tokenTTL`), and
   returns a Vault `auth` block whose `client_token` and `lease_duration`
   `vault-env` understands.

## Request flow: secret read

`GET /v1/secret/data/{path}` with header `X-Vault-Token: <client_token>`

```
vault-env            Gateway: token → RBAC → cache → backend
   │                     │
   │ GET secret/data/p   │
   │ X-Vault-Token       │
   ├────────────────────►│ 1. look up token (constant-time compare)
   │                     │    └─ missing/expired → 403 permission denied
   │                     │ 2. RBAC: identity's role allowedPaths matches "p"?
   │                     │    └─ no match → 403 permission denied
   │                     │ 3. cache.Get("p")
   │                     │    ├─ positive hit → return cached map
   │                     │    ├─ negative hit → 404 not found
   │                     │    └─ miss → backend.GetSecret(ctx, "p")
   │                     │           ├─ ok       → cache positive, return
   │                     │           ├─ NotFound → cache negative, 404
   │                     │           └─ Unavail. → 502 (not cached)
   │  KV v2 response     │
   │◄────────────────────┤
```

The strict ordering — **token verify → RBAC → cache → backend** — is what makes
caching by path alone safe: no caller ever reaches the cache without first
passing authentication and authorization for that exact path. See the
[cache security analysis](./security-model.md#cache-security) for details.

## Backend abstraction layer

Every backend implements one interface (`internal/backend/backend.go`):

```go
type SecretBackend interface {
    GetSecret(ctx context.Context, path string) (map[string]string, error)
    HealthCheck(ctx context.Context) error
    Name() string
    Close() error
}
```

- `GetSecret` returns a flat `map[string]string` of key/value pairs. AWS and GCP
  store JSON objects; a plain-string secret is normalized to `{"value": "..."}`.
  Azure maps names with its `flat`/`json` strategy. Vault passes KV v2 through.
- Backends translate provider "not found" into `ErrSecretNotFound` (→ HTTP 404)
  and connectivity failures into `ErrBackendUnavailable` (→ HTTP 502).
- Backends are constructed once at startup from config and are safe for
  concurrent use. Authentication uses workload identity federation only.

## Cache architecture

- **Scope:** one cache per backend instance, in process memory.
- **Key:** the secret path only (e.g. `opus/workflow-engine`). RBAC is enforced
  before any cache access, so a path-only key cannot leak across identities.
- **Entries:** positive (the resolved key/value map) and negative (a tombstone
  for not-found paths) entries.
- **TTLs:** `cache.ttl` for positive entries, `cache.negativeTTL` for negatives.
  `cache.maxEntries` bounds memory; eviction is by age/capacity.
- **Effect:** absorbs repeated reads from many pods of the same secret, cutting
  backend API calls (and cost / rate-limit pressure). Tunable per backend.

Trade-off: a rotated secret remains served until its cached entry expires.
Lower `ttl` for fresher reads; raise it to reduce backend load. See
[troubleshooting → stale cache](./troubleshooting.md#stale-cache-data).

## Token lifecycle

```
   issue ──► verify (per request) ──► expire (TTL) ──► cleanup (sweep)
     │             │                       │                 │
 crypto/rand   constant-time          no renewal       tokenCleanupInterval
 stored in     compare; bound       (Renewable=false)  removes expired
 memory map    identity + path          on read         entries
```

- **Issue.** On successful login, a random token is generated with `crypto/rand`
  and stored in memory with its bound identity and absolute expiry. The number
  of live tokens per identity is capped by `auth.maxTokensPerIdentity`.
- **Verify.** Each secret read looks the token up and compares it in constant
  time (`crypto/subtle`). An expired token is treated as invalid → 403.
- **Expiry.** Tokens are **non-renewable** (`Renewable: false`). When the TTL
  elapses they become invalid. `vault-env` performs its reads at pod startup,
  well within a single TTL, so renewal is unnecessary.
- **Cleanup.** A background sweeper runs every `auth.tokenCleanupInterval` and
  removes expired entries so the map does not grow unbounded.

### Implications for high availability

Tokens live **in memory, per instance** — they are not replicated or persisted.
Consequences:

- The gateway is otherwise stateless and **horizontally scalable**; run several
  replicas behind a Service.
- A login and the subsequent secret reads must hit the **same replica**, because
  only that replica holds the issued token. Use a Service/`vault-env` setup
  that keeps a client's requests on one backend pod for the short login→read
  window (e.g. session affinity), or rely on the fact that `vault-env` opens a
  single short-lived connection at startup.
- If a replica restarts, its tokens are gone. Any in-flight client simply logs
  in again. There is no shared session state to lose or to compromise.

This is a deliberate trade: no external session store, no persistence of
credentials, at the cost of replica-local tokens — acceptable because the auth
window is seconds long and re-login is cheap.

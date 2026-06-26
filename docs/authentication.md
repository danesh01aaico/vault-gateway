# Authentication

Vault Gateway authenticates workloads exactly the way HashiCorp Vault's
Kubernetes auth method does, so Bank-Vaults' `vault-env` needs no changes. This
page walks through the flow end to end.

Related: [architecture](./architecture.md) · [configuration](./configuration.md) · [security model](./security-model.md).

## Overview

```
 Pod (app + vault-env)        Vault Gateway              Kubernetes API
        │                          │                          │
        │ 1. POST login {role,jwt} │                          │
        ├─────────────────────────►│ 2. TokenReview(jwt)      │
        │                          ├─────────────────────────►│
        │                          │ 3. authenticated identity│
        │                          │◄─────────────────────────┤
        │ 4. client_token + TTL    │ (role binding check)     │
        │◄─────────────────────────┤                          │
        │ 5. GET secret/data/...   │                          │
        │    X-Vault-Token: token  │                          │
        ├─────────────────────────►│ (RBAC + backend read)    │
        │ 6. KV v2 response        │                          │
        │◄─────────────────────────┤                          │
```

## Step 1 — the projected ServiceAccount token

Every pod gets a projected ServiceAccount (SA) token mounted by the kubelet. For
Vault Gateway, this token should be **audience-bound** so it can only be used
against the gateway, not the Kubernetes API or other services.

Bank-Vaults projects such a token into the pod automatically when configured
with an audience. The projected volume looks like:

```yaml
volumes:
  - name: vault-gateway-token
    projected:
      sources:
        - serviceAccountToken:
            path: vault-gateway-token
            audience: vault-gateway      # bound audience
            expirationSeconds: 600
```

The `audience` is the critical control: Kubernetes signs the JWT with this
audience, and the TokenReview in step 3 validates it. A token minted for a
different audience is rejected.

## Step 2 — login request

`vault-env` sends:

```
POST /v1/auth/kubernetes/login
Content-Type: application/json

{
  "role": "workflow-engine",
  "jwt":  "<projected SA token>"
}
```

- `role` selects an entry under `auth.roles` in the gateway config.
- `jwt` is the projected SA token from step 1.

## Step 3 — TokenReview validation

The gateway submits the JWT to the Kubernetes **TokenReview API**. This requires
the gateway's ServiceAccount to hold the only cluster permission it needs:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vault-gateway-tokenreview
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
```

If you bind audiences, the TokenReview is created with the expected audience so
Kubernetes verifies it. On success Kubernetes returns:

- `authenticated: true`
- the username `system:serviceaccount:<namespace>:<serviceaccount>`
- the token's audiences and expiry

The gateway extracts `<namespace>` and `<serviceaccount>` from the username.

## Step 4 — role binding check and token issuance

The named role is looked up in config:

```yaml
auth:
  tokenTTL: 15m
  maxTokensPerIdentity: 32
  roles:
    workflow-engine:
      allowedNamespaces:      ["opus"]
      allowedServiceAccounts: ["workflow-engine"]
      allowedPaths:           ["opus/workflow-engine/*"]
      tokenTTL:               10m
```

The gateway verifies:

1. The authenticated **namespace** is in `allowedNamespaces`.
2. The authenticated **ServiceAccount** is in `allowedServiceAccounts`.

### Wildcard matching

Both `allowedNamespaces` and `allowedServiceAccounts` support `*` as a wildcard
entry meaning "any". For example `allowedNamespaces: ["*"]` accepts any
namespace (use sparingly). Explicit names are matched exactly.

On success the gateway:

- generates a `client_token` with `crypto/rand`,
- stores it in memory bound to this identity and to the role's `allowedPaths`,
- sets an expiry of `role.tokenTTL` (falling back to `auth.tokenTTL`),
- returns a Vault-compatible auth response.

### Login response

```json
{
  "request_id": "…",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "auth": {
    "client_token": "…",
    "accessor": "…",
    "policies": ["workflow-engine"],
    "token_policies": ["workflow-engine"],
    "metadata": {
      "role": "workflow-engine",
      "service_account_name": "workflow-engine",
      "service_account_namespace": "opus"
    },
    "lease_duration": 600,
    "renewable": false,
    "token_type": "service",
    "orphan": true
  }
}
```

`lease_duration` is the token TTL in seconds. `renewable` is always `false` —
tokens are **non-renewable** by design (see
[token lifecycle](./architecture.md#token-lifecycle)).

## Step 5 — using the token

`vault-env` reads each referenced secret with the issued token:

```
GET /v1/secret/data/opus/workflow-engine/db
X-Vault-Token: <client_token>
```

The gateway verifies the token (constant-time compare, expiry check), enforces
that the requested path matches the role's `allowedPaths` glob, then reads from
the backend and returns a KV v2 response. RBAC path matching uses:

- `*` — matches exactly one path segment.
- `**` — matches any number of segments (recursive).

For example `allowedPaths: ["opus/workflow-engine/*"]` permits
`opus/workflow-engine/db` but not `opus/workflow-engine/db/replica`; use
`opus/workflow-engine/**` for the recursive form.

## Token TTL and renewal

- The TTL comes from `role.tokenTTL`, or `auth.tokenTTL` if the role does not
  set one.
- Tokens are **not renewable**. `vault-env` fetches all of a pod's secrets at
  startup within a single TTL window, so renewal is unnecessary.
- Expired tokens are rejected as `permission denied` (403). The pod's
  `vault-env` would simply log in again on a restart.
- Keep TTLs short (minutes). They only need to outlive the brief startup read
  burst.

## How `vault-env` uses all of this

When the Bank-Vaults webhook mutates a pod, it rewrites the container command so
`vault-env` runs first. At startup `vault-env`:

1. Reads the `vault:` references in the container's environment variables
   (e.g. `DB_PASSWORD=vault:secret/data/opus/workflow-engine/db#password`).
2. Logs in to the gateway at `VAULT_ADDR` (set to
   `https://vault-gateway.<namespace>:8200`) using the projected SA token and
   configured role — step 2 above.
3. Fetches each referenced secret with the returned `client_token` — step 5.
4. Replaces the `vault:` references with the resolved values **in the process
   environment only**, then `exec`s the real application.

No Kubernetes `Secret` is ever created; the plaintext exists only in the
launched process's memory. See the [security model](./security-model.md) for the
boundaries of that guarantee.

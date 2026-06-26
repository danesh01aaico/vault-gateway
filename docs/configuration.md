# Configuration reference

Vault Gateway is configured with a single YAML file, with optional environment
variable overrides. This page documents every field, its type, default, and
meaning.

Related: [architecture](./architecture.md) · [authentication](./authentication.md) · [deployment guides](./deployment-aws.md).

## Loading configuration

The config file is located, in order:

1. The `--config <path>` command-line flag.
2. The `VAULT_GATEWAY_CONFIG` environment variable.

```bash
vault-gateway --config /etc/vault-gateway/config.yaml
# or
VAULT_GATEWAY_CONFIG=/etc/vault-gateway/config.yaml vault-gateway
```

### Environment variable overrides

Any field can be overridden with an environment variable using the `VG_` prefix
and underscores for nesting. **Environment variables take precedence over the
file.**

| Field | Environment variable |
| ----- | -------------------- |
| `backend` | `VG_BACKEND` |
| `server.port` | `VG_SERVER_PORT` |
| `server.host` | `VG_SERVER_HOST` |
| `aws.region` | `VG_AWS_REGION` |
| `logging.level` | `VG_LOGGING_LEVEL` |

Precedence (highest to lowest): **`VG_` environment variable → config file →
built-in default**.

## Top-level fields

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `backend` | string | _(required)_ | Active backend: `aws`, `azure`, `vault`, or `gcp`. |
| `server` | object | see below | HTTP server and TLS settings. |
| `aws` / `azure` / `vault` / `gcp` | object | — | Backend-specific settings; only the selected one is required. |
| `auth` | object | see below | Token issuance and RBAC roles. |
| `logging` | object | see below | Log level and format. |
| `metrics` | object | see below | Prometheus metrics endpoint. |
| `healthCheck` | object | see below | Backend health probing. |

## `server`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `host` | string | `0.0.0.0` | Bind address. |
| `port` | int | `8200` | Listen port for the Vault-compatible API. |
| `tls.enabled` | bool | `true` | Enable TLS. Production deployments must keep this on. |
| `tls.certFile` | string | — | Path to the PEM server certificate. |
| `tls.keyFile` | string | — | Path to the PEM private key. |
| `tls.minVersion` | string | `"1.2"` | Minimum TLS version (`"1.2"` or `"1.3"`). |
| `tls.cipherSuites` | []string | _(secure default set)_ | Allowed cipher suites for TLS 1.2. |
| `readTimeout` | duration | `10s` | Max time to read a request. |
| `writeTimeout` | duration | `10s` | Max time to write a response. |
| `idleTimeout` | duration | `60s` | Keep-alive idle timeout. |
| `maxRequestBodySize` | bytes | `1MiB` | Reject larger request bodies. |
| `shutdownGracePeriod` | duration | `15s` | Drain time on SIGTERM before force-close. |

```yaml
server:
  host: 0.0.0.0
  port: 8200
  tls:
    enabled: true
    certFile: /etc/vault-gateway/tls/tls.crt
    keyFile: /etc/vault-gateway/tls/tls.key
    minVersion: "1.2"
    cipherSuites:
      - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  readTimeout: 10s
  writeTimeout: 10s
  idleTimeout: 60s
  maxRequestBodySize: 1048576
  shutdownGracePeriod: 15s
```

## Backend selection

Set `backend` to one of `aws`, `azure`, `vault`, `gcp`. Only the matching block
below is required. Every backend block has a `cache` sub-object (see
[Cache settings](#cache-settings)).

### `aws` — AWS Secrets Manager

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `region` | string | _(required)_ | AWS region (e.g. `us-east-1`). |
| `secretPrefix` | string | `""` | Prefix prepended to every path before lookup. |
| `endpointURL` | string | `""` | Override endpoint (for VPC endpoints / testing). |
| `maxRetries` | int | `3` | SDK retry attempts. |
| `cache` | object | see below | TTL cache. |

Authentication uses **IRSA** (IAM Roles for Service Accounts) — no static keys.
Secrets are expected to be JSON objects; a plain string is returned as
`{"value": "..."}`. The `/` character is allowed, so path `opus/workflow-engine`
maps to secret `opus/workflow-engine` (after `secretPrefix`).

```yaml
backend: aws
aws:
  region: us-east-1
  secretPrefix: opus/
  endpointURL: ""
  maxRetries: 3
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s
    maxEntries: 1024
```

### `azure` — Azure Key Vault

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `vaultURL` | string | _(required)_ | Key Vault URL, e.g. `https://kv-opus.vault.azure.net/`. |
| `namingStrategy` | string | `flat` | `flat` or `json` (see below). |
| `cache` | object | see below | TTL cache. |

Authentication uses **Azure Workload Identity**. Key Vault secret names allow
only alphanumerics and hyphens, with no nesting:

- `flat` — one Key Vault secret per key. Path `opus/workflow-engine` + key
  `db_password` → secret `opus-workflow-engine--db-password`.
- `json` — one Key Vault secret per path; the value is a JSON object holding all
  keys.

```yaml
backend: azure
azure:
  vaultURL: https://kv-opus.vault.azure.net/
  namingStrategy: flat
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s
    maxEntries: 1024
```

### `vault` — HashiCorp Vault

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `address` | string | _(required)_ | Vault API address, e.g. `https://vault.vault:8200`. |
| `authPath` | string | `kubernetes` | Mount path of the Kubernetes auth method. |
| `role` | string | _(required)_ | Vault role to authenticate as. |
| `tlsSkipVerify` | bool | `false` | Skip TLS verification (dev only). |
| `caCert` | string | `""` | Path to a CA bundle for Vault's TLS cert. |
| `cache` | object | see below | TTL cache. |

The gateway authenticates to Vault using Kubernetes auth and passes KV v2 reads
through. Used for in-cluster / airgapped deployments — see
[deployment-airgapped](./deployment-airgapped.md).

```yaml
backend: vault
vault:
  address: https://vault.vault:8200
  authPath: kubernetes
  role: vault-gateway
  tlsSkipVerify: false
  caCert: /etc/vault-gateway/vault-ca/ca.crt
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s
    maxEntries: 1024
```

### `gcp` — GCP Secret Manager

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `projectID` | string | _(required)_ | GCP project ID. |
| `secretPrefix` | string | `""` | Prefix prepended to every path before lookup. |
| `cache` | object | see below | TTL cache. |

Authentication uses **GKE Workload Identity**. Secret names must match
`[a-zA-Z0-9_-]+` (max 255), so `opus/workflow-engine` → `opus-workflow-engine`.
Secrets are expected to be JSON; a plain string is returned as `{"value":"..."}`.

```yaml
backend: gcp
gcp:
  projectID: opus-prod
  secretPrefix: opus-
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s
    maxEntries: 1024
```

## Cache settings

Each backend block contains a `cache` object.

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `enabled` | bool | `true` | Enable the in-memory cache. |
| `ttl` | duration | `60s` | TTL for positive (found) entries. |
| `negativeTTL` | duration | `10s` | TTL for negative (not-found) entries. |
| `maxEntries` | int | `1024` | Maximum cached entries; bounds memory. |

The cache is keyed by path only; RBAC is always checked before a cache lookup,
so this is safe. See the [cache security analysis](./security-model.md#cache-security).

## `auth`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `tokenTTL` | duration | `15m` | Default client-token lifetime. |
| `tokenCleanupInterval` | duration | `1m` | How often expired tokens are swept from memory. |
| `maxTokensPerIdentity` | int | `32` | Cap on concurrent live tokens per identity. |
| `roles` | map | _(required)_ | Named roles; see below. |

### `auth.roles.<name>`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `allowedNamespaces` | []string | _(required)_ | Namespaces allowed to assume this role (`*` = any). |
| `allowedServiceAccounts` | []string | _(required)_ | ServiceAccounts allowed (`*` = any). |
| `allowedPaths` | []string | _(required)_ | Glob patterns of readable paths (`*` = one segment, `**` = recursive). |
| `tokenTTL` | duration | _(inherits `auth.tokenTTL`)_ | Per-role token lifetime override. |

```yaml
auth:
  tokenTTL: 15m
  tokenCleanupInterval: 1m
  maxTokensPerIdentity: 32
  roles:
    workflow-engine:
      allowedNamespaces:      ["opus"]
      allowedServiceAccounts: ["workflow-engine"]
      allowedPaths:           ["opus/workflow-engine/**"]
      tokenTTL:               10m
```

## `logging`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `level` | string | `info` | `debug`, `info`, `warn`, or `error`. |
| `format` | string | `json` | `json` (structured `slog`) or `text`. |

Secret values are never logged at any level.

## `metrics`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `enabled` | bool | `true` | Expose Prometheus metrics. |
| `port` | int | `9090` | Metrics listen port. |
| `path` | string | `/metrics` | Metrics HTTP path. |

## `healthCheck`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `backendCheck` | bool | `true` | Include backend connectivity in `/v1/sys/health`. |
| `backendCheckTimeout` | duration | `3s` | Per-probe timeout. |
| `backendCheckInterval` | duration | `30s` | How often the backend is probed in the background. |

## Full example

```yaml
server:
  host: 0.0.0.0
  port: 8200
  tls:
    enabled: true
    certFile: /etc/vault-gateway/tls/tls.crt
    keyFile: /etc/vault-gateway/tls/tls.key
    minVersion: "1.2"
  readTimeout: 10s
  writeTimeout: 10s
  idleTimeout: 60s
  maxRequestBodySize: 1048576
  shutdownGracePeriod: 15s

backend: aws

aws:
  region: us-east-1
  secretPrefix: opus/
  maxRetries: 3
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
      allowedNamespaces:      ["opus"]
      allowedServiceAccounts: ["workflow-engine"]
      allowedPaths:           ["opus/workflow-engine/**"]
      tokenTTL:               10m

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

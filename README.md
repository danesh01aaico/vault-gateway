# Vault Gateway

A production-grade, cloud-agnostic secret injection platform for Kubernetes. Exposes a [HashiCorp Vault-compatible API](https://developer.hashicorp.com/vault/api-docs) that routes secret reads to pluggable cloud-native backends — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or real HashiCorp Vault.

Works with [Bank-Vaults `vault-env`](https://github.com/bank-vaults/vault-env) to inject secrets into pod environment variables **at runtime**, without creating Kubernetes Secret objects.

---

## Why

Kubernetes Secrets are base64-encoded, stored in etcd, and visible to anyone with `kubectl get secret`. Most teams work around this with external secret operators — but those still create a Secret object as the final step.

Vault Gateway takes a different approach: secrets are **never written to Kubernetes at all**. They live in your cloud secret store and are injected directly into the process environment at pod startup, before your application process begins.

```
Your manifest:       DB_PASSWORD=vault:secret/data/myapp/db#password
App env at runtime:  DB_PASSWORD=s3cr3t
Kubernetes Secrets:  (none)
```

---

## Architecture

```
┌─────────────────────────── Kubernetes Cluster ────────────────────────────┐
│                                                                            │
│  ┌─── vault-system ────────────────────────────────────────────────────┐  │
│  │  vault-gateway  (Deployment, 2 replicas, TLS 1.2+)                  │  │
│  │  port 8200 -- Vault-compatible HTTPS API                            │  │
│  │  port 9090 -- Prometheus metrics + /healthz + /readyz               │  │
│  └──────────────────────────────┬──────────────────────────────────────┘  │
│                                 │ IRSA / Workload Identity                 │
│  ┌─── default (app namespace) ──│──────────────────────────────────────┐  │
│  │  Pod (mutated by Bank-Vaults webhook on admission)                   │  │
│  │  ┌──────────────────────────────────────────────────────────────┐   │  │
│  │  │ initContainer: vault-inject                                  │   │  │
│  │  │   1. reads pod ServiceAccount JWT                            │   │  │
│  │  │   2. POST /v1/auth/kubernetes/login  -> vault-gateway        │   │  │
│  │  │   3. GET  /v1/secret/data/myapp/db   -> vault-gateway        │   │  │
│  │  │   4. exec() -> your-app  (DB_PASSWORD=s3cr3t in env)         │   │  │
│  │  ├──────────────────────────────────────────────────────────────┤   │  │
│  │  │ container: your-app                                          │   │  │
│  │  │   sees DB_PASSWORD=s3cr3t in memory                         │   │  │
│  │  │   no Kubernetes Secret ever created                          │   │  │
│  │  └──────────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬───────────────────────────────────────┘
                                     │ TLS -- temporary STS creds (IRSA)
                              ┌──────┴───────┐
                              │  AWS SM /    │
                              │  Azure KV /  │
                              │  GCP SM /    │
                              │  HashiCorp   │
                              │  Vault       │
                              └──────────────┘
```

### Components

| Component | What it does |
|---|---|
| **vault-gateway** | Deployment in `vault-system`. Validates pod JWTs via Kubernetes TokenReview API, fetches secrets from the configured backend, returns Vault KV v2 responses. |
| **vault-inject** | Init container binary (shipped in the same image). Resolves `vault:` env var references and `exec()`s into the app. Zero dependencies on the Vault SDK. |
| **Bank-Vaults webhook** | MutatingWebhookConfiguration that intercepts pod admission and injects the vault-inject init container automatically. Developers annotate their namespace — nothing else changes. |

### Secret journey (production)

```
1. Developer writes:
     env:
       - name: DB_PASSWORD
         value: "vault:secret/data/myapp/db#password"

2. Pod admitted -> Bank-Vaults webhook injects vault-inject init container

3. vault-inject starts:
     a. reads /var/run/secrets/kubernetes.io/serviceaccount/token
     b. POST /v1/auth/kubernetes/login   (role=payments-role, jwt=<sa-jwt>)
     c. vault-gateway calls kube-apiserver TokenReview -> validates JWT
     d. vault-gateway checks RBAC: payments namespace + payments-app SA + myapp/** path
     e. vault-gateway returns short-lived token (5 min TTL)
     f. GET /v1/secret/data/myapp/db     (X-Vault-Token: <token>)
     g. vault-gateway calls AWS SM with IRSA temporary credentials
     h. returns {"username":"admin","password":"s3cr3t"}

4. vault-inject resolves DB_PASSWORD=s3cr3t, strips all VAULT_* vars from env
5. vault-inject exec()s into your-app -- PID replaced, secrets in memory only
6. Kubernetes Secret: never created
```

---

## Security Posture

### Applied in this repo

| Control | Detail |
|---|---|
| **TLS 1.2+ on all API traffic** | Self-signed cert for k3d; cert-manager in production |
| **Zero Kubernetes Secrets** | No `kind: Secret` ever created for app credentials |
| **Short-lived tokens** | 5-minute TTL on gateway tokens; only needed at pod startup |
| **In-memory token store** | `crypto/rand`, `crypto/subtle.ConstantTimeCompare`; never written to disk |
| **Hardened path validator** | Allowlist-only (`a-z A-Z 0-9 - _ . / :`); rejects traversal, null bytes, shell metacharacters |
| **Per-IP rate limiting** | 50 rps / burst 100; token bucket via `golang.org/x/time/rate` |
| **Container security context** | `runAsNonRoot=true`, `readOnlyRootFilesystem=true`, `allowPrivilegeEscalation=false`, `capabilities: drop: [ALL]`, `seccompProfile: RuntimeDefault` |
| **Resource limits** | `cpu: 50m-500m`, `memory: 64Mi-256Mi` |
| **Pod anti-affinity** | Replicas spread across nodes; no single-node dependency |
| **PodDisruptionBudget** | `minAvailable: 1`; safe during node drains and rolling upgrades |
| **PriorityClass** | Gateway scheduled before app pods that depend on it |
| **NetworkPolicy** | Only pods labelled `vault.io/inject=true` reach port 8200 |
| **Pod Security Standards** | `restricted` enforced on `vault-system` namespace |
| **Distroless image** | `gcr.io/distroless/static-debian12:nonroot`, UID 65534; no shell, no package manager |
| **Structured audit log** | Every login and secret read logged with namespace, SA, role, path, result — never logs values |
| **Response headers** | `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `HSTS` (when TLS enabled) |
| **Secret cache** | 30s TTL; AWS SM not hit on every pod startup under load |
| **Retry with backoff** | vault-inject retries 3x on transient errors (500ms -> 1s -> 2s); does not retry on HTTP 4xx |
| **gosec + govulncheck** | CI enforces zero high-severity findings |

### Requires a real cluster (not in k3d)

| Control | What to do |
|---|---|
| **IRSA (AWS)** | Annotate the `vault-gateway` ServiceAccount with the IAM role ARN. Remove `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars from the Deployment. |
| **Azure Workload Identity** | Assign a managed identity to the ServiceAccount via `azure.workload.identity/client-id` annotation. |
| **GKE Workload Identity** | Bind the Kubernetes SA to a Google SA via IAM binding. |
| **cert-manager TLS** | Replace the self-signed cert with a `Certificate` resource. |

---

## Backends

| Backend | Config key | Auth mechanism |
|---|---|---|
| AWS Secrets Manager | `backend: aws` | IRSA / env creds / instance profile |
| Azure Key Vault | `backend: azure` | Workload Identity / managed identity |
| GCP Secret Manager | `backend: gcp` | Workload Identity / ADC |
| HashiCorp Vault | `backend: vault` | Token or Kubernetes auth |

Switch backends by changing one line in the config — no app changes, no manifest changes.

---

## Env var syntax

```bash
# Fetch a specific key from a JSON secret
DB_PASSWORD=vault:secret/data/myapp/db#password
DB_USER=vault:secret/data/myapp/db#username

# Inject every key from a path as separate env vars
VAULT_ENV_FROM_PATH=secret/data/myapp/config

# Non-vault vars pass through unchanged
APP_PORT=8080
```

Vault config vars (`VAULT_ADDR`, `VAULT_ROLE`, `VAULT_CACERT`, etc.) are automatically stripped from the child process — your app never sees them.

---

## Prerequisites

- Go 1.25+
- Docker
- [k3d](https://k3d.io) v5+
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm](https://helm.sh) v3+
- [LocalStack](https://localstack.cloud) (for local AWS SM simulation)
- AWS CLI (for seeding LocalStack secrets)

---

## Local development (binary-only, no cluster)

Tests the complete flow using local binaries and LocalStack. Nothing is deployed to any cluster.

```bash
# 1. Start LocalStack
docker run -d --name localstack -p 4566:4566 \
  -e SERVICES=secretsmanager localstack/localstack:4.0.3

# 2. Seed a secret
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
aws --endpoint-url=http://localhost:4566 --region us-east-1 \
  secretsmanager create-secret \
  --name myapp/db-password \
  --secret-string '{"username":"admin","password":"s3cr3t"}'

# 3. Start k3d (needed only for JWT validation via TokenReview)
k3d cluster create dev-cluster --agents 2

# 4. Run the full local test
make local-test
```

`make local-test` builds both binaries, creates a k3d ServiceAccount for its JWT, starts vault-gateway locally, runs vault-inject, and asserts the resolved values. No pods are deployed.

---

## K3d deployment (full cluster test)

Deploys vault-gateway as a real Kubernetes workload with all production security controls applied.

```bash
# Prerequisites: k3d dev-cluster running, LocalStack running on port 4566
make deploy-k3d
```

This single command:
1. Generates a self-signed TLS certificate (reuses existing on re-runs)
2. Builds the Docker image and imports it into k3d
3. Enforces Pod Security Standards `restricted` on `vault-system`
4. Applies RBAC, ConfigMap, Deployment, Service, NetworkPolicy, PDB, PriorityClass
5. Waits for the 2-replica rollout to complete
6. Deploys a test pod that resolves `vault:` env vars at runtime
7. Asserts `DB_PASSWORD=s3cr3t`, `DB_USER=admin`, zero Kubernetes Secrets

### Verify for yourself

```bash
export KUBECONFIG=/path/to/k3d-kubeconfig.yaml

# Pod completed successfully
kubectl get pod secret-test -n default

# Resolved secrets in app env (never in the manifest)
kubectl logs secret-test -n default -c test-app | grep -E '^DB_'

# VAULT_* config vars stripped -- app never sees auth material
kubectl logs secret-test -n default -c test-app | grep VAULT || echo "PASS"

# Zero Kubernetes Secrets created
kubectl get secrets -n default

# Pod manifest -- only a reference, not a value
kubectl get pod secret-test -n default \
  -o jsonpath='{.spec.containers[0].env}' | python3 -m json.tool

# Audit trail -- every login and read logged
kubectl logs -l app=vault-gateway -n vault-system | grep '"action"'
```

---

## Production deployment (Helm)

### Install

```bash
helm install vault-gateway-stack deploy/helm/vault-gateway-stack \
  --namespace vault-system \
  --create-namespace \
  -f my-values.yaml
```

### values.yaml -- AWS example

```yaml
backend: aws

aws:
  region: us-east-1
  # No endpointURL = real AWS SM
  # No credentials = IRSA handles it via ServiceAccount annotation

roles:
  - name: payments-role
    namespaces: ["payments"]
    serviceAccounts: ["payments-app"]
    paths: ["payments/**"]

  - name: infra-role
    namespaces: ["infra"]
    serviceAccounts: ["*"]
    paths: ["shared/**", "infra/**"]

tls:
  secretName: vault-gateway-tls   # cert-manager Certificate
```

### IRSA -- remove static creds entirely

Annotate the `vault-gateway` ServiceAccount:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/vault-gateway-role
```

The IAM role needs only:

```json
{
  "Effect": "Allow",
  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"
}
```

Trust policy:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub":
        "system:serviceaccount:vault-system:vault-gateway"
    }
  }
}
```

### App manifest -- no changes required

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
spec:
  template:
    metadata:
      annotations:
        vault.security.banzaicloud.io/vault-addr: "https://vault-gateway.vault-system.svc.cluster.local:8200"
        vault.security.banzaicloud.io/vault-role: "payments-role"
        vault.security.banzaicloud.io/vault-skip-verify: "false"
    spec:
      containers:
        - name: payments-api
          image: my-org/payments-api:latest
          env:
            - name: DB_PASSWORD
              value: "vault:secret/data/payments/db#password"
            - name: STRIPE_KEY
              value: "vault:secret/data/payments/stripe#api_key"
            - name: APP_PORT
              value: "8080"
```

The Bank-Vaults webhook injects the vault-inject init container automatically based on the annotations. `DB_PASSWORD` and `STRIPE_KEY` are replaced at runtime before the application process starts.

---

## Configuration reference

```yaml
backend: aws          # aws | azure | gcp | vault

server:
  port: 8200
  tls:
    enabled: true
    certFile: /etc/vault-gateway/tls/tls.crt
    keyFile:  /etc/vault-gateway/tls/tls.key
    minVersion: "1.2"  # or "1.3"

aws:
  region: us-east-1
  secretPrefix: ""          # prepended to every secret path
  endpointURL: ""           # override for LocalStack: http://localhost:4566
  cache:
    enabled: true
    ttl: 30s
    negativeTTL: 10s
    maxEntries: 1000

azure:
  vaultURL: "https://my-vault.vault.azure.net"
  namingStrategy: flat      # flat | json

gcp:
  projectID: my-gcp-project

vault:
  address: "https://vault.example.com:8200"
  role: my-role

auth:
  tokenTTL: 5m
  roles:
    my-role:
      allowedNamespaces: ["payments", "infra"]
      allowedServiceAccounts: ["payments-app", "infra-*"]
      allowedPaths: ["payments/**", "shared/**"]

rateLimit:
  enabled: true
  requestsPerSecond: 50
  burst: 100

metrics:
  enabled: true
  port: 9090
  path: /metrics
```

### vault-inject env vars

| Var | Default | Description |
|---|---|---|
| `VAULT_ADDR` | `https://vault-gateway.vault-system.svc.cluster.local:8200` | Gateway URL |
| `VAULT_ROLE` | `default-role` | Role name -- must exist in gateway config |
| `VAULT_CACERT` | -- | Path to CA cert for TLS verification |
| `VAULT_SKIP_VERIFY` | `false` | Skip TLS verification (dev only) |
| `VAULT_JWT_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | ServiceAccount JWT path |
| `VAULT_ENV_FROM_PATH` | -- | Comma-separated paths -- inject all keys as env vars |
| `VAULT_IGNORE_MISSING_SECRETS` | `false` | Continue if a secret is not found |
| `VAULT_LOG_LEVEL` | `info` | `debug` or `info` |
| `VAULT_LOGIN_TIMEOUT` | `30s` | Timeout for the login request |
| `VAULT_READ_TIMEOUT` | `15s` | Timeout per secret read |

All `VAULT_*` vars are stripped from the child process — the app never sees them.

---

## Observability

### Metrics (port 9090)

| Metric | Type | Description |
|---|---|---|
| `vault_gateway_auth_requests_total` | Counter | Login attempts by status and role |
| `vault_gateway_secret_requests_total` | Counter | Secret reads by status and backend |
| `vault_gateway_secret_duration_seconds` | Histogram | Secret read latency |
| `vault_gateway_active_tokens` | Gauge | Current in-memory token count |
| `vault_gateway_cache_hits_total` | Counter | Cache hits by backend |
| `vault_gateway_cache_misses_total` | Counter | Cache misses by backend |
| `vault_gateway_rate_limit_exceeded_total` | Counter | Rate-limited requests |

### Health endpoints

```
GET /healthz   -> 200 OK   (process is alive)
GET /readyz    -> 200 OK   (backend reachable)
               -> 503       (backend unavailable)
```

### Audit log

Every login and secret read emits a structured JSON log line:

```json
{
  "time": "2026-06-28T13:43:37Z",
  "level": "INFO",
  "msg": "audit",
  "action": "read",
  "request_id": "b2cbb25d-ab64-4ca0-81ba-d033975ad8cb",
  "src_ip": "10.42.2.15",
  "namespace": "payments",
  "service_account": "payments-app",
  "role": "payments-role",
  "path": "payments/db",
  "result": "success"
}
```

Secret values are **never** logged.

---

## Repository layout

```
.
├── cmd/
│   ├── vault-gateway/      # Gateway server binary
│   └── vault-inject/       # vault-env replacement binary
├── internal/
│   ├── api/                # HTTP handlers (login, secret read, health)
│   ├── auth/               # JWT validation, RBAC, token store
│   ├── backend/
│   │   ├── aws/            # AWS Secrets Manager
│   │   ├── azure/          # Azure Key Vault
│   │   ├── gcp/            # GCP Secret Manager
│   │   └── vault/          # HashiCorp Vault passthrough
│   ├── cache/              # In-memory TTL cache
│   ├── config/             # Config loading, defaults, validation
│   ├── metrics/            # Prometheus metrics definitions
│   ├── secretpath/         # Hardened allowlist path validator
│   ├── server/             # HTTP server, middleware, router
│   └── version/            # Build version info
├── pkg/vaultresponse/      # Vault KV v2 wire types
├── deploy/helm/
│   ├── vault-gateway/           # Single-component chart
│   └── vault-gateway-stack/     # Umbrella chart (gateway + Bank-Vaults webhook)
├── dev/
│   ├── config/
│   │   ├── gateway-local.yaml   # Config for binary-only local test
│   │   └── gateway-k3d.yaml     # Config for k3d deployment
│   ├── k8s/
│   │   ├── 01-gateway-rbac.yaml
│   │   ├── 02-gateway-config.yaml
│   │   ├── 03-gateway-deploy.yaml
│   │   ├── 04-test-pod.yaml
│   │   ├── 05-networkpolicy.yaml
│   │   ├── 06-pdb.yaml
│   │   └── 07-priorityclass.yaml
│   ├── local-test.sh            # Binary-only end-to-end test
│   └── deploy-k3d.sh            # Full k3d deployment and test
└── e2e/                         # Integration tests (AWS, Azure, GCP, Vault)
```

---

## Development

```bash
# Build both binaries
make build

# Run tests with race detector and coverage
make test

# Lint
make lint

# Build Docker image
make docker

# Full local test (binary-only, no cluster pods)
make local-test

# Full k3d deployment and test
make deploy-k3d
```

### Single image, two binaries

The Docker image ships both binaries:

```
/vault-gateway   -- gateway server (ENTRYPOINT)
/vault-env       -- vault-inject init container binary
```

The Bank-Vaults webhook is configured to use this image as its vault-env source:

```yaml
VAULT_IMAGE: ghcr.io/vault-gateway/vault-gateway:latest
```

At pod admission, the webhook copies `/vault-env` from this image into a shared emptyDir volume and wraps the main container command.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

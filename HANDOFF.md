# Vault Gateway — Handoff

**Date:** 2026-06-29
**Repo:** https://github.com/danesh01aaico/vault-gateway
**Branch:** main (4 commits, CI green)

---

## What this is

A production-grade Go service that exposes a HashiCorp Vault-compatible HTTP API and routes secret reads to cloud-native backends — AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, or real HashiCorp Vault.

Works with Bank-Vaults `vault-env` to inject secrets into pod environment variables at runtime. **No Kubernetes Secret objects are ever created.** Secrets live only in pod process memory.

---

## Current state

| Area | Status |
|---|---|
| Go implementation | Done |
| All 4 backends (AWS/Azure/GCP/Vault) | Done |
| vault-inject binary (bank-vaults vault-env, in-house) | Done |
| Security hardening (TLS, securityContext, NetworkPolicy, PSS, PDB, rate limit, audit log) | Done |
| k3d end-to-end test | Passing |
| Local binary test | Passing |
| CI (lint/test/build/helm/docker) | Green |
| README | Done |
| Helm charts | Done |
| AWS dev deployment | **Pending approval** |

---

## What works right now

```bash
# Local binary test (no cluster pods)
make local-test

# Full k3d deployment + assertion
make deploy-k3d
```

Both assert:
- `DB_PASSWORD=s3cr3t` resolved from AWS SM (LocalStack)
- `DB_USER=admin` resolved from AWS SM (LocalStack)
- `VAULT_*` config vars stripped from app env
- Zero Kubernetes Secrets created

---

## Architecture

```
Pod admission
  → Bank-Vaults webhook injects vault-inject init container
  → vault-inject reads SA JWT
  → POST /v1/auth/kubernetes/login  → vault-gateway (validates JWT via TokenReview)
  → GET  /v1/secret/data/<path>     → vault-gateway (fetches from AWS SM / Azure KV / etc.)
  → vault-inject exec()s into app with secrets in env
  → App runs with DB_PASSWORD=s3cr3t in memory
  → Kubernetes Secret: never created
```

---

## Security posture

| Control | Detail |
|---|---|
| TLS 1.2+ | Self-signed in k3d; cert-manager in production |
| Zero K8s Secrets | Nothing in etcd |
| Token TTL | 5 minutes |
| In-memory token store | crypto/rand, never on disk |
| Path validator | Allowlist only — blocks traversal, null bytes, shell metacharacters |
| Rate limiting | 50 rps / burst 100 per IP |
| Container hardening | runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, seccompProfile |
| NetworkPolicy | Only vault.io/inject=true pods reach port 8200 |
| PSS restricted | Enforced on vault-system namespace |
| PDB | minAvailable: 1 |
| PriorityClass | Gateway before app pods |
| Audit log | Every login and read logged — never logs values |
| Retry | 3x exponential backoff in vault-inject; no retry on 4xx |
| Secret cache | 30s TTL — AWS SM not hit on every pod startup |
| CSP header | default-src 'none' |
| Distroless image | gcr.io/distroless/static-debian12:nonroot, UID 65534 |

**Not applied yet (requires real cluster):**
- IRSA — replace static AWS creds with IAM role annotation on SA
- cert-manager — replace self-signed cert with Certificate resource
- Azure Workload Identity / GKE Workload Identity

---

## Security boundary

Vault Gateway defends the **Kubernetes API and etcd layer**:
- Blocks `kubectl get secret` exposure
- Blocks etcd backup leaks
- Blocks GitOps repos accidentally committing Secret manifests
- Provides audit trail for every secret read

It does **not** defend against node/kernel-level compromise. That is true of every secrets solution (HashiCorp Vault, AWS SM, Azure KV). Cluster-level compromise is handled at the infrastructure layer — IAM, VPC, node hardening, GuardDuty.

---

## Next step: AWS dev deployment

Approval requested from team via Slack.

Once approved:

### 1. Push image to ECR
```bash
aws ecr create-repository --repository-name vault-gateway --region <region>
docker build -t <account>.dkr.ecr.<region>.amazonaws.com/vault-gateway:latest .
aws ecr get-login-password | docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com
docker push <account>.dkr.ecr.<region>.amazonaws.com/vault-gateway:latest
```

### 2. Create IAM role (IRSA)
```json
{
  "Effect": "Allow",
  "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"],
  "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:dev/*"
}
```
Trust policy: OIDC provider for the EKS cluster, subject `system:serviceaccount:vault-system:vault-gateway`.

### 3. Install cert-manager + TLS
```bash
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set installCRDs=true
# Then create Issuer + Certificate for vault-gateway.vault-system.svc.cluster.local
```

### 4. Install Bank-Vaults webhook
```bash
helm install vault-secrets-webhook oci://ghcr.io/bank-vaults/helm-charts/vault-secrets-webhook \
  --namespace vault-system \
  --set env.VAULT_IMAGE=<account>.dkr.ecr.<region>.amazonaws.com/vault-gateway:latest
```

### 5. Helm install vault-gateway
```yaml
# prod-values.yaml
backend: aws
aws:
  region: <region>
  # No endpointURL — real AWS SM
  # No credentials — IRSA via SA annotation
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/vault-gateway-role
tls:
  secretName: vault-gateway-tls
```
```bash
helm install vault-gateway deploy/helm/vault-gateway \
  --namespace vault-system --create-namespace \
  -f prod-values.yaml
```

### 6. Test
Deploy any pod with:
```yaml
env:
  - name: DB_PASSWORD
    value: "vault:secret/data/dev/myapp#password"
```
Assert: resolved at runtime, zero K8s Secrets, audit log entry visible in gateway logs.

---

## Repository layout

```
cmd/vault-gateway/       Gateway server binary
cmd/vault-inject/        Init container binary (bank-vaults vault-env, in-house)
internal/
  api/                   HTTP handlers
  auth/                  JWT validation, RBAC, token store
  backend/{aws,azure,gcp,vault}/
  cache/                 In-memory TTL cache
  config/                Config loading
  metrics/               Prometheus metrics
  secretpath/            Hardened path validator
  server/                HTTP server, middleware, router
deploy/helm/             Helm charts
dev/
  local-test.sh          Binary-only e2e test
  deploy-k3d.sh          Full k3d deployment + assertion
  k8s/                   K8s manifests (01-rbac through 07-priorityclass)
  config/                Gateway config for local and k3d
```

---

## Dev environment

| Thing | Value |
|---|---|
| Go binary | `/opt/homebrew/bin/go` |
| k3d kubeconfig | `/Users/daneshwar/.config/k3d/kubeconfig-dev-cluster.yaml` |
| LocalStack | `docker start localstack` (port 4566) |
| golangci-lint | Installed via `go install` — do NOT use pre-built binary (compiled with Go 1.24, incompatible with go 1.26) |

---

## Safety rule

`dev/deploy-k3d.sh` enforces `[[ "$CONTEXT" == k3d-* ]]` before touching any cluster. Do not remove this check. A prior session deployed to production EKS (`opus-workloads-delta-7bq25`) accidentally — that must not happen again.

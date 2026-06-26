# Deployment guide: AWS (Secrets Manager + IRSA)

This guide deploys Vault Gateway on Amazon EKS, backed by AWS Secrets Manager,
authenticating with **IRSA** (IAM Roles for Service Accounts) so no static
credentials are ever used.

Related: [configuration](./configuration.md) · [authentication](./authentication.md) · [troubleshooting](./troubleshooting.md).

## Prerequisites

- An EKS cluster (1.27+) with an **IAM OIDC provider** associated.
- `kubectl`, `helm` (3.x), `aws` CLI, and `eksctl` (optional but convenient).
- Permission to create IAM roles/policies and Secrets Manager secrets.
- Bank-Vaults `vault-secrets-webhook` installed (we configure it at the end).
- A namespace for the gateway, e.g. `vault-gateway`, and one for the app, e.g.
  `opus`.

```bash
export CLUSTER=opus-eks
export REGION=us-east-1
export GW_NS=vault-gateway
export APP_NS=opus
kubectl create namespace "$GW_NS"
kubectl create namespace "$APP_NS"
```

## 1. Create secrets in AWS Secrets Manager

Secrets are expected to be **JSON objects**. A plain string is returned as
`{"value": "..."}`, but JSON lets a single path carry multiple keys.

```bash
aws secretsmanager create-secret \
  --region "$REGION" \
  --name "opus/workflow-engine/db" \
  --secret-string '{"username":"workflow","password":"s3cr3t-pw","host":"db.internal"}'
```

With `aws.secretPrefix: opus/`, `vault-env` reference
`secret/data/workflow-engine/db` resolves to the secret `opus/workflow-engine/db`.
(Choose your prefix and reference paths to match.)

## 2. Set up IRSA for the gateway

Create an IAM policy granting read access to the secret namespace:

```bash
cat > gw-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:opus/*"
    }
  ]
}
JSON

aws iam create-policy \
  --policy-name vault-gateway-read \
  --policy-document file://gw-policy.json
```

Create an IRSA-bound ServiceAccount that assumes a role with that policy:

```bash
eksctl create iamserviceaccount \
  --cluster "$CLUSTER" --region "$REGION" \
  --namespace "$GW_NS" --name vault-gateway \
  --attach-policy-arn arn:aws:iam::aws:policy/vault-gateway-read \
  --approve
```

This annotates the `vault-gateway` ServiceAccount with
`eks.amazonaws.com/role-arn`, which the AWS SDK picks up automatically — no keys.

## 3. Install with Helm (AWS values overlay)

```yaml
# values-aws.yaml
backend: aws

serviceAccount:
  # reuse the IRSA-bound SA created above
  create: false
  name: vault-gateway

aws:
  region: us-east-1
  secretPrefix: "opus/"
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s

server:
  tls:
    enabled: true
    minVersion: "1.2"

auth:
  tokenTTL: 15m
  roles:
    workflow-engine:
      allowedNamespaces:      ["opus"]
      allowedServiceAccounts: ["workflow-engine"]
      allowedPaths:           ["workflow-engine/**"]

metrics:
  enabled: true
```

```bash
helm install vault-gateway vault-gateway/vault-gateway \
  --namespace "$GW_NS" \
  -f values-aws.yaml
```

> TLS: provide a server certificate for `vault-gateway.<GW_NS>.svc`. In most
> clusters cert-manager issues this; point `server.tls.certFile`/`keyFile` at the
> mounted secret. For a quick test you can generate a self-signed cert (see
> [troubleshooting → TLS](./troubleshooting.md#tls-certificate-issues)).

## 4. Point the Bank-Vaults webhook at the gateway

The webhook's `vault-env` needs `VAULT_ADDR` set to the gateway Service. Set it
via the webhook's default environment or per-pod annotations:

```yaml
# pod / deployment annotations consumed by vault-secrets-webhook
metadata:
  annotations:
    vault.security.banzaicloud.io/vault-addr: "https://vault-gateway.vault-gateway:8200"
    vault.security.banzaicloud.io/vault-role: "workflow-engine"
    vault.security.banzaicloud.io/vault-path: "kubernetes"
    # if using a private/self-signed cert, mount the CA and skip-verify only in dev:
    # vault.security.banzaicloud.io/vault-skip-verify: "false"
```

## 5. Deploy a sample app

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: workflow-engine
  namespace: opus
spec:
  replicas: 1
  selector: { matchLabels: { app: workflow-engine } }
  template:
    metadata:
      labels: { app: workflow-engine }
      annotations:
        vault.security.banzaicloud.io/vault-addr: "https://vault-gateway.vault-gateway:8200"
        vault.security.banzaicloud.io/vault-role: "workflow-engine"
    spec:
      serviceAccountName: workflow-engine
      containers:
        - name: app
          image: busybox
          command: ["sh", "-c", "echo db=$DB_PASSWORD && sleep 3600"]
          env:
            - name: DB_PASSWORD
              value: "vault:secret/data/workflow-engine/db#password"
```

```bash
kubectl create serviceaccount workflow-engine -n opus
kubectl apply -f sample-app.yaml
```

The webhook injects `vault-env`, which logs in to the gateway, reads
`workflow-engine/db`, and exports `DB_PASSWORD` — without any Kubernetes Secret.

## 6. Verify

```bash
# gateway health
kubectl run curl --rm -it --image=curlimages/curl -n vault-gateway -- \
  curl -sk https://vault-gateway.vault-gateway:8200/v1/sys/health

# gateway logs (audit lines: identity, path, outcome — never secret values)
kubectl logs -n vault-gateway deploy/vault-gateway

# the secret reached the app's environment
kubectl exec -n opus deploy/workflow-engine -- printenv DB_PASSWORD
```

## Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| App pod stuck in `Init`/crashloop | Gateway unreachable, or IRSA policy missing `GetSecretValue` for the path. |
| `permission denied` | Role `allowedNamespaces`/`allowedServiceAccounts`/`allowedPaths` mismatch. |
| `502` from gateway | Secrets Manager unreachable; check IRSA, region, VPC endpoint. |
| `404` | Secret name (after `secretPrefix`) does not exist. |

More detail in [troubleshooting](./troubleshooting.md).

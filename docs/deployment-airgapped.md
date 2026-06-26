# Deployment guide: Airgapped (in-cluster HashiCorp Vault backend)

In an airgapped or sovereign cluster there is no cloud secret manager to reach.
This guide deploys Vault Gateway in front of a **real, in-cluster HashiCorp
Vault**, so applications still get daemonless, etcd-free secret injection through
the same `vault-env` flow.

> You may reasonably ask: if you run real Vault, why front it with the gateway?
> Two reasons: (1) a single, uniform `vault-env`/Vault-Gateway contract across
> all your clusters (cloud and airgapped) with one set of roles and RBAC
> semantics, and (2) the gateway's least-privilege surface, per-IP rate
> limiting, path-glob RBAC, and caching in front of Vault. If you prefer, you
> can point `vault-env` straight at Vault — the gateway is optional in the
> airgapped case but keeps your topology consistent.

Related: [configuration](./configuration.md) · [authentication](./authentication.md) · [troubleshooting](./troubleshooting.md).

## Prerequisites

- A Kubernetes cluster (no internet egress required once images are mirrored).
- All container images mirrored to your internal registry (gateway, Vault,
  Bank-Vaults webhook).
- `kubectl`, `helm` (3.x), and the `vault` CLI.
- A running HashiCorp Vault in the cluster (e.g. namespace `vault`) with the KV
  v2 secrets engine and the Kubernetes auth method enabled.
- Namespaces `vault-gateway` and `opus`.

## 1. Enable Kubernetes auth on Vault and create a role

```bash
# inside a Vault-authenticated shell
vault auth enable kubernetes

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc"

# policy granting the gateway read access to the secret tree
vault policy write vault-gateway - <<'HCL'
path "secret/data/opus/*" {
  capabilities = ["read"]
}
HCL

# bind the gateway's ServiceAccount to that policy
vault write auth/kubernetes/role/vault-gateway \
  bound_service_account_names=vault-gateway \
  bound_service_account_namespaces=vault-gateway \
  policies=vault-gateway \
  ttl=15m
```

## 2. Create secrets in Vault (KV v2)

```bash
vault kv put secret/opus/workflow-engine/db \
  username=workflow \
  password=s3cr3t-pw \
  host=db.internal
```

The gateway passes KV v2 reads through unchanged, so a `vault-env` reference
`secret/data/opus/workflow-engine/db#password` resolves directly.

## 3. Install with Helm (Vault values overlay)

```yaml
# values-airgapped.yaml
image:
  repository: registry.internal/vault-gateway/vault-gateway   # mirrored image
  tag: 0.1.0

backend: vault

serviceAccount:
  create: true
  name: vault-gateway

vault:
  address: "https://vault.vault:8200"
  authPath: kubernetes
  role: vault-gateway
  caCert: /etc/vault-gateway/vault-ca/ca.crt   # mount Vault's CA
  tlsSkipVerify: false
  cache:
    enabled: true
    ttl: 60s
    negativeTTL: 10s

# mount the Vault CA so the gateway can verify Vault's TLS cert
extraVolumes:
  - name: vault-ca
    configMap:
      name: vault-ca
extraVolumeMounts:
  - name: vault-ca
    mountPath: /etc/vault-gateway/vault-ca
    readOnly: true

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
      allowedPaths:           ["opus/workflow-engine/**"]

metrics:
  enabled: true
```

```bash
kubectl -n vault-gateway create configmap vault-ca --from-file=ca.crt=./vault-ca.crt

helm install vault-gateway vault-gateway/vault-gateway \
  --namespace vault-gateway \
  -f values-airgapped.yaml
```

The gateway's own ServiceAccount still needs only the `tokenreviews.create`
cluster permission (the Helm chart creates this). It authenticates to Vault using
the Kubernetes auth role from step 1 — no static Vault token is stored.

## 4. Point the Bank-Vaults webhook at the gateway

```yaml
metadata:
  annotations:
    vault.security.banzaicloud.io/vault-addr: "https://vault-gateway.vault-gateway:8200"
    vault.security.banzaicloud.io/vault-role: "workflow-engine"
    vault.security.banzaicloud.io/vault-path: "kubernetes"
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
          image: registry.internal/busybox:latest
          command: ["sh", "-c", "echo db=$DB_PASSWORD && sleep 3600"]
          env:
            - name: DB_PASSWORD
              value: "vault:secret/data/opus/workflow-engine/db#password"
```

```bash
kubectl create serviceaccount workflow-engine -n opus
kubectl apply -f sample-app.yaml
```

## 6. Verify

```bash
kubectl run curl --rm -it --image=registry.internal/curlimages/curl -n vault-gateway -- \
  curl -sk https://vault-gateway.vault-gateway:8200/v1/sys/health

kubectl logs -n vault-gateway deploy/vault-gateway
kubectl exec -n opus deploy/workflow-engine -- printenv DB_PASSWORD
```

## Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| Gateway can't reach Vault (`502`) | Wrong `vault.address`, network policy blocking egress to the Vault Service, or CA not mounted. |
| Gateway login to Vault fails | `bound_service_account_*` in the Vault role does not match the gateway's SA/namespace, or `kubernetes_host` misconfigured. |
| TLS verify error to Vault | `caCert` missing/incorrect. Use a correct CA bundle; `tlsSkipVerify: true` is dev-only. |
| App `403 permission denied` | Gateway role namespace/SA/path mismatch (separate from Vault's own policy). |

More detail in [troubleshooting](./troubleshooting.md).

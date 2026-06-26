# Deployment guide: Azure (Key Vault + Workload Identity)

This guide deploys Vault Gateway on Azure Kubernetes Service (AKS), backed by
Azure Key Vault, authenticating with **Azure Workload Identity** — no static
credentials.

Related: [configuration](./configuration.md) · [authentication](./authentication.md) · [troubleshooting](./troubleshooting.md).

## Prerequisites

- An AKS cluster with the **OIDC issuer** and **Workload Identity** add-ons
  enabled (`--enable-oidc-issuer --enable-workload-identity`).
- `kubectl`, `helm` (3.x), and the `az` CLI.
- An Azure Key Vault and permission to set secrets and assign access.
- Bank-Vaults `vault-secrets-webhook` installed.
- Namespaces, e.g. `vault-gateway` and `opus`.

```bash
export RG=opus-rg
export KV=kv-opus
export GW_NS=vault-gateway
export APP_NS=opus
kubectl create namespace "$GW_NS"
kubectl create namespace "$APP_NS"
```

## 1. Create secrets in Key Vault (flat naming)

Key Vault names allow only alphanumerics and hyphens, with no nesting. With the
default `flat` strategy, path `opus/workflow-engine` + key `db_password` maps to
the Key Vault secret `opus-workflow-engine--db-password` (note the `--` joining
path and key, and `_` rewritten to `-`).

```bash
az keyvault secret set \
  --vault-name "$KV" \
  --name "opus-workflow-engine--db-password" \
  --value "s3cr3t-pw"

az keyvault secret set \
  --vault-name "$KV" \
  --name "opus-workflow-engine--db-username" \
  --value "workflow"
```

With the `json` strategy instead, store one secret per path whose value is a
JSON object:

```bash
az keyvault secret set \
  --vault-name "$KV" \
  --name "opus-workflow-engine" \
  --value '{"db_password":"s3cr3t-pw","db_username":"workflow"}'
```

Set `azure.namingStrategy` to whichever you used.

## 2. Set up Workload Identity for the gateway

Create a user-assigned managed identity and federate it with the gateway's
ServiceAccount:

```bash
export OIDC=$(az aks show -g "$RG" -n opus-aks --query oidcIssuerProfile.issuerUrl -o tsv)

az identity create -g "$RG" -n vault-gateway-id
export MI_CLIENT_ID=$(az identity show -g "$RG" -n vault-gateway-id --query clientId -o tsv)

az identity federated-credential create \
  -g "$RG" --identity-name vault-gateway-id \
  --name vault-gateway-fc \
  --issuer "$OIDC" \
  --subject "system:serviceaccount:${GW_NS}:vault-gateway" \
  --audience api://AzureADTokenExchange
```

Grant the identity read access to the Key Vault (RBAC mode shown):

```bash
export KV_ID=$(az keyvault show -n "$KV" --query id -o tsv)
az role assignment create \
  --assignee "$MI_CLIENT_ID" \
  --role "Key Vault Secrets User" \
  --scope "$KV_ID"
```

## 3. Install with Helm (Azure values overlay)

```yaml
# values-azure.yaml
backend: azure

serviceAccount:
  create: true
  name: vault-gateway
  annotations:
    azure.workload.identity/client-id: "<MI_CLIENT_ID>"

podLabels:
  azure.workload.identity/use: "true"

azure:
  vaultURL: "https://kv-opus.vault.azure.net/"
  namingStrategy: flat
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
      allowedPaths:           ["opus/workflow-engine/**"]

metrics:
  enabled: true
```

```bash
helm install vault-gateway vault-gateway/vault-gateway \
  --namespace "$GW_NS" \
  -f values-azure.yaml \
  --set serviceAccount.annotations."azure\.workload\.identity/client-id"="$MI_CLIENT_ID"
```

> The pod must carry the label `azure.workload.identity/use: "true"` for the
> webhook/sidecar to inject the federated token.

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
          image: busybox
          command: ["sh", "-c", "echo db=$DB_PASSWORD && sleep 3600"]
          env:
            - name: DB_PASSWORD
              value: "vault:secret/data/opus/workflow-engine#db_password"
```

```bash
kubectl create serviceaccount workflow-engine -n opus
kubectl apply -f sample-app.yaml
```

## 6. Verify

```bash
kubectl run curl --rm -it --image=curlimages/curl -n vault-gateway -- \
  curl -sk https://vault-gateway.vault-gateway:8200/v1/sys/health

kubectl logs -n vault-gateway deploy/vault-gateway
kubectl exec -n opus deploy/workflow-engine -- printenv DB_PASSWORD
```

## Troubleshooting

| Symptom | Likely cause |
| ------- | ------------ |
| App pod stuck in `Init` | Gateway unreachable, or managed identity lacks `Key Vault Secrets User`. |
| `404` | Key Vault secret name does not match the `flat`/`json` mapping — recompute the encoded name. |
| `403 permission denied` | Role namespace/SA/path mismatch. |
| Workload identity token errors | Missing `azure.workload.identity/use: "true"` label, or a federated-credential subject that does not match `system:serviceaccount:<GW_NS>:vault-gateway`. |

More detail in [troubleshooting](./troubleshooting.md).

#!/usr/bin/env bash
#
# azure-workload-identity-setup.sh
#
# Provision Azure Workload Identity for vault-gateway so it can read secrets
# from Azure Key Vault without static credentials.
#
# Steps performed:
#   1. Create a user-assigned managed identity.
#   2. Create a federated identity credential linking the identity to the
#      gateway's Kubernetes ServiceAccount (via the cluster OIDC issuer).
#   3. Grant the identity read access to the Key Vault (RBAC role assignment;
#      falls back to an access policy for vaults in legacy access-policy mode).
#   4. Annotate / label the Kubernetes ServiceAccount.
#
# Prerequisites: azure-cli with the aks-preview features enabled, kubectl,
# and an AKS cluster with the OIDC issuer + workload identity add-ons enabled.
set -euo pipefail

# ----------------------------- Parameters ------------------------------------
SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-00000000-0000-0000-0000-000000000000}"
RESOURCE_GROUP="${RESOURCE_GROUP:-vault-gateway-rg}"
LOCATION="${LOCATION:-qatarcentral}"
CLUSTER_NAME="${CLUSTER_NAME:-my-aks-cluster}"
IDENTITY_NAME="${IDENTITY_NAME:-vault-gateway-identity}"
KEYVAULT_NAME="${KEYVAULT_NAME:-my-keyvault}"
NAMESPACE="${NAMESPACE:-vault-system}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-vault-gateway}"
FEDERATED_CRED_NAME="${FEDERATED_CRED_NAME:-vault-gateway-federated}"
# -----------------------------------------------------------------------------

az account set --subscription "${SUBSCRIPTION_ID}"

echo ">> Creating user-assigned managed identity ${IDENTITY_NAME} ..."
az identity create \
  --name "${IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --location "${LOCATION}" 1>/dev/null

CLIENT_ID="$(az identity show \
  --name "${IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query clientId -o tsv)"
PRINCIPAL_ID="$(az identity show \
  --name "${IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query principalId -o tsv)"

echo ">> Resolving AKS OIDC issuer URL ..."
OIDC_ISSUER="$(az aks show \
  --name "${CLUSTER_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query oidcIssuerProfile.issuerUrl -o tsv)"

echo ">> Creating federated identity credential ${FEDERATED_CRED_NAME} ..."
az identity federated-credential create \
  --name "${FEDERATED_CRED_NAME}" \
  --identity-name "${IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --issuer "${OIDC_ISSUER}" \
  --subject "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}" \
  --audience "api://AzureADTokenExchange" 1>/dev/null

echo ">> Granting Key Vault read access ..."
KV_ID="$(az keyvault show --name "${KEYVAULT_NAME}" --query id -o tsv)"
# Preferred: RBAC role assignment (vault must use Azure RBAC permission model).
az role assignment create \
  --assignee-object-id "${PRINCIPAL_ID}" \
  --assignee-principal-type ServicePrincipal \
  --role "Key Vault Secrets User" \
  --scope "${KV_ID}" 2>/dev/null || {
    echo "   RBAC assignment failed; applying access policy instead"
    az keyvault set-policy \
      --name "${KEYVAULT_NAME}" \
      --object-id "${PRINCIPAL_ID}" \
      --secret-permissions get list 1>/dev/null
  }

echo ">> Annotating + labeling ServiceAccount ${NAMESPACE}/${SERVICE_ACCOUNT} ..."
kubectl annotate serviceaccount "${SERVICE_ACCOUNT}" \
  --namespace "${NAMESPACE}" \
  "azure.workload.identity/client-id=${CLIENT_ID}" \
  --overwrite
kubectl label serviceaccount "${SERVICE_ACCOUNT}" \
  --namespace "${NAMESPACE}" \
  "azure.workload.identity/use=true" \
  --overwrite

echo
echo "Done. Set these in your Helm values (values-azure.yaml):"
echo "  serviceAccount.annotations.azure.workload.identity/client-id: ${CLIENT_ID}"
echo "  serviceAccount.labels.azure.workload.identity/use: \"true\""
echo "  podLabels.azure.workload.identity/use: \"true\""
echo "  config.azure.vaultURL: https://${KEYVAULT_NAME}.vault.azure.net"

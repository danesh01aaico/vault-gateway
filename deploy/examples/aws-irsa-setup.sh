#!/usr/bin/env bash
#
# aws-irsa-setup.sh
#
# Provision AWS IAM Roles for Service Accounts (IRSA) for vault-gateway so the
# gateway can read secrets from AWS Secrets Manager without static credentials.
#
# Steps performed:
#   1. Create an IAM policy granting read-only access to Secrets Manager.
#   2. Ensure the cluster's OIDC provider is registered with IAM.
#   3. Create an IAM role with a trust policy scoped to the gateway's
#      Kubernetes ServiceAccount (web identity / OIDC).
#   4. Attach the policy to the role.
#   5. Annotate the Kubernetes ServiceAccount with the role ARN.
#
# Prerequisites: awscli v2, eksctl (or jq + kubectl), and cluster admin access.
set -euo pipefail

# ----------------------------- Parameters ------------------------------------
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-123456789012}"
AWS_REGION="${AWS_REGION:-me-south-1}"
CLUSTER_NAME="${CLUSTER_NAME:-my-eks-cluster}"
NAMESPACE="${NAMESPACE:-vault-system}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-vault-gateway}"
ROLE_NAME="${ROLE_NAME:-vault-gateway-role}"
POLICY_NAME="${POLICY_NAME:-vault-gateway-secrets-read}"
# -----------------------------------------------------------------------------

POLICY_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:policy/${POLICY_NAME}"
ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"

echo ">> Creating IAM policy ${POLICY_NAME} ..."
cat > /tmp/vault-gateway-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSecretsRead",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "*"
    }
  ]
}
JSON

aws iam create-policy \
  --policy-name "${POLICY_NAME}" \
  --policy-document file:///tmp/vault-gateway-policy.json \
  --region "${AWS_REGION}" 2>/dev/null || \
  echo "   policy already exists, continuing"

echo ">> Associating the cluster OIDC provider with IAM (idempotent) ..."
eksctl utils associate-iam-oidc-provider \
  --cluster "${CLUSTER_NAME}" \
  --region "${AWS_REGION}" \
  --approve

# Derive the OIDC provider URL/ID for the trust policy.
OIDC_PROVIDER="$(aws eks describe-cluster \
  --name "${CLUSTER_NAME}" \
  --region "${AWS_REGION}" \
  --query 'cluster.identity.oidc.issuer' \
  --output text | sed -e 's|^https://||')"

echo ">> Building trust policy for ${OIDC_PROVIDER} ..."
cat > /tmp/vault-gateway-trust.json <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
JSON

echo ">> Creating IAM role ${ROLE_NAME} ..."
aws iam create-role \
  --role-name "${ROLE_NAME}" \
  --assume-role-policy-document file:///tmp/vault-gateway-trust.json \
  --region "${AWS_REGION}" 2>/dev/null || \
  aws iam update-assume-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-document file:///tmp/vault-gateway-trust.json

echo ">> Attaching policy to role ..."
aws iam attach-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-arn "${POLICY_ARN}"

echo ">> Annotating ServiceAccount ${NAMESPACE}/${SERVICE_ACCOUNT} ..."
kubectl annotate serviceaccount "${SERVICE_ACCOUNT}" \
  --namespace "${NAMESPACE}" \
  "eks.amazonaws.com/role-arn=${ROLE_ARN}" \
  --overwrite

echo
echo "Done. Set this in your Helm values (values-aws.yaml):"
echo "  serviceAccount.annotations.eks.amazonaws.com/role-arn: ${ROLE_ARN}"

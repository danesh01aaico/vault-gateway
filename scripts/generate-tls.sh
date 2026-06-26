#!/usr/bin/env bash
#
# generate-tls.sh
#
# Generate a self-signed TLS certificate + private key for LOCAL DEVELOPMENT
# of Vault Gateway. The cert includes Subject Alternative Names covering the
# in-cluster service DNS names and localhost so it works both inside Kubernetes
# and when port-forwarding / running locally.
#
# WARNING: This produces a self-signed cert. Do NOT use it in production.
#
# Usage:
#   ./scripts/generate-tls.sh [output-dir]
#
# Environment:
#   OUTPUT_DIR   Output directory (default: ./dev/tls)
#   DAYS         Validity in days (default: 365)
#   KEY_BITS     RSA key size (default: 4096)
#   CN           Certificate common name (default: vault-gateway)

set -euo pipefail

OUTPUT_DIR="${1:-${OUTPUT_DIR:-./dev/tls}}"
DAYS="${DAYS:-365}"
KEY_BITS="${KEY_BITS:-4096}"
CN="${CN:-vault-gateway}"

KEY_FILE="${OUTPUT_DIR}/tls.key"
CRT_FILE="${OUTPUT_DIR}/tls.crt"

# Subject Alternative Names: in-cluster service DNS + local development hosts.
SANS="DNS:vault-gateway,DNS:vault-gateway.vault-system,DNS:vault-gateway.vault-system.svc,DNS:localhost,IP:127.0.0.1"

command -v openssl >/dev/null 2>&1 || {
  echo "error: openssl is required but not installed" >&2
  exit 1
}

mkdir -p "${OUTPUT_DIR}"

echo "Generating self-signed TLS material in: ${OUTPUT_DIR}"
echo "  CN:   ${CN}"
echo "  SANs: ${SANS}"
echo "  Days: ${DAYS}"

# Single-shot generation: new RSA key + self-signed cert with SANs.
# -addext requires OpenSSL 1.1.1+; -subj avoids the interactive prompt.
openssl req -x509 -nodes \
  -newkey "rsa:${KEY_BITS}" \
  -keyout "${KEY_FILE}" \
  -out "${CRT_FILE}" \
  -days "${DAYS}" \
  -subj "/CN=${CN}" \
  -addext "subjectAltName=${SANS}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 600 "${KEY_FILE}"
chmod 644 "${CRT_FILE}"

echo
echo "Done."
echo "  key: ${KEY_FILE}"
echo "  crt: ${CRT_FILE}"
echo
echo "Inspect with: openssl x509 -in ${CRT_FILE} -noout -text"

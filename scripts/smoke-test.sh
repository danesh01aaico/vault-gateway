#!/usr/bin/env bash
#
# smoke-test.sh
#
# Lightweight smoke test against a running Vault Gateway instance. It checks the
# health and seal-status endpoints, then (optionally) exercises a login +
# secret-read flow using placeholder credentials supplied via environment
# variables.
#
# Because dev uses a self-signed cert, curl is invoked with -k (insecure).
#
# Usage:
#   ./scripts/smoke-test.sh
#
# Environment:
#   GATEWAY_ADDR   Base URL (default: https://localhost:8200)
#   JWT            JWT/token used for the login flow (optional)
#   ROLE           Auth role to log in as (optional)
#   SECRET_PATH    Secret path to read after login (optional)
#   AUTH_PATH      Auth mount path for login (default: auth/jwt/login)

set -euo pipefail

GATEWAY_ADDR="${GATEWAY_ADDR:-https://localhost:8200}"
JWT="${JWT:-}"
ROLE="${ROLE:-}"
SECRET_PATH="${SECRET_PATH:-}"
AUTH_PATH="${AUTH_PATH:-auth/jwt/login}"

PASS=0
FAIL=0

# pass <message>
pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
# fail <message>
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

command -v curl >/dev/null 2>&1 || { echo "error: curl required" >&2; exit 1; }

# curl wrapper: insecure (self-signed dev cert), silent, fail on HTTP errors,
# print the HTTP status code on its own line for assertions.
http_get() {
  curl -k -sS -o /tmp/smoke-body.$$ -w "%{http_code}" "$1" 2>/dev/null || echo "000"
}

echo "== Vault Gateway smoke test =="
echo "Target: ${GATEWAY_ADDR}"
echo

# --- 1. Health endpoint -----------------------------------------------------
echo "-> GET /v1/sys/health"
code="$(http_get "${GATEWAY_ADDR}/v1/sys/health")"
if [[ "${code}" =~ ^(200|429|472|473|501|503)$ ]]; then
  # Vault health returns various 2xx/5xx codes depending on seal/standby state;
  # any of these means the endpoint is reachable and responding.
  pass "health endpoint reachable (HTTP ${code})"
else
  fail "health endpoint returned HTTP ${code}"
fi

# --- 2. Seal status ---------------------------------------------------------
echo "-> GET /v1/sys/seal-status"
code="$(http_get "${GATEWAY_ADDR}/v1/sys/seal-status")"
if [[ "${code}" == "200" ]]; then
  pass "seal-status endpoint reachable (HTTP ${code})"
else
  fail "seal-status endpoint returned HTTP ${code}"
fi

# --- 3. Login + secret read (optional) --------------------------------------
if [[ -n "${JWT}" && -n "${ROLE}" ]]; then
  echo "-> POST /v1/${AUTH_PATH} (login)"
  login_resp="$(curl -k -sS -X POST \
    -H "Content-Type: application/json" \
    -d "{\"role\":\"${ROLE}\",\"jwt\":\"${JWT}\"}" \
    "${GATEWAY_ADDR}/v1/${AUTH_PATH}" 2>/dev/null || true)"

  # Extract client_token without requiring jq.
  token="$(printf '%s' "${login_resp}" | grep -o '"client_token"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed 's/.*:"\(.*\)"/\1/')"

  if [[ -n "${token}" ]]; then
    pass "login succeeded, obtained client token"

    if [[ -n "${SECRET_PATH}" ]]; then
      echo "-> GET /v1/${SECRET_PATH} (secret read)"
      code="$(curl -k -sS -o /dev/null -w "%{http_code}" \
        -H "X-Vault-Token: ${token}" \
        "${GATEWAY_ADDR}/v1/${SECRET_PATH}" 2>/dev/null || echo "000")"
      if [[ "${code}" == "200" ]]; then
        pass "secret read at ${SECRET_PATH} (HTTP ${code})"
      else
        fail "secret read at ${SECRET_PATH} returned HTTP ${code}"
      fi
    else
      echo "SKIP: SECRET_PATH not set, skipping secret read"
    fi
  else
    fail "login did not return a client_token"
  fi
else
  echo "SKIP: JWT/ROLE not set, skipping login + secret read flow"
fi

# Cleanup temp body file.
rm -f "/tmp/smoke-body.$$" 2>/dev/null || true

echo
echo "== Results: ${PASS} passed, ${FAIL} failed =="
[[ "${FAIL}" -eq 0 ]] || exit 1

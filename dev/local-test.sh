#!/usr/bin/env bash
# local-test.sh — End-to-end local test for vault-gateway + vault-inject.
#
# Flow:
#   LocalStack (localhost:4566)
#     └─> vault-gateway (binary, localhost:8200, AWS backend → LocalStack)
#           └─> vault-inject (binary, reads SA JWT from k3d, execs into `env`)
#
# Nothing is deployed to any cluster. k3d is used only for its TokenReview API
# (the control-plane validates the SA JWT we generate).
#
# Prerequisites:
#   - k3d dev-cluster running   (k3d cluster start dev-cluster)
#   - LocalStack running        (docker start localstack)
#   - Secret seeded             (see below if needed)
#
# Usage:
#   ./dev/local-test.sh
#   make local-test
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K3D_KUBECONFIG="/Users/daneshwar/.config/k3d/kubeconfig-dev-cluster.yaml"
GATEWAY_CONFIG="$SCRIPT_DIR/config/gateway-local.yaml"
GATEWAY_ADDR="http://127.0.0.1:8200"
METRICS_ADDR="http://127.0.0.1:9090"

GW_PID=""
JWT_FILE=""

cleanup() {
  if [[ -n "$GW_PID" ]]; then
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
  fi
  [[ -n "$JWT_FILE" ]] && rm -f "$JWT_FILE"
}
trap cleanup EXIT

print_step() { echo; echo "==> $*"; }
die()        { echo "ERROR: $*" >&2; exit 1; }

# ── 1. Safety checks ─────────────────────────────────────────────────────────
print_step "Safety checks"

[[ -f "$K3D_KUBECONFIG" ]] \
  || die "k3d kubeconfig not found at $K3D_KUBECONFIG — run: k3d cluster start dev-cluster"

# Verify the kubeconfig points at k3d (not a cloud cluster).
CURRENT_CONTEXT=$(KUBECONFIG="$K3D_KUBECONFIG" kubectl config current-context 2>/dev/null || true)
if [[ "$CURRENT_CONTEXT" != k3d-* ]]; then
  die "Kubeconfig context is '$CURRENT_CONTEXT', expected k3d-*. Refusing to run."
fi
echo "    Cluster context: $CURRENT_CONTEXT (k3d only)"

# Verify k3d control-plane is reachable.
KUBECONFIG="$K3D_KUBECONFIG" kubectl get nodes --no-headers >/dev/null 2>&1 \
  || die "k3d cluster is not reachable. Run: k3d cluster start dev-cluster"

# ── 2. LocalStack health check ───────────────────────────────────────────────
print_step "LocalStack check (localhost:4566)"

curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1 \
  || die "LocalStack is not running. Run: docker start localstack"

if AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
     aws --endpoint-url=http://localhost:4566 --region us-east-1 \
     secretsmanager describe-secret --secret-id myapp/db-password \
     >/dev/null 2>&1; then
  echo "    Secret 'myapp/db-password' found."
else
  echo "    Secret not found — seeding myapp/db-password..."
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url=http://localhost:4566 --region us-east-1 \
  secretsmanager create-secret \
    --name myapp/db-password \
    --secret-string '{"username":"admin","password":"s3cr3t"}' >/dev/null
  echo "    Seeded."
fi

# ── 3. Build binaries ────────────────────────────────────────────────────────
print_step "Building binaries"
cd "$REPO_ROOT"

echo "    vault-gateway..."
go build -o bin/vault-gateway ./cmd/vault-gateway/

echo "    vault-inject (vault-env)..."
go build -o bin/vault-env ./cmd/vault-inject/

echo "    Done."

# ── 4. Service account JWT from k3d ─────────────────────────────────────────
print_step "Creating test service account in k3d (JWT only — no pod deployed)"

KUBECONFIG="$K3D_KUBECONFIG" kubectl create serviceaccount vault-test \
  --namespace default --dry-run=client -o yaml \
  | KUBECONFIG="$K3D_KUBECONFIG" kubectl apply -f - 2>&1 \
  | sed 's/^/    /'

echo "    Requesting 1-hour service account token..."
JWT=$(KUBECONFIG="$K3D_KUBECONFIG" kubectl create token vault-test \
  --namespace default --duration=1h)

JWT_FILE=$(mktemp /tmp/vault-test-jwt.XXXX)
echo "$JWT" > "$JWT_FILE"
echo "    Token written to $JWT_FILE"

# ── 5. Start vault-gateway ───────────────────────────────────────────────────
print_step "Starting vault-gateway (HTTP, port 8200)"

# Port conflict guard.
if lsof -ti:8200 >/dev/null 2>&1; then
  die "Port 8200 already in use. Stop whatever is listening and retry."
fi
if lsof -ti:9090 >/dev/null 2>&1; then
  die "Port 9090 already in use."
fi

AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
AWS_DEFAULT_REGION=us-east-1 \
  "$REPO_ROOT/bin/vault-gateway" \
    --config "$GATEWAY_CONFIG" \
    --kubeconfig "$K3D_KUBECONFIG" \
    > /tmp/vault-gateway-local.log 2>&1 &
GW_PID=$!
echo "    PID $GW_PID | logs: /tmp/vault-gateway-local.log"

# ── 6. Wait for healthz ──────────────────────────────────────────────────────
print_step "Waiting for gateway /healthz..."
ATTEMPTS=0
until curl -sf "$METRICS_ADDR/healthz" >/dev/null 2>&1; do
  ATTEMPTS=$((ATTEMPTS+1))
  if [[ $ATTEMPTS -ge 30 ]]; then
    echo; echo "Gateway failed to start. Last 20 lines of log:"; echo
    tail -20 /tmp/vault-gateway-local.log
    die "Gateway did not become healthy within 30s"
  fi
  printf "."
  sleep 1
done
echo " healthy"

# Verify readyz (backend connectivity to LocalStack).
print_step "Checking /readyz (backend → LocalStack)"
if curl -sf "$METRICS_ADDR/readyz" >/dev/null 2>&1; then
  echo "    Backend ready."
else
  echo "    /readyz not ready — showing gateway log:"; echo
  tail -30 /tmp/vault-gateway-local.log
  die "Backend health check failed"
fi

# ── 7. Run vault-inject ──────────────────────────────────────────────────────
print_step "Running vault-inject (resolving secrets into env)"
echo
echo "    Input env vars:"
echo "      DB_PASSWORD = vault:secret/data/myapp/db-password#password"
echo "      DB_USER     = vault:secret/data/myapp/db-password#username"
echo

RESOLVED=$(
  VAULT_ADDR="$GATEWAY_ADDR" \
  VAULT_ROLE=local-test \
  VAULT_SKIP_VERIFY=true \
  VAULT_JWT_FILE="$JWT_FILE" \
  VAULT_LOG_LEVEL=info \
  DB_PASSWORD='vault:secret/data/myapp/db-password#password' \
  DB_USER='vault:secret/data/myapp/db-password#username' \
    "$REPO_ROOT/bin/vault-env" env 2>/tmp/vault-env-local.log
)

# Show only the resolved DB_ vars.
echo "    Resolved env vars:"
echo "$RESOLVED" | grep -E '^DB_' | sed 's/^/      /'

# Verify expected values.
echo
PASS=true
check_var() {
  local name="$1" expected="$2"
  local actual
  actual=$(echo "$RESOLVED" | grep "^${name}=" | cut -d= -f2-)
  if [[ "$actual" == "$expected" ]]; then
    echo "    [PASS] $name=$actual"
  else
    echo "    [FAIL] $name: expected '$expected', got '$actual'"
    PASS=false
  fi
}

check_var "DB_PASSWORD" "s3cr3t"
check_var "DB_USER"     "admin"

# Verify VAULT_* vars are stripped.
if echo "$RESOLVED" | grep -qE '^VAULT_'; then
  echo "    [FAIL] VAULT_* vars leaked into child env"
  PASS=false
else
  echo "    [PASS] VAULT_* config vars stripped from child env"
fi

echo
if $PASS; then
  echo "==> LOCAL TEST PASSED"
  echo
  echo "    The full flow works:"
  echo "      vault-inject → vault-gateway (localhost:8200)"
  echo "                   → AWS Secrets Manager (LocalStack localhost:4566)"
  echo "                   → resolved secret injected as env var"
  echo "                   → VAULT_* config vars stripped from child process"
else
  echo "==> LOCAL TEST FAILED"
  echo; echo "vault-inject log:"; cat /tmp/vault-env-local.log
  echo; echo "gateway log:"; tail -40 /tmp/vault-gateway-local.log
  exit 1
fi

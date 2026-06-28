#!/usr/bin/env bash
# deploy-k3d.sh — Production-hardened deployment to the local k3d cluster.
#
# What this applies:
#   - TLS on vault-gateway (self-signed cert, CA distributed to pods)
#   - Pod Security Standards (restricted) enforced on vault-system namespace
#   - securityContext: runAsNonRoot, readOnlyRootFilesystem, drop ALL caps, seccomp
#   - Resource limits and requests
#   - Pod anti-affinity across nodes
#   - PodDisruptionBudget (minAvailable: 1)
#   - PriorityClass (gateway starts before app pods)
#   - NetworkPolicy (only labelled pods reach port 8200)
#   - Token TTL: 5 minutes
#   - Rate limiting: 50 rps / burst 100
#   - Secret cache: 30s TTL (AWS SM not hit on every request)
#
# Prerequisites:
#   - k3d dev-cluster running   (k3d cluster start dev-cluster)
#   - LocalStack running        (docker start localstack)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export KUBECONFIG="/Users/daneshwar/.config/k3d/kubeconfig-dev-cluster.yaml"
K8S_DIR="$SCRIPT_DIR/k8s"
IMAGE="vault-gateway:local"

print_step() { echo; echo "━━━ $* ━━━"; }
die()        { echo; echo "ERROR: $*" >&2; exit 1; }

# ── 1. Safety ────────────────────────────────────────────────────────────────
print_step "Safety checks"

[[ -f "$KUBECONFIG" ]] \
  || die "k3d kubeconfig not found at $KUBECONFIG"

CONTEXT=$(kubectl config current-context 2>/dev/null || true)
[[ "$CONTEXT" == k3d-* ]] \
  || die "kubeconfig context is '$CONTEXT', expected k3d-*. Refusing to proceed."
echo "  Cluster  : $CONTEXT"
echo "  KUBECONFIG : $KUBECONFIG"

kubectl get nodes --no-headers >/dev/null 2>&1 \
  || die "k3d cluster not reachable. Run: k3d cluster start dev-cluster"

READY=$(kubectl get nodes --no-headers | grep -c " Ready " || true)
echo "  Ready nodes : $READY / $(kubectl get nodes --no-headers | wc -l | tr -d ' ')"
[[ "$READY" -ge 1 ]] || die "No Ready nodes."

# ── 2. LocalStack ─────────────────────────────────────────────────────────────
print_step "LocalStack"

curl -sf http://localhost:4566/_localstack/health >/dev/null 2>&1 \
  || die "LocalStack not running. Run: docker start localstack"

if ! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
     aws --endpoint-url=http://localhost:4566 --region us-east-1 \
     secretsmanager describe-secret --secret-id myapp/db-password >/dev/null 2>&1; then
  echo "  Seeding myapp/db-password..."
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url=http://localhost:4566 --region us-east-1 \
  secretsmanager create-secret \
    --name myapp/db-password \
    --secret-string '{"username":"admin","password":"s3cr3t"}' >/dev/null
fi
echo "  Secret myapp/db-password present."

# ── 3. TLS certificate ────────────────────────────────────────────────────────
print_step "TLS certificate"

CERT_DIR=$(mktemp -d /tmp/vg-tls.XXXX)
trap 'rm -rf "$CERT_DIR"' EXIT

# Reuse existing cert if present — regenerating creates a CA/cert mismatch with
# running pods that already have the old cert mounted.
if kubectl get secret vault-gateway-tls -n vault-system >/dev/null 2>&1; then
  echo "  Reusing existing TLS secret vault-gateway-tls."
  kubectl get secret vault-gateway-tls -n vault-system \
    -o jsonpath='{.data.tls\.crt}' | base64 -d > "$CERT_DIR/tls.crt"
  kubectl get secret vault-gateway-tls -n vault-system \
    -o jsonpath='{.data.tls\.key}' | base64 -d > "$CERT_DIR/tls.key"
else
  echo "  Generating new self-signed certificate..."
  openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERT_DIR/tls.key" \
    -out    "$CERT_DIR/tls.crt" \
    -sha256 -days 365 -nodes \
    -subj "/CN=vault-gateway.vault-system.svc.cluster.local" \
    -addext "subjectAltName=DNS:vault-gateway.vault-system.svc.cluster.local,DNS:vault-gateway.vault-system.svc,DNS:vault-gateway" \
    2>/dev/null

  kubectl create secret tls vault-gateway-tls \
    --cert="$CERT_DIR/tls.crt" \
    --key="$CERT_DIR/tls.key" \
    -n vault-system \
    --dry-run=client -o yaml | kubectl apply -f -
  echo "  TLS secret vault-gateway-tls created in vault-system."
fi

# Always sync the CA ConfigMap so pods get the cert that matches the current secret.
kubectl create configmap vault-gateway-ca \
  --from-file=ca.crt="$CERT_DIR/tls.crt" \
  -n default \
  --dry-run=client -o yaml | kubectl apply -f -
echo "  CA configmap vault-gateway-ca synced in default."

# ── 4. Build image ────────────────────────────────────────────────────────────
print_step "Building Docker image ($IMAGE)"
cd "$REPO_ROOT"
docker build -t "$IMAGE" . 2>&1 | tail -5
echo "  Built: $IMAGE"

# ── 5. Import image into k3d ──────────────────────────────────────────────────
print_step "Importing image into k3d"
k3d image import "$IMAGE" -c dev-cluster 2>&1 | tail -5
echo "  Image imported."

# ── 6. Pod Security Standards on vault-system ─────────────────────────────────
print_step "Enforcing Pod Security Standards (restricted) on vault-system"
kubectl label namespace vault-system \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted \
  --overwrite
echo "  PSS restricted enforced on vault-system."

# ── 7. Apply all manifests ────────────────────────────────────────────────────
print_step "Applying manifests"

kubectl apply -f "$K8S_DIR/07-priorityclass.yaml"
kubectl apply -f "$K8S_DIR/01-gateway-rbac.yaml"
kubectl apply -f "$K8S_DIR/02-gateway-config.yaml"
kubectl apply -f "$K8S_DIR/03-gateway-deploy.yaml"
kubectl apply -f "$K8S_DIR/05-networkpolicy.yaml"
kubectl apply -f "$K8S_DIR/06-pdb.yaml"

# Always restart so pods pick up the current TLS secret and config.
kubectl rollout restart deployment/vault-gateway -n vault-system
echo "  Waiting for vault-gateway rollout (2 replicas)..."
kubectl rollout status deployment/vault-gateway -n vault-system --timeout=120s

# ── 8. Verify gateway health ──────────────────────────────────────────────────
print_step "Health check via port-forward"

kubectl port-forward svc/vault-gateway 9191:9090 -n vault-system \
  >/tmp/pf-vault-gateway.log 2>&1 &
PF_PID=$!
trap 'kill $PF_PID 2>/dev/null || true; rm -rf "$CERT_DIR"' EXIT
sleep 2

curl -sf http://localhost:9191/healthz >/dev/null && echo "  /healthz → OK" \
  || { kubectl logs -l app=vault-gateway -n vault-system --tail=20; die "/healthz failed"; }

curl -sf http://localhost:9191/readyz >/dev/null && echo "  /readyz  → OK (backend reachable)" \
  || { kubectl logs -l app=vault-gateway -n vault-system --tail=30; die "/readyz failed — check LocalStack"; }

kill $PF_PID 2>/dev/null || true

# ── 9. Deploy test pod ────────────────────────────────────────────────────────
print_step "Deploying test pod"

kubectl delete pod secret-test -n default --ignore-not-found --wait=true 2>/dev/null || true
kubectl apply -f "$K8S_DIR/04-test-pod.yaml"

# ── 10. Wait for pod to complete ─────────────────────────────────────────────
print_step "Waiting for test pod"

DEADLINE=120
ELAPSED=0
while true; do
  PHASE=$(kubectl get pod secret-test -n default \
    -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
  printf "\r  Phase: %-12s  (%ds)" "$PHASE" "$ELAPSED"

  if [[ "$PHASE" == "Succeeded" ]]; then echo; break; fi
  if [[ "$PHASE" == "Failed" ]]; then
    echo
    kubectl logs secret-test -n default -c copy-vault-inject 2>/dev/null || true
    kubectl logs secret-test -n default -c test-app 2>/dev/null || true
    kubectl describe pod secret-test -n default | grep -A 20 "^Events:"
    die "Test pod failed"
  fi
  [[ $ELAPSED -lt $DEADLINE ]] || { echo; kubectl describe pod secret-test -n default | grep -A 20 "^Events:"; die "Timed out"; }

  sleep 3; ELAPSED=$((ELAPSED+3))
done

# ── 11. Results ───────────────────────────────────────────────────────────────
print_step "Results"

POD_ENV=$(kubectl logs secret-test -n default -c test-app 2>/dev/null)

echo
echo "  Env vars seen by the app:"
echo "$POD_ENV" | grep -E '^(DB_|APP_ENV)' | sed 's/^/    /'

# ── 12. Assertions ────────────────────────────────────────────────────────────
print_step "Assertions"
PASS=true

check() {
  local name="$1" expected="$2"
  local actual
  actual=$(echo "$POD_ENV" | grep "^${name}=" | cut -d= -f2- | tr -d '\r')
  if [[ "$actual" == "$expected" ]]; then
    echo "  [PASS] $name = $actual"
  else
    echo "  [FAIL] $name : expected '$expected', got '$actual'"
    PASS=false
  fi
}

check "DB_PASSWORD" "s3cr3t"
check "DB_USER"     "admin"
check "APP_ENV"     "local-k3d"

if echo "$POD_ENV" | grep -qE '^VAULT_(ADDR|ROLE|SKIP_VERIFY|CACERT|JWT_FILE)='; then
  echo "  [FAIL] VAULT_* vars leaked into app env"
  PASS=false
else
  echo "  [PASS] VAULT_* config vars stripped from app env"
fi

K8S_SECRETS=$(kubectl get secrets -n default --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [[ "$K8S_SECRETS" -eq 0 ]]; then
  echo "  [PASS] Zero Kubernetes Secrets in default namespace"
else
  echo "  [INFO] $K8S_SECRETS secret(s) in default namespace:"
  kubectl get secrets -n default | sed 's/^/    /'
fi

echo "  [INFO] NetworkPolicy in place — only vault.io/inject=true pods reach port 8200"
echo "  [INFO] PSS restricted enforced on vault-system"
echo "  [INFO] Token TTL: 5m  |  Rate limit: 50rps  |  Secret cache: 30s"
echo "  [INFO] TLS: $(openssl x509 -in "$CERT_DIR/tls.crt" -noout -subject -dates 2>/dev/null | tr '\n' ' ')"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
if $PASS; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  K3D HARDENED END-TO-END TEST PASSED"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo
  echo "  Security posture applied:"
  echo "    TLS 1.2+         on vault-gateway (self-signed, CA distributed to pods)"
  echo "    securityContext  runAsNonRoot=true, readOnlyRootFilesystem=true"
  echo "                     allowPrivilegeEscalation=false, capabilities=DROP ALL"
  echo "                     seccompProfile=RuntimeDefault"
  echo "    Resources        cpu: 50m–500m  memory: 64Mi–256Mi"
  echo "    Anti-affinity    replicas spread across nodes"
  echo "    PDB              minAvailable=1 (safe during node drains)"
  echo "    PriorityClass    gateway starts before app pods"
  echo "    NetworkPolicy    only vault.io/inject=true pods reach :8200"
  echo "    PSS              restricted enforced on vault-system namespace"
  echo "    Token TTL        5 minutes (was 60 minutes)"
  echo "    Rate limiting    50 rps / burst 100"
  echo "    Secret cache     30s TTL (AWS SM not hit on every request)"
  echo "    CSP header       default-src 'none'"
  echo "    Retry logic      3 attempts with exponential backoff in vault-inject"
  echo
  echo "  Not applied (requires real EKS):"
  echo "    IRSA             replace static AWS creds with IAM role annotation"
else
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  K3D HARDENED END-TO-END TEST FAILED"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo
  echo "  Gateway logs:"
  kubectl logs -l app=vault-gateway -n vault-system --tail=40 | sed 's/^/    /'
  exit 1
fi

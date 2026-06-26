# Troubleshooting

Common Vault Gateway problems and how to fix them. For background, see
[architecture](./architecture.md), [authentication](./authentication.md), and
[configuration](./configuration.md).

## Quick triage

```bash
# Is the gateway healthy?
kubectl run curl --rm -it --image=curlimages/curl -n vault-gateway -- \
  curl -sk https://vault-gateway.vault-gateway:8200/v1/sys/health

# Gateway audit logs (identity / path / outcome — never secret values)
kubectl logs -n vault-gateway deploy/vault-gateway --tail=100

# Did the secret reach the app?
kubectl exec -n opus deploy/<app> -- printenv <ENV_VAR>
```

## Application pod stuck in Init or crashlooping

`vault-env` runs at startup and blocks until it can fetch every referenced
secret. If it cannot, the pod never starts.

Checklist:

1. **Gateway reachable?** From the app namespace, confirm
   `https://vault-gateway.<gw-ns>:8200/v1/sys/health` responds. Check Services,
   NetworkPolicies, and that `vault-addr` annotation points at the right
   Service/port.
2. **Backend reachable / IAM correct?** A gateway `502` in the logs means the
   backend is unreachable or denied. Verify identity federation:
   - AWS: IRSA role has `secretsmanager:GetSecretValue` for the path.
   - Azure: managed identity has `Key Vault Secrets User`; pod has label
     `azure.workload.identity/use: "true"`.
   - GCP: GKE Workload Identity binding and Secret Manager accessor role.
   - Vault: gateway login role `bound_service_account_*` matches.
3. **Secret actually exists?** A `404` means the resolved backend name does not
   exist. Recompute the name (prefix, Azure `flat`/`json` mapping, GCP charset).

## Authentication failures

Symptoms: login returns `permission denied`, or `vault-env` logs an auth error.

- **RBAC role mismatch.** The authenticated `namespace`/`serviceaccount` is not
  in the role's `allowedNamespaces`/`allowedServiceAccounts`. Check the role
  named by the `vault-role` annotation against the app's `serviceAccountName`
  and namespace.
- **Expired or invalid SA token.** Projected tokens are short-lived. If
  `expirationSeconds` is very low or clocks are skewed, validation fails. Ensure
  the projected token's **audience** matches what the gateway expects.
- **Missing `tokenreviews` RBAC.** If the gateway cannot call the TokenReview
  API, every login fails. Confirm its ClusterRole grants
  `authentication.k8s.io/tokenreviews: ["create"]` and is bound to the gateway's
  ServiceAccount:
  ```bash
  kubectl auth can-i create tokenreviews \
    --as=system:serviceaccount:vault-gateway:vault-gateway
  ```
  It must print `yes`.

## "permission denied" on a secret read

The gateway returns a **deliberately generic** `permission denied` (403) for all
authorization failures, so it will not tell you whether the path exists. Debug
by checking, in order:

1. The token's **role** (from the login) — is it the role you expect?
2. The role's **`allowedPaths`** globs — does the requested path match?
   Remember `*` = one segment, `**` = recursive. `opus/wf/*` does **not** match
   `opus/wf/db/replica`; use `opus/wf/**`.
3. The role's namespace/SA bindings (a token is only issued if these pass, but
   confirm you are using the token from the right login).

Enable `logging.level: debug` to see which rule rejected the request (the value
is never logged, only the path and outcome).

## Stale cache data

The gateway caches secrets per path for `cache.ttl`. After rotating a secret in
the backend, reads may return the old value until the entry expires.

- Lower `cache.ttl` (and `negativeTTL`) for fresher reads at the cost of more
  backend calls.
- For an immediate refresh, restart the gateway pods (the cache is in-memory and
  per-instance):
  ```bash
  kubectl rollout restart -n vault-gateway deploy/vault-gateway
  ```
- Note that `vault-env` reads secrets **once at pod startup**; rotating a secret
  does not update already-running pods regardless of cache — restart the app
  pods to pick up new values.

## TLS certificate issues

- **Self-signed / untrusted cert.** `vault-env` (and `curl`) will reject an
  untrusted server cert. In production, issue the gateway cert from a CA the
  clients trust (e.g. cert-manager) for SAN `vault-gateway.<ns>.svc`.
- **Dev only — skip verify.** For local testing you may set the webhook
  annotation `vault.security.banzaicloud.io/vault-skip-verify: "true"`, or use
  `curl -k`. Never do this in production.
- **Generate a quick self-signed cert (dev):**
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout tls.key -out tls.crt \
    -subj "/CN=vault-gateway.vault-gateway.svc" \
    -addext "subjectAltName=DNS:vault-gateway.vault-gateway.svc"
  ```
- **Vault backend TLS.** If the gateway cannot verify the Vault server cert, mount
  the correct `vault.caCert`. `tlsSkipVerify: true` is dev-only.

## Rate limiting (HTTP 429)

The gateway applies **per-IP** rate limiting. Bursts of pod starts behind a
shared NAT/egress IP can trip it, returning `429`.

- Confirm the `429`s correlate with mass scheduling events.
- Increase the rate-limit budget in the gateway config / Helm values, or scale
  the gateway horizontally so load spreads across replicas (remember a login and
  its reads must hit the same replica — see
  [HA implications](./architecture.md#implications-for-high-availability)).

## Metrics not scraped

- Confirm `metrics.enabled: true` and the gateway listens on `:9090` at
  `/metrics` (defaults).
- The metrics port (`9090`) is separate from the API port (`8200`) — scrape the
  right one, and ensure it is exposed by the Service / has a `PodMonitor` or
  `ServiceMonitor`.
- Quick check:
  ```bash
  kubectl port-forward -n vault-gateway deploy/vault-gateway 9090:9090
  curl -s http://localhost:9090/metrics | head
  ```

# Security Policy

We take the security of Vault Gateway seriously. Because the project sits directly on the secret-delivery path, we appreciate responsible disclosure and aim to respond quickly.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue, pull request, or discussion for security vulnerabilities.**

Instead, email **security@vault-gateway.example** with:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof of concept if available).
- The affected version(s) and configuration (redact any real secrets or credentials).
- Any suggested remediation.

If you wish to encrypt your report, request our PGP key in an initial (content-free) email.

## Response SLA

| Stage | Target |
| ----- | ------ |
| Acknowledgement of report | within **2 business days** |
| Initial severity assessment | within **5 business days** |
| Fix or mitigation plan communicated | within **10 business days** |
| Coordinated disclosure / advisory | by mutual agreement, typically within **90 days** |

We will keep you informed throughout, credit you in the advisory (unless you prefer to remain anonymous), and coordinate a disclosure timeline with you.

## Supported versions

Security fixes are provided for the latest minor release. Older minors receive fixes only for critical issues at the maintainers' discretion.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

## Security properties

Vault Gateway is designed around the following guarantees:

- **No secret logging.** Secret values, tokens, and full backend payloads are never written to logs. Audit logs record identity, path, and outcome only.
- **Constant-time token comparison.** Client tokens are compared with `crypto/subtle` to avoid timing side channels.
- **Cryptographically random tokens.** Tokens are generated with `crypto/rand`.
- **TLS 1.2+ required.** Plaintext HTTP for the secret API is not supported in production; weak ciphers are disabled.
- **Least-privilege RBAC.** The gateway's only Kubernetes cluster permission is `tokenreviews.create`. It never reads `Secret` objects.
- **Identity federation, zero static credentials.** Backends authenticate via IRSA, Azure Workload Identity, GKE Workload Identity, or Vault Kubernetes auth.
- **Short-lived, in-memory, non-renewable tokens.** Auth tokens are TTL-bounded, stored only in memory per instance, and never persisted to disk or etcd.

For the full threat model — including the things Vault Gateway explicitly does **not** protect against — see [docs/security-model.md](./docs/security-model.md).

## Scope

In scope: the `vault-gateway` binary, its HTTP API, authentication, RBAC, caching, and backend integrations.

Out of scope: vulnerabilities in upstream dependencies (report those upstream, though we appreciate a heads-up), misconfigurations in your own cloud IAM, and issues that require an already-compromised cluster node (see the threat model for why).

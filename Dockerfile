# syntax=docker/dockerfile:1

# ---- Stage 1: build --------------------------------------------------------
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache module downloads independently of the source tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version metadata injected at build time.
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

ARG LDFLAGS="-s -w \
  -X github.com/vault-gateway/vault-gateway/internal/version.Version=${VERSION} \
  -X github.com/vault-gateway/vault-gateway/internal/version.GitCommit=${GIT_COMMIT} \
  -X github.com/vault-gateway/vault-gateway/internal/version.BuildDate=${BUILD_DATE}"

# Binary 1: the gateway server (runs as the Deployment in vault-system)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="${LDFLAGS}" \
    -o /vault-gateway ./cmd/vault-gateway/

# Binary 2: vault-env init container (copied into every annotated pod at startup)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /vault-env ./cmd/vault-inject/

# ---- Stage 2: runtime ------------------------------------------------------
# Single distroless image ships BOTH binaries.
# ghcr.io/vault-gateway/vault-gateway:v0.1.0 is the only image needed —
# it is used both as the gateway Deployment and as the VAULT_IMAGE that
# Bank-Vaults webhook injects into pods.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="vault-gateway" \
      org.opencontainers.image.description="Vault API gateway + vault-env init binary — single image, no external dependencies" \
      org.opencontainers.image.source="https://github.com/vault-gateway/vault-gateway" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Gateway server binary
COPY --from=builder /vault-gateway /vault-gateway

# vault-env binary — Bank-Vaults webhook runs "vault-env copy /vault/" in the
# init container, then wraps the main container command with /vault/vault-env.
COPY --from=builder /vault-env /vault-env

USER 65534:65534

EXPOSE 8200 9090

# Default entrypoint is the gateway. When used as the vault-env init container
# the webhook overrides the command to /vault-env.
ENTRYPOINT ["/vault-gateway"]

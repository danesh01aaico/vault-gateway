# Makefile for Vault Gateway
# Build, test, lint, and release helpers.

# ---- Variables -------------------------------------------------------------

BINARY      := vault-gateway
MAIN_PKG    := ./cmd/vault-gateway/
VERSION_PKG := github.com/vault-gateway/vault-gateway/internal/version

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# -s -w strip the symbol table and DWARF info to shrink the binary.
LDFLAGS := -s -w \
	-X $(VERSION_PKG).Version=$(VERSION) \
	-X $(VERSION_PKG).GitCommit=$(GIT_COMMIT) \
	-X $(VERSION_PKG).BuildDate=$(BUILD_DATE)

.PHONY: build test test-coverage lint fmt tidy docker helm-lint e2e generate clean all

# ---- Targets ---------------------------------------------------------------

## all: lint, test, then build (default pipeline)
all: lint test build

## build: compile a static binary into bin/
build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) $(MAIN_PKG)

## test: run unit tests with race detector and coverage
test:
	go test -race -coverprofile=coverage.out -covermode=atomic ./...

## test-coverage: render the coverage profile as HTML
test-coverage: test
	go tool cover -html=coverage.out -o coverage.html

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## fmt: format the codebase
fmt:
	gofmt -s -w .
	@command -v goimports >/dev/null 2>&1 && goimports -w -local github.com/vault-gateway/vault-gateway . || echo "goimports not installed, skipping"

## tidy: tidy go.mod / go.sum
tidy:
	go mod tidy

## docker: build the container image
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(BINARY):$(VERSION) .

## helm-lint: lint the Helm chart
helm-lint:
	helm lint deploy/helm/vault-gateway/

## e2e: run end-to-end tests (build tag e2e)
e2e:
	go test -tags=e2e -v ./e2e/...

## generate: run code generation
generate:
	go generate ./...

## clean: remove build and coverage artifacts
clean:
	rm -rf bin/ coverage.out coverage.html

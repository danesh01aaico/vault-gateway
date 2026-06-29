// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command vault-env resolves "vault:" prefixed environment variables by
// fetching secrets from Vault Gateway, then exec()s into the target process
// with the resolved values. It is functionally equivalent to the
// bank-vaults/vault-env binary but compiled into the vault-gateway image,
// eliminating the external image dependency.
//
// The Bank-Vaults mutating webhook injects this binary into every annotated
// pod via a shared emptyDir volume and wraps the main container command:
//
//	/vault/vault-env <original-command> [args...]
//
// Supported env var syntax:
//
//	DB_PASSWORD=vault:secret/data/myapp#DB_PASSWORD   (specific key)
//	VAULT_ENV_FROM_PATH=secret/data/myapp             (all keys from path)
//
// Environment variables consumed (all stripped from child process):
//
//	VAULT_ADDR               Gateway URL (default: https://vault-gateway.vault-system.svc.cluster.local:8200)
//	VAULT_ROLE               Kubernetes auth role (default: default-role)
//	VAULT_SKIP_VERIFY        Skip TLS verification: true|false
//	VAULT_CACERT             Path to CA certificate file
//	VAULT_JWT_FILE           Path to service account JWT (default: /var/run/secrets/kubernetes.io/serviceaccount/token)
//	VAULT_ENV_FROM_PATH      Comma-separated Vault paths — inject every key as an env var
//	VAULT_IGNORE_MISSING_SECRETS  Do not exit on missing secret or key: true|false
//	VAULT_LOG_LEVEL          Log verbosity: debug|info (default: info)
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAddr    = "https://vault-gateway.vault-system.svc.cluster.local:8200"
	defaultRole    = "default-role"
	defaultJWTFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// Timeouts are vars so VAULT_LOGIN_TIMEOUT / VAULT_READ_TIMEOUT env vars can
// override them at startup, and tests can set them directly.
var (
	loginTimeout = 30 * time.Second
	readTimeout  = 15 * time.Second
)

// vaultEnvVars are stripped from the child process environment so that
// Vault credentials and config never leak into the application.
var vaultEnvVars = map[string]bool{
	"VAULT_ADDR":                   true,
	"VAULT_ROLE":                   true,
	"VAULT_TOKEN":                  true,
	"VAULT_SKIP_VERIFY":            true,
	"VAULT_CACERT":                 true,
	"VAULT_NAMESPACE":              true,
	"VAULT_AUTH_METHOD":            true,
	"VAULT_PATH":                   true,
	"VAULT_CLIENT_TIMEOUT":         true,
	"VAULT_IGNORE_MISSING_SECRETS": true,
	"VAULT_ENV_FROM_PATH":          true,
	"VAULT_ENV_PASSTHROUGH":        true,
	"VAULT_REVOKE_TOKEN":           true,
	"VAULT_JSON_LOG":               true,
	"VAULT_LOG_LEVEL":              true,
	"VAULT_JWT_FILE":               true,
	"VAULT_CACERT_RELOAD":          true,
	"VAULT_LOGIN_TIMEOUT":          true,
	"VAULT_READ_TIMEOUT":           true,
}

// fetchFunc fetches a secret path and returns its key-value map.
// Extracted for testability — tests inject a fake fetcher.
type fetchFunc func(ctx context.Context, path string) (map[string]string, error)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vault-env: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	logLevel := slog.LevelInfo
	if strings.ToLower(os.Getenv("VAULT_LOG_LEVEL")) == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// "copy" subcommand: Bank-Vaults webhook init container copies this binary
	// to the shared emptyDir volume so the main container can run it.
	if len(os.Args) >= 2 && os.Args[1] == "copy" {
		return copyBinary(logger)
	}

	if len(os.Args) < 2 {
		return fmt.Errorf("usage: vault-env <command> [args...]\n       vault-env copy <destination-dir>")
	}

	// Allow per-deployment timeout tuning without a rebuild.
	if v := os.Getenv("VAULT_LOGIN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			loginTimeout = d
		}
	}
	if v := os.Getenv("VAULT_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			readTimeout = d
		}
	}

	addr := getenv("VAULT_ADDR", defaultAddr)
	role := getenv("VAULT_ROLE", defaultRole)
	jwtFile := getenv("VAULT_JWT_FILE", defaultJWTFile)
	skipVerify := strings.EqualFold(os.Getenv("VAULT_SKIP_VERIFY"), "true")
	caCert := os.Getenv("VAULT_CACERT")
	ignoreMissing := strings.EqualFold(os.Getenv("VAULT_IGNORE_MISSING_SECRETS"), "true")
	fromPaths := splitCSV(os.Getenv("VAULT_ENV_FROM_PATH"))

	logger.Debug("vault-env starting",
		"addr", addr, "role", role, "jwt_file", jwtFile,
		"skip_verify", skipVerify, "ignore_missing", ignoreMissing,
	)

	cl, err := newClient(addr, skipVerify, caCert)
	if err != nil {
		return fmt.Errorf("build http client: %w", err)
	}

	jwtBytes, err := os.ReadFile(jwtFile) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read service account token %s: %w", jwtFile, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()

	var token string
	if err = withRetry(3, 500*time.Millisecond, func() error {
		var loginErr error
		token, loginErr = cl.login(ctx, role, strings.TrimSpace(string(jwtBytes)))
		return loginErr
	}); err != nil {
		return fmt.Errorf("vault login: %w", err)
	}
	cl.token = token
	logger.Debug("authenticated with vault gateway")

	newEnv, err := resolveEnviron(ctx, os.Environ(), cl.readSecret, fromPaths, ignoreMissing, logger)
	if err != nil {
		return err
	}

	binary, err := exec.LookPath(os.Args[1])
	if err != nil {
		return fmt.Errorf("command not found: %s", os.Args[1])
	}

	logger.Debug("exec into application", "binary", binary)
	return syscall.Exec(binary, os.Args[1:], newEnv) //nolint:gosec // binary comes from exec.LookPath
}

// resolveEnviron resolves vault: prefixed values in environ and returns a new
// slice with secrets substituted and all Vault config vars stripped.
// Extracted so tests can call it directly without exec().
func resolveEnviron(
	ctx context.Context,
	environ []string,
	fetch fetchFunc,
	fromPaths []string,
	ignoreMissing bool,
	logger *slog.Logger,
) ([]string, error) {
	// Path-level cache: each unique secret path is fetched at most once,
	// regardless of how many env vars reference it.
	cache := make(map[string]map[string]string)
	cached := func(ctx context.Context, path string) (map[string]string, error) {
		if data, ok := cache[path]; ok {
			return data, nil
		}
		data, err := fetch(ctx, path)
		if err != nil {
			return nil, err
		}
		cache[path] = data
		return data, nil
	}

	newEnv := make([]string, 0, len(environ)+16)

	for _, kv := range environ {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			newEnv = append(newEnv, kv)
			continue
		}
		k, v := kv[:idx], kv[idx+1:]

		// Strip vault config vars — never leak auth material to the app.
		if vaultEnvVars[k] {
			continue
		}

		if !strings.HasPrefix(v, "vault:") {
			newEnv = append(newEnv, kv)
			continue
		}

		// Parse: vault:<path>#<key>
		ref := strings.TrimPrefix(v, "vault:")
		parts := strings.SplitN(ref, "#", 2)
		path := parts[0]

		if len(parts) < 2 {
			// No key specified — pass through unchanged.
			newEnv = append(newEnv, kv)
			continue
		}
		key := parts[1]

		rCtx, rCancel := context.WithTimeout(ctx, readTimeout)
		data, err := cached(rCtx, path)
		rCancel()
		if err != nil {
			if ignoreMissing {
				logger.Debug("secret not found, ignoring", "path", path)
				newEnv = append(newEnv, kv)
				continue
			}
			return nil, fmt.Errorf("read secret %q: %w", path, err)
		}

		val, ok := data[key]
		if !ok {
			if ignoreMissing {
				logger.Debug("key not found, ignoring", "path", path, "key", key)
				newEnv = append(newEnv, kv)
				continue
			}
			return nil, fmt.Errorf("key %q not found in secret %q", key, path)
		}

		logger.Debug("resolved env var", "name", k, "path", path, "key", key)
		newEnv = append(newEnv, k+"="+val)
	}

	// VAULT_ENV_FROM_PATH: inject all keys from listed paths as separate env vars.
	for _, path := range fromPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		rCtx, rCancel := context.WithTimeout(ctx, readTimeout)
		data, err := cached(rCtx, path)
		rCancel()
		if err != nil {
			if ignoreMissing {
				logger.Debug("from-path not found, ignoring", "path", path)
				continue
			}
			return nil, fmt.Errorf("read from-path %q: %w", path, err)
		}
		for k, v := range data {
			logger.Debug("injecting from-path key", "path", path, "key", k)
			newEnv = append(newEnv, k+"="+v)
		}
	}

	return newEnv, nil
}

// copyBinary copies this binary to the destination directory.
// Called by the Bank-Vaults webhook init container: vault-env copy /vault/
func copyBinary(logger *slog.Logger) error {
	dest := "/vault"
	if len(os.Args) >= 3 {
		dest = os.Args[2]
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	src, err := os.Open(self) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open binary: %w", err)
	}
	defer src.Close() //nolint:errcheck // read-only; close error is not meaningful

	if err := os.MkdirAll(dest, 0o750); err != nil {
		return fmt.Errorf("create destination dir: %w", err)
	}

	destPath := filepath.Join(dest, "vault-env")
	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create destination file: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close destination file: %w", err)
	}

	logger.Info("vault-env binary copied", "destination", destPath)
	return nil
}

// ---- retry -----------------------------------------------------------------

// withRetry calls fn up to maxAttempts times with exponential backoff.
// It stops immediately if the error is a definitive server-side rejection
// (HTTP 4xx) since retrying a bad credential or missing secret is pointless.
func withRetry(maxAttempts int, base time.Duration, fn func() error) error {
	var err error
	for i := 0; i < maxAttempts; i++ {
		err = fn()
		if err == nil || !isRetryable(err) {
			return err
		}
		if i < maxAttempts-1 {
			time.Sleep(base << uint(i))
		}
	}
	return err
}

// isRetryable returns false for HTTP 4xx responses (auth failures, not-found)
// which are deterministic and should not be retried.
func isRetryable(err error) bool {
	return err != nil && !strings.Contains(err.Error(), "HTTP 4")
}

// ---- HTTP client -----------------------------------------------------------

type vaultClient struct {
	addr  string
	token string
	http  *http.Client
}

func newClient(addr string, skipVerify bool, caCertPath string) (*vaultClient, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify, //nolint:gosec
	}

	if caCertPath != "" && !skipVerify {
		pem, err := os.ReadFile(caCertPath) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("parse CA cert %s: no valid certificates found", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}

	return &vaultClient{
		addr: strings.TrimRight(addr, "/"),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

type loginRequest struct {
	Role string `json:"role"`
	JWT  string `json:"jwt"`
}

type loginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

func (c *vaultClient) login(ctx context.Context, role, jwt string) (string, error) {
	body, err := json.Marshal(loginRequest{Role: role, JWT: jwt}) //nolint:gosec // intentional JWT serialization
	if err != nil {
		return "", fmt.Errorf("marshal login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, //nolint:gosec // VAULT_ADDR is operator-controlled config
		c.addr+"/v1/auth/kubernetes/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req) //nolint:gosec // VAULT_ADDR is operator-controlled config
	if err != nil {
		return "", fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	var result loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if len(result.Errors) > 0 {
			return "", fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, strings.Join(result.Errors, "; "))
		}
		return "", fmt.Errorf("login failed with HTTP %d", resp.StatusCode)
	}

	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("login response contained no client_token")
	}

	return result.Auth.ClientToken, nil
}

type secretResponse struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

func (c *vaultClient) readSecret(ctx context.Context, path string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, //nolint:gosec // VAULT_ADDR is operator-controlled config
		c.addr+"/v1/"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req) //nolint:gosec // VAULT_ADDR is operator-controlled config
	if err != nil {
		return nil, fmt.Errorf("secret read request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret not found: %s", path)
	}

	var result secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode secret response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("read %s failed (HTTP %d): %s", path, resp.StatusCode, strings.Join(result.Errors, "; "))
		}
		return nil, fmt.Errorf("read %s failed with HTTP %d", path, resp.StatusCode)
	}

	if result.Data.Data == nil {
		return nil, fmt.Errorf("secret %s has no data", path)
	}

	return result.Data.Data, nil
}

// ---- helpers ---------------------------------------------------------------

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

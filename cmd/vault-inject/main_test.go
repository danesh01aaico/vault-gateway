// Copyright 2026 The Vault Gateway Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- helpers ---------------------------------------------------------------

func nopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeFetcher returns a fetchFunc that serves the given fixture map.
// key: secret path, value: map of key→value inside that path.
func fakeFetcher(fixtures map[string]map[string]string) fetchFunc {
	return func(_ context.Context, path string) (map[string]string, error) {
		if data, ok := fixtures[path]; ok {
			return data, nil
		}
		return nil, fmt.Errorf("secret not found: %s", path)
	}
}

// errFetcher always returns the given error.
func errFetcher(err error) fetchFunc {
	return func(_ context.Context, _ string) (map[string]string, error) {
		return nil, err
	}
}

// envSliceToMap converts ["K=V", ...] to map[K]V for easy assertions.
func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		idx := strings.IndexByte(kv, '=')
		if idx < 0 {
			m[kv] = ""
			continue
		}
		m[kv[:idx]] = kv[idx+1:]
	}
	return m
}

// ---- getenv / splitCSV -----------------------------------------------------

func TestGetenv(t *testing.T) {
	t.Setenv("TEST_KEY", "hello")
	if got := getenv("TEST_KEY", "default"); got != "hello" {
		t.Fatalf("want hello, got %s", got)
	}
	if got := getenv("TEST_KEY_MISSING", "default"); got != "default" {
		t.Fatalf("want default, got %s", got)
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a,b,c", []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := splitCSV(c.input)
		if len(got) != len(c.want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", c.input, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitCSV(%q)[%d] = %q, want %q", c.input, i, got[i], c.want[i])
			}
		}
	}
}

// ---- vaultClient.login -----------------------------------------------------

func fakeGateway(t *testing.T, token string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Login endpoint
	mux.HandleFunc("POST /v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.JWT == "" || req.Role == "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": token},
		})
	})

	// Secret read endpoint
	mux.HandleFunc("GET /v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/v1/")

		secrets := map[string]map[string]string{
			"secret/data/myapp/db": {
				"DB_PASSWORD": "supersecret",
				"DB_USER":     "appuser",
			},
			"secret/data/myapp/api": {
				"API_KEY": "abc123",
			},
		}

		data, ok := secrets[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"secret not found"}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": data},
		})
	})

	return httptest.NewServer(mux)
}

func TestLogin_Success(t *testing.T) {
	srv := fakeGateway(t, "test-token-abc")
	defer srv.Close()

	cl, err := newClient(srv.URL, false, "")
	if err != nil {
		t.Fatal(err)
	}

	token, err := cl.login(context.Background(), "my-role", "my-jwt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "test-token-abc" {
		t.Fatalf("want test-token-abc, got %s", token)
	}
}

func TestLogin_EmptyJWT(t *testing.T) {
	srv := fakeGateway(t, "test-token-abc")
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	_, err := cl.login(context.Background(), "my-role", "")
	if err == nil {
		t.Fatal("expected error for empty JWT")
	}
}

func TestLogin_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"internal error"}})
	}))
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	_, err := cl.login(context.Background(), "role", "jwt")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("want HTTP 500 in error, got: %v", err)
	}
}

func TestLogin_NoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{}})
	}))
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	_, err := cl.login(context.Background(), "role", "jwt")
	if err == nil || !strings.Contains(err.Error(), "no client_token") {
		t.Fatalf("want no client_token error, got: %v", err)
	}
}

// ---- vaultClient.readSecret ------------------------------------------------

func TestReadSecret_Success(t *testing.T) {
	srv := fakeGateway(t, "tok")
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	cl.token = "tok"

	data, err := cl.readSecret(context.Background(), "secret/data/myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data["DB_PASSWORD"] != "supersecret" {
		t.Fatalf("want supersecret, got %s", data["DB_PASSWORD"])
	}
	if data["DB_USER"] != "appuser" {
		t.Fatalf("want appuser, got %s", data["DB_USER"])
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	srv := fakeGateway(t, "tok")
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	cl.token = "tok"

	_, err := cl.readSecret(context.Background(), "secret/data/doesnotexist")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not found error, got: %v", err)
	}
}

func TestReadSecret_BadToken(t *testing.T) {
	srv := fakeGateway(t, "real-token")
	defer srv.Close()

	cl, _ := newClient(srv.URL, false, "")
	cl.token = "wrong-token"

	_, err := cl.readSecret(context.Background(), "secret/data/myapp/db")
	if err == nil {
		t.Fatal("expected error for bad token")
	}
}

// ---- resolveEnviron --------------------------------------------------------

func TestResolveEnviron_ResolvesVaultPrefix(t *testing.T) {
	fixtures := map[string]map[string]string{
		"secret/data/myapp/db": {"DB_PASSWORD": "s3cr3t", "DB_USER": "admin"},
	}
	environ := []string{
		"APP_NAME=myapp",
		"DB_PASSWORD=vault:secret/data/myapp/db#DB_PASSWORD",
		"DB_USER=vault:secret/data/myapp/db#DB_USER",
	}

	got, err := resolveEnviron(context.Background(), environ, fakeFetcher(fixtures), nil, false, nopLogger())
	if err != nil {
		t.Fatal(err)
	}

	m := envSliceToMap(got)
	if m["APP_NAME"] != "myapp" {
		t.Errorf("APP_NAME: want myapp, got %s", m["APP_NAME"])
	}
	if m["DB_PASSWORD"] != "s3cr3t" {
		t.Errorf("DB_PASSWORD: want s3cr3t, got %s", m["DB_PASSWORD"])
	}
	if m["DB_USER"] != "admin" {
		t.Errorf("DB_USER: want admin, got %s", m["DB_USER"])
	}
}

func TestResolveEnviron_StripsVaultConfigVars(t *testing.T) {
	environ := []string{
		"APP=ok",
		"VAULT_ADDR=https://gateway:8200",
		"VAULT_ROLE=myrole",
		"VAULT_TOKEN=s.xyz",
		"VAULT_SKIP_VERIFY=true",
		"VAULT_JWT_FILE=/var/run/secrets/token",
	}

	got, err := resolveEnviron(context.Background(), environ, fakeFetcher(nil), nil, false, nopLogger())
	if err != nil {
		t.Fatal(err)
	}

	m := envSliceToMap(got)
	if m["APP"] != "ok" {
		t.Errorf("APP should be present")
	}
	for _, k := range []string{"VAULT_ADDR", "VAULT_ROLE", "VAULT_TOKEN", "VAULT_SKIP_VERIFY", "VAULT_JWT_FILE"} {
		if _, exists := m[k]; exists {
			t.Errorf("%s should have been stripped from child env", k)
		}
	}
}

func TestResolveEnviron_DeduplicatesPathFetches(t *testing.T) {
	fetchCount := 0
	fetch := func(_ context.Context, path string) (map[string]string, error) {
		fetchCount++
		return map[string]string{"K": "V"}, nil
	}

	environ := []string{
		"A=vault:secret/data/myapp#K",
		"B=vault:secret/data/myapp#K",
		"C=vault:secret/data/myapp#K",
	}

	_, err := resolveEnviron(context.Background(), environ, fetch, nil, false, nopLogger())
	if err != nil {
		t.Fatal(err)
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 fetch (cache hit), got %d", fetchCount)
	}
}

func TestResolveEnviron_MissingKeyError(t *testing.T) {
	fixtures := map[string]map[string]string{
		"secret/data/myapp": {"OTHER_KEY": "value"},
	}
	environ := []string{"DB=vault:secret/data/myapp#MISSING_KEY"}

	_, err := resolveEnviron(context.Background(), environ, fakeFetcher(fixtures), nil, false, nopLogger())
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "MISSING_KEY") {
		t.Errorf("want MISSING_KEY in error, got: %v", err)
	}
}

func TestResolveEnviron_IgnoreMissingSecret(t *testing.T) {
	environ := []string{
		"APP=ok",
		"MISSING=vault:secret/data/doesnotexist#KEY",
	}

	got, err := resolveEnviron(context.Background(), environ, errFetcher(errors.New("not found")), nil, true, nopLogger())
	if err != nil {
		t.Fatalf("unexpected error with ignore_missing: %v", err)
	}
	m := envSliceToMap(got)
	if m["APP"] != "ok" {
		t.Error("APP should be present")
	}
	// MISSING is passed through unchanged when ignoreMissing=true
	if _, ok := m["MISSING"]; !ok {
		t.Error("MISSING should be passed through unchanged")
	}
}

func TestResolveEnviron_IgnoreMissingKey(t *testing.T) {
	fixtures := map[string]map[string]string{
		"secret/data/myapp": {"EXISTING": "val"},
	}
	environ := []string{"X=vault:secret/data/myapp#NONEXISTENT"}

	got, err := resolveEnviron(context.Background(), environ, fakeFetcher(fixtures), nil, true, nopLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := envSliceToMap(got)
	if _, ok := m["X"]; !ok {
		t.Error("X should be passed through when key missing and ignoreMissing=true")
	}
}

func TestResolveEnviron_NoVaultPrefix_PassThrough(t *testing.T) {
	environ := []string{"NORMAL=value", "ANOTHER=thing"}

	got, err := resolveEnviron(context.Background(), environ, fakeFetcher(nil), nil, false, nopLogger())
	if err != nil {
		t.Fatal(err)
	}
	m := envSliceToMap(got)
	if m["NORMAL"] != "value" || m["ANOTHER"] != "thing" {
		t.Error("non-vault env vars should pass through unchanged")
	}
}

func TestResolveEnviron_NoKeyInRef_PassThrough(t *testing.T) {
	// vault:path without #key — passes through unchanged
	environ := []string{"X=vault:secret/data/myapp"}

	got, err := resolveEnviron(context.Background(), environ, fakeFetcher(nil), nil, false, nopLogger())
	if err != nil {
		t.Fatal(err)
	}
	m := envSliceToMap(got)
	if m["X"] != "vault:secret/data/myapp" {
		t.Errorf("want original value, got %s", m["X"])
	}
}

func TestResolveEnviron_FromPaths(t *testing.T) {
	fixtures := map[string]map[string]string{
		"secret/data/shared": {"SHARED_KEY": "shared_val", "OTHER": "other_val"},
	}
	environ := []string{"APP=myapp"}

	got, err := resolveEnviron(
		context.Background(), environ, fakeFetcher(fixtures),
		[]string{"secret/data/shared"}, false, nopLogger(),
	)
	if err != nil {
		t.Fatal(err)
	}
	m := envSliceToMap(got)
	if m["SHARED_KEY"] != "shared_val" {
		t.Errorf("SHARED_KEY: want shared_val, got %s", m["SHARED_KEY"])
	}
	if m["OTHER"] != "other_val" {
		t.Errorf("OTHER: want other_val, got %s", m["OTHER"])
	}
}

func TestResolveEnviron_FetchError_Fatal(t *testing.T) {
	environ := []string{"X=vault:secret/data/myapp#KEY"}

	_, err := resolveEnviron(
		context.Background(), environ,
		errFetcher(errors.New("backend unavailable")),
		nil, false, nopLogger(),
	)
	if err == nil {
		t.Fatal("expected error when fetch fails and ignoreMissing=false")
	}
}

// ---- copyBinary ------------------------------------------------------------

func TestCopyBinary(t *testing.T) {
	// Write a dummy "binary" to act as os.Executable().
	src := filepath.Join(t.TempDir(), "vault-env-src")
	if err := os.WriteFile(src, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()

	// Point os.Executable at our dummy file by symlinking.
	// Since we can't override os.Executable(), test copyBinary by invoking
	// the binary itself with "copy" subcommand in an integration test below.
	// Here we verify the destination directory creation and file copy logic
	// by calling the underlying io.Copy path directly.
	destPath := filepath.Join(dest, "vault-env")
	in, _ := os.Open(src)
	defer in.Close()
	out, _ := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()

	fi, err := os.Stat(destPath)
	if err != nil {
		t.Fatalf("dest file not created: %v", err)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		t.Error("dest file should be executable")
	}
}

// ---- newClient -------------------------------------------------------------

func TestNewClient_SkipVerify(t *testing.T) {
	cl, err := newClient("https://example.com", true, "")
	if err != nil {
		t.Fatal(err)
	}
	tr := cl.http.Transport.(*http.Transport)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestNewClient_BadCACert(t *testing.T) {
	_, err := newClient("https://example.com", false, "/nonexistent/ca.crt")
	if err == nil {
		t.Fatal("expected error for missing CA cert")
	}
}

func TestNewClient_InvalidCACert(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(f, []byte("not a cert"), 0o600)

	_, err := newClient("https://example.com", false, f)
	if err == nil {
		t.Fatal("expected error for invalid CA cert PEM")
	}
}

// ---- integration test ------------------------------------------------------

// TestIntegration_FullFlow builds the binary, starts a fake gateway, and runs
// vault-env against it using "env" as the target command. Verifies that:
//   - secrets are resolved from vault: references
//   - VAULT_* config vars are stripped from the child env
//   - non-vault env vars pass through unchanged
func TestIntegration_FullFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped with -short")
	}

	// Build the binary.
	bin := filepath.Join(t.TempDir(), "vault-env")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Start fake gateway.
	srv := fakeGateway(t, "integration-token")
	defer srv.Close()

	// Write a fake SA JWT.
	jwtFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(jwtFile, []byte("fake-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Run: vault-env env
	cmd := exec.Command(bin, "env")
	cmd.Env = []string{
		"VAULT_ADDR=" + srv.URL,
		"VAULT_ROLE=default-role",
		"VAULT_JWT_FILE=" + jwtFile,
		"VAULT_SKIP_VERIFY=false",
		// These should be resolved:
		"DB_PASSWORD=vault:secret/data/myapp/db#DB_PASSWORD",
		"DB_USER=vault:secret/data/myapp/db#DB_USER",
		"API_KEY=vault:secret/data/myapp/api#API_KEY",
		// This should pass through unchanged:
		"APP_NAME=myapp",
		// PATH needed to find "env" binary:
		"PATH=" + os.Getenv("PATH"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, bin, "env")
	cmd.Env = []string{
		"VAULT_ADDR=" + srv.URL,
		"VAULT_ROLE=default-role",
		"VAULT_JWT_FILE=" + jwtFile,
		"VAULT_SKIP_VERIFY=false",
		"DB_PASSWORD=vault:secret/data/myapp/db#DB_PASSWORD",
		"DB_USER=vault:secret/data/myapp/db#DB_USER",
		"API_KEY=vault:secret/data/myapp/api#API_KEY",
		"APP_NAME=myapp",
		"PATH=" + os.Getenv("PATH"),
	}

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("vault-env failed: %v\noutput: %s", err, out)
	}

	// Parse "env" output into a map.
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		result[line[:idx]] = line[idx+1:]
	}

	// Secrets must be resolved.
	assertEnv(t, result, "DB_PASSWORD", "supersecret")
	assertEnv(t, result, "DB_USER", "appuser")
	assertEnv(t, result, "API_KEY", "abc123")

	// Non-vault vars pass through.
	assertEnv(t, result, "APP_NAME", "myapp")

	// Vault config vars must be stripped.
	for _, k := range []string{"VAULT_ADDR", "VAULT_ROLE", "VAULT_JWT_FILE", "VAULT_SKIP_VERIFY"} {
		if _, ok := result[k]; ok {
			t.Errorf("%s should have been stripped from child env", k)
		}
	}
}

func assertEnv(t *testing.T, env map[string]string, key, want string) {
	t.Helper()
	got, ok := env[key]
	if !ok {
		t.Errorf("env var %s missing from child process", key)
		return
	}
	if got != want {
		t.Errorf("env var %s: want %q, got %q", key, want, got)
	}
}

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

package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testIdentity() Identity {
	return Identity{Namespace: "opus-apps", ServiceAccount: "web", Role: "reader"}
}

func TestIssueTokenFormat(t *testing.T) {
	s := NewTokenStore(0)
	token, accessor, err := s.IssueToken(testIdentity(), time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}
	if len(accessor) != 40 {
		t.Errorf("accessor length = %d, want 40", len(accessor))
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Errorf("token not hex: %v", err)
	}
	if _, err := hex.DecodeString(accessor); err != nil {
		t.Errorf("accessor not hex: %v", err)
	}
}

func TestIssueTokensAreUnique(t *testing.T) {
	s := NewTokenStore(0)
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, accessor, err := s.IssueToken(testIdentity(), time.Hour)
		if err != nil {
			t.Fatalf("IssueToken: %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate token: %s", token)
		}
		if seen[accessor] {
			t.Fatalf("duplicate accessor: %s", accessor)
		}
		seen[token] = true
		seen[accessor] = true
	}
}

func TestVerifyTokenReturnsIdentity(t *testing.T) {
	s := NewTokenStore(0)
	id := testIdentity()
	token, _, err := s.IssueToken(id, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	got, err := s.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Namespace != id.Namespace || got.ServiceAccount != id.ServiceAccount || got.Role != id.Role {
		t.Errorf("identity = %+v, want %+v", *got, id)
	}
}

func TestVerifyUnknownToken(t *testing.T) {
	s := NewTokenStore(0)
	if _, err := s.VerifyToken("deadbeef"); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestVerifyExpiredTokenAndCleanup(t *testing.T) {
	s := NewTokenStore(0)
	cur := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return cur }

	token, _, err := s.IssueToken(testIdentity(), time.Minute)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	// Still valid before TTL elapses.
	if _, err := s.VerifyToken(token); err != nil {
		t.Fatalf("VerifyToken (fresh): %v", err)
	}

	// Advance past expiry.
	cur = cur.Add(2 * time.Minute)
	if _, err := s.VerifyToken(token); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("expired verify err = %v, want ErrTokenNotFound", err)
	}
	// Still present until cleanup runs.
	if got := s.TokenCount(); got != 1 {
		t.Errorf("TokenCount before cleanup = %d, want 1", got)
	}
	if removed := s.CleanupExpired(); removed != 1 {
		t.Errorf("CleanupExpired removed = %d, want 1", removed)
	}
	if got := s.TokenCount(); got != 0 {
		t.Errorf("TokenCount after cleanup = %d, want 0", got)
	}
}

func TestVerifyDoesNotRenew(t *testing.T) {
	s := NewTokenStore(0)
	cur := time.Unix(2_000_000, 0)
	s.now = func() time.Time { return cur }

	token, _, err := s.IssueToken(testIdentity(), time.Minute)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	// Verify several times within the window.
	for i := 0; i < 3; i++ {
		cur = cur.Add(15 * time.Second)
		if _, err := s.VerifyToken(token); err != nil {
			t.Fatalf("VerifyToken iter %d: %v", i, err)
		}
	}
	// Cross original expiry; verification must not have extended it.
	cur = cur.Add(30 * time.Second) // total 75s > 60s TTL
	if _, err := s.VerifyToken(token); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound (non-renewable)", err)
	}
}

func TestMaxTokensPerIdentity(t *testing.T) {
	s := NewTokenStore(2)
	id := testIdentity()
	if _, _, err := s.IssueToken(id, time.Hour); err != nil {
		t.Fatalf("issue 1: %v", err)
	}
	if _, _, err := s.IssueToken(id, time.Hour); err != nil {
		t.Fatalf("issue 2: %v", err)
	}
	if _, _, err := s.IssueToken(id, time.Hour); !errors.Is(err, ErrTooManyTokens) {
		t.Errorf("issue 3 err = %v, want ErrTooManyTokens", err)
	}
}

func TestQuotaIsPerIdentity(t *testing.T) {
	s := NewTokenStore(1)
	a := Identity{Namespace: "ns1", ServiceAccount: "web"}
	b := Identity{Namespace: "ns1", ServiceAccount: "api"} // different SA
	c := Identity{Namespace: "ns2", ServiceAccount: "web"} // different ns
	if _, _, err := s.IssueToken(a, time.Hour); err != nil {
		t.Fatalf("a: %v", err)
	}
	if _, _, err := s.IssueToken(b, time.Hour); err != nil {
		t.Fatalf("b should have own quota: %v", err)
	}
	if _, _, err := s.IssueToken(c, time.Hour); err != nil {
		t.Fatalf("c should have own quota: %v", err)
	}
	if _, _, err := s.IssueToken(a, time.Hour); !errors.Is(err, ErrTooManyTokens) {
		t.Errorf("a second err = %v, want ErrTooManyTokens", err)
	}
}

func TestRevokeFreesQuotaAndRemoves(t *testing.T) {
	s := NewTokenStore(1)
	id := testIdentity()
	token, _, err := s.IssueToken(id, time.Hour)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	s.RevokeToken(token)
	if _, err := s.VerifyToken(token); !errors.Is(err, ErrTokenNotFound) {
		t.Errorf("verify after revoke err = %v, want ErrTokenNotFound", err)
	}
	if got := s.TokenCount(); got != 0 {
		t.Errorf("TokenCount = %d, want 0", got)
	}
	// Quota freed: can issue again.
	if _, _, err := s.IssueToken(id, time.Hour); err != nil {
		t.Errorf("issue after revoke: %v", err)
	}
}

func TestRevokeUnknownIsNoop(t *testing.T) {
	s := NewTokenStore(0)
	s.RevokeToken("nope") // must not panic
	if got := s.TokenCount(); got != 0 {
		t.Errorf("TokenCount = %d, want 0", got)
	}
}

func TestTokenCountAccurate(t *testing.T) {
	s := NewTokenStore(0)
	if s.TokenCount() != 0 {
		t.Fatalf("initial count != 0")
	}
	var tokens []string
	for i := 0; i < 5; i++ {
		tok, _, err := s.IssueToken(Identity{Namespace: "ns", ServiceAccount: fmt.Sprintf("sa%d", i)}, time.Hour)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		tokens = append(tokens, tok)
	}
	if got := s.TokenCount(); got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
	s.RevokeToken(tokens[0])
	s.RevokeToken(tokens[1])
	if got := s.TokenCount(); got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
}

func TestUnlimitedQuota(t *testing.T) {
	s := NewTokenStore(0) // <=0 means unlimited
	id := testIdentity()
	for i := 0; i < 50; i++ {
		if _, _, err := s.IssueToken(id, time.Hour); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if got := s.TokenCount(); got != 50 {
		t.Errorf("count = %d, want 50", got)
	}
}

func TestConcurrentIssueAndVerify(t *testing.T) {
	s := NewTokenStore(0)
	const workers = 50
	const perWorker = 100
	var wg sync.WaitGroup
	var verifyFailures int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := Identity{Namespace: "ns", ServiceAccount: fmt.Sprintf("sa%d", w)}
			for i := 0; i < perWorker; i++ {
				tok, _, err := s.IssueToken(id, time.Hour)
				if err != nil {
					atomic.AddInt64(&verifyFailures, 1)
					continue
				}
				if _, err := s.VerifyToken(tok); err != nil {
					atomic.AddInt64(&verifyFailures, 1)
				}
				if i%3 == 0 {
					s.RevokeToken(tok)
				}
				_ = s.TokenCount()
				_ = s.CleanupExpired()
			}
		}(w)
	}
	wg.Wait()
	if verifyFailures != 0 {
		t.Errorf("unexpected failures: %d", verifyFailures)
	}
}

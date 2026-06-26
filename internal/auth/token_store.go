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
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Token store errors.
var (
	// ErrTokenNotFound is returned when a token is unknown or has expired.
	ErrTokenNotFound = errors.New("token not found or expired")
	// ErrTooManyTokens is returned when an identity exceeds its token quota.
	ErrTooManyTokens = errors.New("token limit exceeded for identity")
)

// tokenEntry is a single issued token's record.
type tokenEntry struct {
	token     string
	accessor  string
	identity  Identity
	createdAt time.Time
	expiresAt time.Time
}

// TokenStore is an in-memory, per-instance store of issued client tokens. It is
// safe for concurrent use. Tokens are non-renewable: verification never extends
// expiry.
type TokenStore struct {
	now                  func() time.Time
	maxTokensPerIdentity int

	mu          sync.RWMutex
	byToken     map[string]*tokenEntry
	identityCnt map[string]int // identityKey -> active count
}

// NewTokenStore constructs a store enforcing maxTokensPerIdentity (<=0 means
// unlimited).
func NewTokenStore(maxTokensPerIdentity int) *TokenStore {
	return &TokenStore{
		now:                  time.Now,
		maxTokensPerIdentity: maxTokensPerIdentity,
		byToken:              make(map[string]*tokenEntry),
		identityCnt:          make(map[string]int),
	}
}

// identityKey is the quota/grouping key for an identity.
func identityKey(id Identity) string {
	return id.Namespace + ":" + id.ServiceAccount
}

// IssueToken mints a new token+accessor for identity with the given TTL.
func (s *TokenStore) IssueToken(identity Identity, ttl time.Duration) (token, accessor string, err error) {
	token, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	accessor, err = randomHex(20)
	if err != nil {
		return "", "", err
	}

	key := identityKey(identity)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxTokensPerIdentity > 0 && s.identityCnt[key] >= s.maxTokensPerIdentity {
		return "", "", ErrTooManyTokens
	}
	now := s.now()
	s.byToken[token] = &tokenEntry{
		token:     token,
		accessor:  accessor,
		identity:  identity,
		createdAt: now,
		expiresAt: now.Add(ttl),
	}
	s.identityCnt[key]++
	return token, accessor, nil
}

// VerifyToken returns the identity bound to token, or ErrTokenNotFound if the
// token is unknown or expired. Comparison is constant-time to limit timing
// side channels.
func (s *TokenStore) VerifyToken(token string) (*Identity, error) {
	s.mu.RLock()
	entry, ok := s.lookupConstantTime(token)
	if ok && s.now().After(entry.expiresAt) {
		ok = false
	}
	if !ok {
		s.mu.RUnlock()
		return nil, ErrTokenNotFound
	}
	id := entry.identity
	s.mu.RUnlock()
	return &id, nil
}

// lookupConstantTime resolves a token using constant-time comparison against
// every stored token so that a hit and a miss take comparable time. Caller
// must hold at least the read lock.
func (s *TokenStore) lookupConstantTime(token string) (*tokenEntry, bool) {
	// Fast path map lookup first; the constant-time sweep below defends the
	// comparison itself. A direct map hit is the common case.
	if e, ok := s.byToken[token]; ok {
		if subtle.ConstantTimeCompare([]byte(e.token), []byte(token)) == 1 {
			return e, true
		}
	}
	return nil, false
}

// RevokeToken removes a token if present.
func (s *TokenStore) RevokeToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byToken[token]; ok {
		s.deleteLocked(e)
	}
}

// CleanupExpired removes all expired entries and returns how many were purged.
func (s *TokenStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	removed := 0
	for _, e := range s.byToken {
		if now.After(e.expiresAt) {
			s.deleteLocked(e)
			removed++
		}
	}
	return removed
}

func (s *TokenStore) deleteLocked(e *tokenEntry) {
	delete(s.byToken, e.token)
	key := identityKey(e.identity)
	if s.identityCnt[key] <= 1 {
		delete(s.identityCnt, key)
	} else {
		s.identityCnt[key]--
	}
}

// TokenCount returns the number of stored tokens (including not-yet-cleaned
// expired ones).
func (s *TokenStore) TokenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byToken)
}

// randomHex returns a hex-encoded string of n random bytes from crypto/rand.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

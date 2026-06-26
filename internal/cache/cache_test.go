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

package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func enabledCfg() Config {
	return Config{Enabled: true, TTL: time.Minute, NegativeTTL: 30 * time.Second, MaxEntries: 100}
}

func TestDisabledCache(t *testing.T) {
	c := New(Config{Enabled: false, TTL: time.Minute})
	c.Set("p", map[string]string{"k": "v"})
	c.SetNegative("n")
	if _, hit, _ := c.Get("p"); hit {
		t.Errorf("disabled cache returned a hit")
	}
	if _, hit, _ := c.Get("n"); hit {
		t.Errorf("disabled cache returned a negative hit")
	}
	if c.Len() != 0 {
		t.Errorf("disabled cache Len = %d, want 0", c.Len())
	}
}

func TestSetThenGet(t *testing.T) {
	c := New(enabledCfg())
	c.Set("opus/web", map[string]string{"user": "admin", "pass": "secret"})
	got, hit, neg := c.Get("opus/web")
	if !hit || neg {
		t.Fatalf("hit=%v neg=%v, want hit=true neg=false", hit, neg)
	}
	if got["user"] != "admin" || got["pass"] != "secret" {
		t.Errorf("value = %v", got)
	}
}

func TestGetReturnsClone(t *testing.T) {
	c := New(enabledCfg())
	original := map[string]string{"k": "v"}
	c.Set("p", original)

	// Mutating the source after Set must not affect cache.
	original["k"] = "tampered"

	got1, _, _ := c.Get("p")
	if got1["k"] != "v" {
		t.Errorf("cache was affected by source mutation: %v", got1)
	}
	// Mutating the returned map must not affect a subsequent Get.
	got1["k"] = "mutated"
	got1["new"] = "x"

	got2, _, _ := c.Get("p")
	if got2["k"] != "v" {
		t.Errorf("returned map mutation leaked into cache: %v", got2)
	}
	if _, ok := got2["new"]; ok {
		t.Errorf("added key leaked into cache: %v", got2)
	}
}

func TestTTLExpiry(t *testing.T) {
	cur := time.Unix(1000, 0)
	c := newWithClock(enabledCfg(), func() time.Time { return cur })
	c.Set("p", map[string]string{"k": "v"})

	if _, hit, _ := c.Get("p"); !hit {
		t.Fatalf("expected hit before expiry")
	}
	cur = cur.Add(2 * time.Minute) // TTL is 1 minute
	if _, hit, _ := c.Get("p"); hit {
		t.Errorf("expected miss after expiry")
	}
	// Expired entry should be removed lazily by Get.
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0 after expiry get", c.Len())
	}
}

func TestNegativeEntry(t *testing.T) {
	cur := time.Unix(1000, 0)
	c := newWithClock(enabledCfg(), func() time.Time { return cur })
	c.SetNegative("missing")

	val, hit, neg := c.Get("missing")
	if !hit || !neg {
		t.Fatalf("hit=%v neg=%v, want both true", hit, neg)
	}
	if val != nil {
		t.Errorf("negative hit value = %v, want nil", val)
	}

	cur = cur.Add(time.Minute) // NegativeTTL is 30s
	if _, hit, _ := c.Get("missing"); hit {
		t.Errorf("expected negative entry to expire")
	}
}

func TestSetZeroTTLStoresNothing(t *testing.T) {
	c := New(Config{Enabled: true, TTL: 0, NegativeTTL: 0, MaxEntries: 10})
	c.Set("p", map[string]string{"k": "v"})
	c.SetNegative("n")
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0 with zero TTLs", c.Len())
	}
	if _, hit, _ := c.Get("p"); hit {
		t.Errorf("unexpected hit with zero TTL")
	}
}

func TestLRUEviction(t *testing.T) {
	cfg := Config{Enabled: true, TTL: time.Hour, MaxEntries: 2}
	c := New(cfg)
	c.Set("a", map[string]string{"v": "1"})
	c.Set("b", map[string]string{"v": "2"})
	// Access "a" to make it most-recently-used.
	if _, hit, _ := c.Get("a"); !hit {
		t.Fatalf("a should be present")
	}
	// Insert "c" -> exceeds MaxEntries; least recently used ("b") evicted.
	c.Set("c", map[string]string{"v": "3"})

	if _, hit, _ := c.Get("b"); hit {
		t.Errorf("b should have been evicted as LRU")
	}
	if _, hit, _ := c.Get("a"); !hit {
		t.Errorf("a should survive (recently used)")
	}
	if _, hit, _ := c.Get("c"); !hit {
		t.Errorf("c should be present")
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d, want 2", c.Len())
	}
}

func TestUpdateExistingKey(t *testing.T) {
	c := New(enabledCfg())
	c.Set("p", map[string]string{"v": "1"})
	c.Set("p", map[string]string{"v": "2"})
	got, _, _ := c.Get("p")
	if got["v"] != "2" {
		t.Errorf("value = %v, want updated to 2", got)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestInvalidate(t *testing.T) {
	c := New(enabledCfg())
	c.Set("a", map[string]string{"v": "1"})
	c.Set("b", map[string]string{"v": "2"})
	c.Invalidate("a")
	if _, hit, _ := c.Get("a"); hit {
		t.Errorf("a should be invalidated")
	}
	if _, hit, _ := c.Get("b"); !hit {
		t.Errorf("b should remain")
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
	// Invalidate unknown key is a no-op.
	c.Invalidate("ghost")
	if c.Len() != 1 {
		t.Errorf("Len changed after invalidating unknown key")
	}
}

func TestFlush(t *testing.T) {
	c := New(enabledCfg())
	for i := 0; i < 5; i++ {
		c.Set(fmt.Sprintf("k%d", i), map[string]string{"v": "x"})
	}
	if c.Len() != 5 {
		t.Fatalf("Len = %d, want 5", c.Len())
	}
	c.Flush()
	if c.Len() != 0 {
		t.Errorf("Len after flush = %d, want 0", c.Len())
	}
	// Cache still usable after flush.
	c.Set("new", map[string]string{"v": "y"})
	if _, hit, _ := c.Get("new"); !hit {
		t.Errorf("cache unusable after flush")
	}
}

func TestDefaultMaxEntries(t *testing.T) {
	c := New(Config{Enabled: true, TTL: time.Hour, MaxEntries: 0})
	if c.cfg.MaxEntries != 10000 {
		t.Errorf("MaxEntries = %d, want default 10000", c.cfg.MaxEntries)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(Config{Enabled: true, TTL: time.Hour, NegativeTTL: time.Hour, MaxEntries: 64})
	const workers = 50
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				key := fmt.Sprintf("k%d", i%100)
				switch i % 4 {
				case 0:
					c.Set(key, map[string]string{"w": fmt.Sprintf("%d", w)})
				case 1:
					c.Get(key)
				case 2:
					c.SetNegative(key)
				case 3:
					c.Invalidate(key)
				}
				_ = c.Len()
			}
		}(w)
	}
	wg.Wait()
}

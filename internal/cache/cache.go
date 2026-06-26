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

// Package cache provides a thread-safe, TTL-based in-memory secret cache that
// every backend embeds. It supports positive and negative (not-found) entries
// and bounded LRU eviction.
//
// Security note: cache entries are keyed by secret path only, never by caller
// identity. This is safe because RBAC authorization is always evaluated before
// the cache is consulted; the cache never makes an authorization decision.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// Config controls cache behavior. A zero Config with Enabled=false yields a
// pass-through cache that never stores anything.
type Config struct {
	Enabled     bool
	TTL         time.Duration
	NegativeTTL time.Duration
	MaxEntries  int
}

// clock abstracts time for deterministic testing.
type clock func() time.Time

type entry struct {
	value      map[string]string
	expiresAt  time.Time
	isNegative bool
	elem       *list.Element // position in the LRU list
}

// Cache is a TTL + LRU bounded cache. The zero value is not usable; call New.
type Cache struct {
	cfg   Config
	now   clock
	mu    sync.RWMutex
	items map[string]*entry
	lru   *list.List // front = most recently used
}

// New creates a Cache from cfg. When cfg.Enabled is false the returned cache
// is a no-op.
func New(cfg Config) *Cache {
	return newWithClock(cfg, time.Now)
}

func newWithClock(cfg Config, now clock) *Cache {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10000
	}
	return &Cache{
		cfg:   cfg,
		now:   now,
		items: make(map[string]*entry),
		lru:   list.New(),
	}
}

// Get returns the cached value for path. The boolean reports whether the entry
// was a live cache hit (positive or negative). For a negative hit the returned
// map is nil; callers distinguish the two cases via the second boolean
// (isNegative).
func (c *Cache) Get(path string) (value map[string]string, hit bool, isNegative bool) {
	if !c.cfg.Enabled {
		return nil, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[path]
	if !ok {
		return nil, false, false
	}
	if c.now().After(e.expiresAt) {
		c.removeLocked(path, e)
		return nil, false, false
	}
	c.lru.MoveToFront(e.elem)
	if e.isNegative {
		return nil, true, true
	}
	// Return a copy so callers cannot mutate cached state.
	return cloneMap(e.value), true, false
}

// Set stores a positive entry for path.
func (c *Cache) Set(path string, value map[string]string) {
	if !c.cfg.Enabled || c.cfg.TTL <= 0 {
		return
	}
	c.store(path, cloneMap(value), false, c.cfg.TTL)
}

// SetNegative stores a negative (not-found) entry for path.
func (c *Cache) SetNegative(path string) {
	if !c.cfg.Enabled || c.cfg.NegativeTTL <= 0 {
		return
	}
	c.store(path, nil, true, c.cfg.NegativeTTL)
}

func (c *Cache) store(path string, value map[string]string, negative bool, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[path]; ok {
		e.value = value
		e.isNegative = negative
		e.expiresAt = c.now().Add(ttl)
		c.lru.MoveToFront(e.elem)
		return
	}
	e := &entry{value: value, isNegative: negative, expiresAt: c.now().Add(ttl)}
	e.elem = c.lru.PushFront(path)
	c.items[path] = e
	c.evictLocked()
}

// Invalidate removes a single entry.
func (c *Cache) Invalidate(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[path]; ok {
		c.removeLocked(path, e)
	}
}

// Flush clears the entire cache.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*entry)
	c.lru.Init()
}

// Len returns the current number of entries (including not-yet-expired ones).
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *Cache) evictLocked() {
	for len(c.items) > c.cfg.MaxEntries {
		back := c.lru.Back()
		if back == nil {
			return
		}
		path := back.Value.(string)
		if e, ok := c.items[path]; ok {
			c.removeLocked(path, e)
		} else {
			c.lru.Remove(back)
		}
	}
}

func (c *Cache) removeLocked(path string, e *entry) {
	c.lru.Remove(e.elem)
	delete(c.items, path)
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

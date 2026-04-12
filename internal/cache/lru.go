// Package cache provides a bounded, thread-safe LRU cache with per-entry TTL.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// entry is the value stored in each list element.
type entry[K comparable, V any] struct {
	key    K
	value  V
	expiry time.Time // zero means no expiry
}

// LRU is a generic, thread-safe Least Recently Used cache.
// On capacity overflow the least recently used entry is evicted.
// Expired entries are lazily evicted on Get; a full sweep runs on every
// Purge call (useful for long-lived caches to reclaim memory proactively).
type LRU[K comparable, V any] struct {
	mu    sync.Mutex
	cap   int
	list  *list.List
	items map[K]*list.Element
}

// New returns an LRU cache with the given maximum capacity.
// Panics if capacity is <= 0.
func New[K comparable, V any](capacity int) *LRU[K, V] {
	if capacity <= 0 {
		panic("cache: capacity must be > 0")
	}
	return &LRU[K, V]{
		cap:   capacity,
		list:  list.New(),
		items: make(map[K]*list.Element, capacity),
	}
}

// Set inserts or updates key with value.
// If ttl > 0 the entry expires after that duration; ttl == 0 means never.
// If the cache is at capacity the LRU entry is evicted first.
func (c *LRU[K, V]) Set(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiry time.Time
	if ttl > 0 {
		expiry = time.Now().Add(ttl)
	}

	// Update existing entry.
	if el, ok := c.items[key]; ok {
		e := el.Value.(*entry[K, V])
		e.value = value
		e.expiry = expiry
		c.list.MoveToFront(el)
		return
	}

	// Evict LRU when at capacity.
	if c.list.Len() >= c.cap {
		c.evictOldest()
	}

	e := &entry[K, V]{key: key, value: value, expiry: expiry}
	el := c.list.PushFront(e)
	c.items[key] = el
}

// Get returns the value for key and true if found and not expired.
// An expired entry is removed and (zero, false) is returned.
func (c *LRU[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	e := el.Value.(*entry[K, V])

	// Lazy TTL eviction.
	if !e.expiry.IsZero() && time.Now().After(e.expiry) {
		delete(c.items, key)
		c.list.Remove(el)
		var zero V
		return zero, false
	}

	c.list.MoveToFront(el)
	return e.value, true
}

// Len returns the current number of entries (including not-yet-expired ones).
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.list.Len()
}

// Purge removes all expired entries. Call periodically on long-lived caches
// to reclaim memory from entries that were never re-requested after expiry.
func (c *LRU[K, V]) Purge() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	var next *list.Element
	for el := c.list.Back(); el != nil; el = next {
		next = el.Prev()
		e := el.Value.(*entry[K, V])
		if !e.expiry.IsZero() && now.After(e.expiry) {
			delete(c.items, e.key)
			c.list.Remove(el)
		}
	}
}

// evictOldest removes the least recently used entry. Must be called with mu held.
func (c *LRU[K, V]) evictOldest() {
	oldest := c.list.Back()
	if oldest == nil {
		return
	}
	e := oldest.Value.(*entry[K, V])
	delete(c.items, e.key)
	c.list.Remove(oldest)
}

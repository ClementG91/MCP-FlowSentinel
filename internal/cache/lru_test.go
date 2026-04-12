package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestNew_ZeroCapacity_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for capacity=0")
		}
	}()
	New[string, string](0)
}

func TestSetGet_Basic(t *testing.T) {
	c := New[string, int](10)
	c.Set("a", 1, 0)
	v, ok := c.Get("a")
	if !ok || v != 1 {
		t.Errorf("Get(a) = %d, %v; want 1, true", v, ok)
	}
}

func TestGet_Missing_ReturnsFalse(t *testing.T) {
	c := New[string, int](10)
	_, ok := c.Get("missing")
	if ok {
		t.Error("Get on missing key should return false")
	}
}

func TestSet_Update_ExistingKey(t *testing.T) {
	c := New[string, int](10)
	c.Set("k", 1, 0)
	c.Set("k", 99, 0)
	v, ok := c.Get("k")
	if !ok || v != 99 {
		t.Errorf("Get after update = %d, %v; want 99, true", v, ok)
	}
	if c.Len() != 1 {
		t.Errorf("Len after update = %d, want 1", c.Len())
	}
}

func TestEviction_AtCapacity_RemovesLRU(t *testing.T) {
	c := New[string, int](3)
	c.Set("a", 1, 0)
	c.Set("b", 2, 0)
	c.Set("c", 3, 0)

	// Access "a" to make it recently used; "b" is now LRU.
	c.Get("a")

	// Insert "d" → evicts "b" (least recently used).
	c.Set("d", 4, 0)

	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
	if _, ok := c.Get("b"); ok {
		t.Error("evicted key 'b' should not be retrievable")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := c.Get(k); !ok {
			t.Errorf("key %q should still be present", k)
		}
	}
}

func TestTTL_ExpiredEntry_NotReturned(t *testing.T) {
	c := New[string, string](10)
	c.Set("k", "v", 10*time.Millisecond)

	v, ok := c.Get("k")
	if !ok || v != "v" {
		t.Errorf("Get before expiry = %q, %v; want 'v', true", v, ok)
	}

	time.Sleep(20 * time.Millisecond)

	_, ok = c.Get("k")
	if ok {
		t.Error("expired entry should not be returned")
	}
	if c.Len() != 0 {
		t.Errorf("Len after expiry eviction = %d, want 0", c.Len())
	}
}

func TestTTL_ZeroMeansNoExpiry(t *testing.T) {
	c := New[string, string](10)
	c.Set("k", "permanent", 0)

	time.Sleep(5 * time.Millisecond)

	v, ok := c.Get("k")
	if !ok || v != "permanent" {
		t.Errorf("Get with TTL=0 = %q, %v; want 'permanent', true", v, ok)
	}
}

func TestPurge_RemovesExpiredEntries(t *testing.T) {
	c := New[string, int](100)
	// Insert 5 entries that expire quickly and 3 that don't.
	for i := 0; i < 5; i++ {
		c.Set(fmt.Sprintf("exp-%d", i), i, 10*time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		c.Set(fmt.Sprintf("perm-%d", i), i, 0)
	}

	time.Sleep(20 * time.Millisecond)
	c.Purge()

	if c.Len() != 3 {
		t.Errorf("Len after Purge = %d, want 3 (only permanent entries)", c.Len())
	}
}

func TestLen_Empty(t *testing.T) {
	c := New[int, int](5)
	if c.Len() != 0 {
		t.Errorf("Len on empty cache = %d, want 0", c.Len())
	}
}

// TestConcurrent verifies no data races under concurrent Set/Get. Run with -race.
func TestConcurrent_NoDataRace(t *testing.T) {
	c := New[int, int](50)
	var wg sync.WaitGroup
	const workers = 20
	wg.Add(workers * 2)

	for i := 0; i < workers; i++ {
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Set(n*100+j, n+j, time.Millisecond)
			}
		}(i)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Get(n*100 + j)
			}
		}(i)
	}
	wg.Wait()
}

// TestEvictOldest_EmptyList_IsNoop calls evictOldest on a fresh (empty) LRU
// directly to cover the defensive "oldest == nil → return" branch.
// This is an internal-only path; the public API never reaches it because Set
// only calls evictOldest when len(items) > cap, which implies a non-empty list.
func TestEvictOldest_EmptyList_IsNoop(t *testing.T) {
	c := New[string, int](4)
	// No entries added — list is empty. Must not panic.
	c.evictOldest()
}

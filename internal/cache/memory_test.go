package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCacheLifecycle(t *testing.T) {
	// 1. Setup
	ttl := 10 * time.Millisecond
	mgr, err := NewCacheManager("", "", &ttl)
	assert.NoError(t, err)
	c := mgr.GetCache("html", CacheOptions{})

	ctx := context.Background()

	// 2. Set Generation 1
	mgr.Cycle("1", false)
	c.Set(ctx, "page1", "content-v1")

	// 3. Update to Generation 2 (The Cycle)
	mgr.Cycle("2", false)

	// 4. Verify Fallback (N-1)
	val, ok, isCurrent, err := c.Get(ctx, "page1")
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, isCurrent)
	assert.Equal(t, "content-v1", val)

	// Trigger migration as discussed
	c.Set(ctx, "page1", val)

	// 5. Test TTL
	time.Sleep(100 * time.Millisecond) // Wait for reaper
	_, ok, _, err = c.Get(ctx, "page1")
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestInMemoryCacheManager_GetCache(t *testing.T) {
	tests := []struct {
		name       string
		args       func(t *testing.T) (class string, opts CacheOptions)
		assertions func(t *testing.T, got Cache, cacheManager CacheManager)
	}{
		{
			name: "memory",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.False(t, got.Uncycled())
			},
		},
		{
			name: "cycle - generation updates",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.False(t, got.Uncycled())
				cacheManager.Cycle("1", false)
				assert.Equal(t, "1", got.Checksum())
				cacheManager.Cycle("2", false)
				assert.Equal(t, "2", got.Checksum())
			},
		},
		{
			name: "cycle - with fallback",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.False(t, got.Uncycled())

				ctx := context.Background()

				// Set an item in the cache
				got.Set(ctx, "test", "test")
				val, ok, isCurrent, err := got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// Cycle to generation 1 - we got the fallback v(N-1)
				cacheManager.Cycle("1", false)
				assert.Equal(t, "1", got.Checksum())
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.False(t, isCurrent)
				assert.Equal(t, "test", val)

				// Cycle to generation 2
				cacheManager.Cycle("2", false)
				assert.Equal(t, "2", got.Checksum())
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "", val)
			},
		},
		{
			name: "cycle - force - no fallback",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.False(t, got.Uncycled())

				ctx := context.Background()

				// Set an item in the cache
				got.Set(ctx, "test", "test")
				val, ok, isCurrent, err := got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// Cycle to generation 1 - force, no fallback
				cacheManager.Cycle("1", true)
				assert.Equal(t, "1", got.Checksum())
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "", val)
			},
		},
		{
			name: "uncycled",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{Uncycled: true}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.True(t, got.Uncycled())

				ctx := context.Background()

				// Set an item in the cache
				got.Set(ctx, "test", "test")
				val, ok, isCurrent, err := got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// Cycle an uncycled cache without force does not clear the cache
				cacheManager.Cycle("1", false)
				assert.Equal(t, "0", got.Checksum())
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)
			},
		},
		{
			name: "uncycled - force",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{Uncycled: true}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.True(t, got.Uncycled())

				ctx := context.Background()

				// Set an item in the cache
				got.Set(ctx, "test", "test")
				val, ok, isCurrent, err := got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// Cycle with force clears an uncycled cache
				cacheManager.Cycle("1", true)
				assert.Equal(t, "1", got.Checksum())
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "", val)
			},
		},
		{
			name: "update ttl",
			args: func(t *testing.T) (string, CacheOptions) {
				return "test", CacheOptions{TTL: new(100 * time.Millisecond)}
			},
			assertions: func(t *testing.T, got Cache, cacheManager CacheManager) {
				assert.NotNil(t, got)
				assert.Equal(t, "test", got.Class())
				assert.Equal(t, "0", got.Checksum())
				assert.Equal(t, "foo", got.Host())
				assert.Equal(t, time.Duration(100*time.Millisecond), got.TTL())
				assert.False(t, got.Uncycled())

				ctx := context.Background()

				// Set an item in the cache
				got.Set(ctx, "test", "test")
				val, ok, isCurrent, err := got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// Update TTL
				got = cacheManager.GetCache("test", CacheOptions{TTL: new(1 * time.Millisecond)})
				assert.Equal(t, time.Duration(1*time.Millisecond), got.TTL())

				// preexisting items in the cache still have the old expiry based on previous TTL
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// a new item will have the new expiry
				got.Set(ctx, "foo", "foo")
				time.Sleep(10 * time.Millisecond)

				// check it new item should be expired
				val, ok, isCurrent, err = got.Get(ctx, "foo")
				assert.NoError(t, err)
				assert.False(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "", val)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheManager, err := NewCacheManager("", "foo", new(100*time.Millisecond))
			assert.NoError(t, err)
			class, opts := tt.args(t)
			got := cacheManager.GetCache(class, opts)
			tt.assertions(t, got, cacheManager)
			t.Cleanup(func() {
				cacheManager.Cycle("0", true)
			})
		})
	}
}

func TestInMemoryCache_LRU(t *testing.T) {
	ctx := context.Background()
	maxItems := 3
	mgr, _ := NewCacheManager("", "foo", nil)
	c := mgr.GetCache("lru", CacheOptions{MaxItems: &maxItems})

	// Add 3 items
	c.Set(ctx, "k1", "v1")
	c.Set(ctx, "k2", "v2")
	c.Set(ctx, "k3", "v3")

	// Verify all are present
	v, ok, _, _ := c.Get(ctx, "k1")
	assert.True(t, ok)
	assert.Equal(t, "v1", v)

	// k1 is now most recently used. LRU is k2.

	// Add 4th item, should evict k2
	c.Set(ctx, "k4", "v4")

	_, ok, _, _ = c.Get(ctx, "k2")
	assert.False(t, ok, "k2 should have been evicted")

	// Verify others are still there
	_, ok, _, _ = c.Get(ctx, "k1")
	assert.True(t, ok)
	_, ok, _, _ = c.Get(ctx, "k3")
	assert.True(t, ok)
	_, ok, _, _ = c.Get(ctx, "k4")
	assert.True(t, ok)
}

func TestInMemoryCache_IndividualTTL(t *testing.T) {
	ctx := context.Background()
	defaultTTL := 1 * time.Hour
	mgr, _ := NewCacheManager("", "foo", &defaultTTL)
	c := mgr.GetCache("ttl", CacheOptions{})

	// Set with short TTL
	shortTTL := 10 * time.Millisecond
	c.Set(ctx, "short", "val", WithTTL(shortTTL))

	// Set with default TTL
	c.Set(ctx, "default", "val")

	// Verify both present
	_, ok, _, _ := c.Get(ctx, "short")
	assert.True(t, ok)
	_, ok, _, _ = c.Get(ctx, "default")
	assert.True(t, ok)

	// Wait for short TTL to expire
	time.Sleep(50 * time.Millisecond)

	// short should be gone (lazy delete in Get)
	_, ok, _, _ = c.Get(ctx, "short")
	assert.False(t, ok, "item with short TTL should have expired")

	// default should still be there
	_, ok, _, _ = c.Get(ctx, "default")
	assert.True(t, ok)
}

// TestInMemoryCacheManager_GetCache_RaceOnFirstCreate pins the fix for
// kdex-tech/host-manager#57. The pre-fix GetCache slow-path took
// m.mu.Lock() but did not re-check m.caches[class] before constructing
// — two concurrent callers that both missed the RLock fast path would
// each construct a separate *InMemoryCache + launch a separate reaper
// goroutine, the second overwriting the first in m.caches[class]. The
// loser's cache was orphaned (silent data loss for any tokens already
// written through it) and the loser's reaper goroutine leaked.
//
// Post-fix, all concurrent callers receive the same cache pointer.
func TestInMemoryCacheManager_GetCache_RaceOnFirstCreate(t *testing.T) {
	ttl := time.Minute
	mgr, err := NewCacheManager("", "", &ttl)
	assert.NoError(t, err)

	const n = 32
	results := make([]Cache, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = mgr.GetCache("race-class", CacheOptions{})
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 1; i < n; i++ {
		assert.Samef(t, results[0], results[i],
			"GetCache must return the same cache pointer for every concurrent caller (#57); got distinct caches at index 0 and %d", i)
	}

	// And only one entry exists in the manager's map.
	im := mgr.(*InMemoryCacheManager)
	im.mu.RLock()
	count := len(im.caches)
	im.mu.RUnlock()
	assert.Equal(t, 1, count, "must register exactly one cache for the class (#57)")
}

// TestInMemoryCacheManager_UpdateChanInitializedBeforeReaper pins the
// fix for kdex-tech/host-manager#75. Pre-fix, InMemoryCache.updateChan
// was initialised INSIDE the reaper goroutine (`c.updateChan = make(...)`
// at the top of startReaper), but the fast-path GetCache sent to that
// same channel — a classic publish-after-spawn race. Under -race the
// detector trips on the unsynchronised write/read. The reaper's
// eventual `case <-c.updateChan` on the uninitialised field is also a
// goroutine-leak vector.
//
// Post-fix the channel is constructed synchronously in GetCache's
// slow path before `go cache.startReaper(...)` is spawned, so the
// reaper observes an already-initialised field.
func TestInMemoryCacheManager_UpdateChanInitializedBeforeReaper(t *testing.T) {
	ttl := 100 * time.Millisecond
	mgr, err := NewCacheManager("", "", &ttl)
	assert.NoError(t, err)

	// Concurrent GetCache calls on the same class: one spawns the
	// reaper, the other hits the fast path and sends to updateChan
	// with a different TTL. Pre-fix this race-detector trips on the
	// updateChan field write/read.
	const goroutines = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		newTTL := 50 * time.Millisecond * time.Duration(i+1)
		go func() {
			defer wg.Done()
			<-start
			_ = mgr.GetCache("class-x", CacheOptions{TTL: &newTTL})
		}()
	}
	close(start)
	wg.Wait()
}

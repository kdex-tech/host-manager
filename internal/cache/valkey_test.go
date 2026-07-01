package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestValkeyCacheManager_GetCache(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Error(err)
	}

	tests := []struct {
		name       string
		args       func(t *testing.T) (addr, host, class string, opts CacheOptions)
		assertions func(t *testing.T, got Cache, cacheManager CacheManager)
	}{
		{
			name: "valkey",
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{}
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{}
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{}
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
				err := got.Set(ctx, "test", "test")
				assert.NoError(t, err)
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{}
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{Uncycled: true}
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{Uncycled: true}
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
			args: func(t *testing.T) (string, string, string, CacheOptions) {
				return s.Addr(), "foo", "test", CacheOptions{TTL: new(100 * time.Millisecond)}
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
				got = cacheManager.GetCache("test", CacheOptions{TTL: new(10 * time.Millisecond)})
				assert.Equal(t, time.Duration(10*time.Millisecond), got.TTL())

				// preexisting items in the cache still have the old expiry based on previous TTL
				val, ok, isCurrent, err = got.Get(ctx, "test")
				assert.NoError(t, err)
				assert.True(t, ok)
				assert.True(t, isCurrent)
				assert.Equal(t, "test", val)

				// a new item will have the new expiry
				err = got.Set(ctx, "foo", "foo")
				assert.NoError(t, err)
				s.FastForward(20 * time.Millisecond)

				// new item should be expired
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
			attr, host, class, opts := tt.args(t)
			cacheManager, err := NewCacheManager(attr, host, new(100*time.Millisecond))
			assert.NoError(t, err)
			got := cacheManager.GetCache(class, opts)
			tt.assertions(t, got, cacheManager)
			t.Cleanup(func() {
				cacheManager.Cycle("0", true)
			})
		})
	}
}

func TestValkeyCache_IndividualTTL(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Error(err)
	}
	defer s.Close()

	ctx := context.Background()
	defaultTTL := 1 * time.Hour
	mgr, _ := NewCacheManager(s.Addr(), "foo", &defaultTTL)
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
	s.FastForward(50 * time.Millisecond)

	// short should be gone
	_, ok, _, _ = c.Get(ctx, "short")
	assert.False(t, ok, "item with short TTL should have expired")

	// default should still be there
	_, ok, _, _ = c.Get(ctx, "default")
	assert.True(t, ok)
}

// TestDecrementIfPositive_Valkey mirrors TestDecrementIfPositive_Memory's
// assertion sequence against the Lua-backed atomic decrement. miniredis
// runs in-process and supports EVAL, so this exercises the real script
// rather than a stand-in.
func TestDecrementIfPositive_Valkey(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Error(err)
	}
	defer s.Close()

	ctx := context.Background()
	ttl := time.Minute
	mgr, err := NewCacheManager(s.Addr(), "foo", &ttl)
	assert.NoError(t, err)
	c := mgr.GetCache("cap", CacheOptions{Uncycled: true})

	// missing key -> fail-closed
	rem, ok, err := c.DecrementIfPositive(ctx, "j1")
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)

	assert.NoError(t, c.Set(ctx, "j1", "2"))
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(1), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1")
	assert.True(t, ok)
	assert.Equal(t, int64(0), rem)
	rem, ok, _ = c.DecrementIfPositive(ctx, "j1") // exhausted
	assert.False(t, ok)
	assert.Equal(t, int64(-1), rem)
}

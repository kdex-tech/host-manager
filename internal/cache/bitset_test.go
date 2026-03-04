package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
)

func TestBitSetLifecycle_InMemory(t *testing.T) {
	ttl := 100 * time.Millisecond
	mgr, err := NewCacheManager("", "foo", &ttl)
	assert.NoError(t, err)
	bs := mgr.GetBitSet("bits", CacheOptions{})

	ctx := context.Background()

	// 1. Initial State
	mgr.Cycle("1", false)
	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)

	val, ok, isCurrent, err := bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, isCurrent)
	assert.True(t, val)

	// 2. Cycle with Fallback
	mgr.Cycle("2", false)
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, isCurrent)
	assert.True(t, val)

	// 3. Bit not set in old generation
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 11)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, isCurrent)
	assert.False(t, val)

	// 4. Migration to current generation
	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, isCurrent)
	assert.True(t, val)

	// 5. Delete
	err = bs.Delete(ctx, "set1")
	assert.NoError(t, err)
	_, ok, _, _ = bs.Get(ctx, "set1", 10)
	assert.False(t, ok)
}

func TestBitSetLifecycle_Valkey(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ttl := 100 * time.Millisecond
	mgr, err := NewCacheManager(s.Addr(), "foo", &ttl)
	assert.NoError(t, err)
	bs := mgr.GetBitSet("bits", CacheOptions{})

	ctx := context.Background()

	// 1. Initial State
	mgr.Cycle("1", false)
	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)

	val, ok, isCurrent, err := bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, isCurrent)
	assert.True(t, val)

	// 2. Cycle with Fallback
	mgr.Cycle("2", false)
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, isCurrent)
	assert.True(t, val)

	// 3. Bit not set in old generation
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 11)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.False(t, isCurrent)
	assert.False(t, val)

	// 4. Migration to current generation
	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)
	val, ok, isCurrent, err = bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, isCurrent)
	assert.True(t, val)

	// 5. Delete
	err = bs.Delete(ctx, "set1")
	assert.NoError(t, err)
	_, ok, _, _ = bs.Get(ctx, "set1", 10)
	assert.False(t, ok)
}

func TestBitSetTTL_InMemory(t *testing.T) {
	ttl := 10 * time.Millisecond
	mgr, err := NewCacheManager("", "foo", &ttl)
	assert.NoError(t, err)
	bs := mgr.GetBitSet("bits", CacheOptions{})

	ctx := context.Background()
	mgr.Cycle("1", false)

	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	_, ok, _, err := bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.False(t, ok)
}

func TestBitSetTTL_Valkey(t *testing.T) {
	s, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ttl := 10 * time.Millisecond
	mgr, err := NewCacheManager(s.Addr(), "foo", &ttl)
	assert.NoError(t, err)
	bs := mgr.GetBitSet("bits", CacheOptions{})

	ctx := context.Background()
	mgr.Cycle("1", false)

	err = bs.Set(ctx, "set1", 10, true)
	assert.NoError(t, err)

	s.FastForward(20 * time.Millisecond)
	_, ok, _, err := bs.Get(ctx, "set1", 10)
	assert.NoError(t, err)
	assert.False(t, ok)
}

package cache

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Derived data follows the host generation; state lives in the one class
// that survives it. These pin both halves against each backend. See
// kdex-tech/host-manager#245.

func eachBackend(t *testing.T, run func(t *testing.T, newManager func() CacheManager)) {
	t.Run("memory", func(t *testing.T) {
		run(t, func() CacheManager {
			m, err := NewCacheManager("", "foo", new(time.Minute))
			require.NoError(t, err)
			return m
		})
	})
	t.Run("valkey", func(t *testing.T) {
		s := miniredis.RunT(t)
		run(t, func() CacheManager {
			m, err := NewCacheManager(s.Addr(), "foo", new(time.Minute))
			require.NoError(t, err)
			return m
		})
	})
}

// A reconcile that leaves the checksum unchanged is not a new generation, so
// it must not spend the previous generation's grace window.
func TestCycle_UnchangedChecksumKeepsThePreviousGeneration(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		m := newManager()
		c := m.GetCache("page", CacheOptions{})
		require.NoError(t, m.Cycle("1", false))
		require.NoError(t, c.Set(ctx, "k", "v1"))

		require.NoError(t, m.Cycle("2", false))
		require.NoError(t, m.Cycle("2", false))

		val, found, isCurrent, err := c.Get(ctx, "k")
		require.NoError(t, err)
		assert.True(t, found, "generation 1 is still the previous generation")
		assert.False(t, isCurrent)
		assert.Equal(t, "v1", val)
	})
}

// The surviving class has one generation, whatever the host's checksum was
// when a replica first created it: a cache created after a cycle (a lazily
// created class, or a pod started after a reconfiguration) reads what its
// peers wrote.
func TestUncycled_GenerationDoesNotDependOnWhenTheCacheWasCreated(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		early := newManager()
		require.NoError(t, early.GetCache("state", CacheOptions{Uncycled: true}).Set(ctx, "k", "v"))

		late := newManager()
		require.NoError(t, late.Cycle("abc", false))
		c := late.GetCache("state", CacheOptions{Uncycled: true})
		assert.Equal(t, SurvivingGeneration, c.Checksum())

		if _, isMemory := late.(*InMemoryCacheManager); isMemory {
			return // process memory is not shared between managers
		}
		val, found, _, err := c.Get(ctx, "k")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "v", val)
	})
}

func TestUncycled_SurvivesAForcedCycle(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		m := newManager()
		c := m.GetCache("state", CacheOptions{Uncycled: true})
		require.NoError(t, c.Set(ctx, "k", "v"))

		require.NoError(t, m.Cycle("1", true))

		assert.Equal(t, SurvivingGeneration, c.Checksum())
		val, found, _, err := c.Get(ctx, "k")
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "v", val)
	})
}

func TestSetIfAbsent(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		c := newManager().GetCache("state", CacheOptions{Uncycled: true})

		set, err := c.SetIfAbsent(ctx, "k", "first", WithTTL(time.Hour))
		require.NoError(t, err)
		assert.True(t, set)

		set, err = c.SetIfAbsent(ctx, "k", "second", WithTTL(time.Hour))
		require.NoError(t, err)
		assert.False(t, set, "an existing entry is never overwritten")

		val, _, _, err := c.Get(ctx, "k")
		require.NoError(t, err)
		assert.Equal(t, "first", val)
	})
}

// ScanGenerations reaches the entries a class holds under every generation,
// including the ones no current read can reach any more.
func TestScanGenerations(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		m := newManager()
		c := m.GetCache("revocations", CacheOptions{})
		other := m.GetCache("revocations-v2", CacheOptions{Uncycled: true})
		require.NoError(t, other.Set(ctx, "not-this-class", "x"))

		require.NoError(t, m.Cycle("1", false))
		require.NoError(t, c.Set(ctx, "a", "a1", WithTTL(time.Hour)))
		require.NoError(t, m.Cycle("2", false))
		require.NoError(t, c.Set(ctx, "a", "a2", WithTTL(time.Hour)))
		require.NoError(t, c.Set(ctx, "b", "b2", WithTTL(time.Hour)))

		var got []string
		require.NoError(t, m.ScanGenerations(ctx, "revocations", func(e Entry) error {
			assert.Positive(t, e.TTL, e.Key)
			assert.LessOrEqual(t, e.TTL, time.Hour, e.Key)
			got = append(got, e.Key+"="+e.Value)
			return nil
		}))
		sort.Strings(got)
		assert.Equal(t, []string{"a=a1", "a=a2", "b=b2"}, got)
	})
}

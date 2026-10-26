package cache

import (
	"context"
	"sort"
	"strconv"
	"sync"
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

// The surviving scope has one generation, whatever the host's checksum was
// when a replica first created the cache: one created after a cycle (a
// lazily created cache, or a pod started after a reconfiguration) reads what
// its peers wrote. Valkey only: process memory is not shared between managers.
func TestUncycled_GenerationDoesNotDependOnWhenTheCacheWasCreated(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	newManager := func() CacheManager {
		m, err := NewCacheManager(s.Addr(), "foo", new(time.Minute))
		require.NoError(t, err)
		return m
	}
	require.NoError(t, newManager().GetCache("state", CacheOptions{Uncycled: true}).Set(ctx, "k", "v"))

	late := newManager()
	require.NoError(t, late.Cycle("abc", false))
	c := late.GetCache("state", CacheOptions{Uncycled: true})
	assert.Equal(t, SurvivingGeneration, c.Checksum())

	val, found, _, err := c.Get(ctx, "k")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "v", val)
}

// A cache asked for under the other scope moves to that scope's generation
// and leaves the old one behind, on both backends alike.
func TestGetCache_ChangingScopeLeavesTheOldGeneration(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		m := newManager()
		require.NoError(t, m.Cycle("1", false))
		cycled := m.GetCache("c", CacheOptions{})
		require.NoError(t, cycled.Set(ctx, "k", "cycled"))

		surviving := m.GetCache("c", CacheOptions{Uncycled: true})
		assert.Equal(t, SurvivingGeneration, surviving.Checksum())
		_, found, _, err := surviving.Get(ctx, "k")
		require.NoError(t, err)
		assert.False(t, found)
	})
}

func TestUpdate(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		c := newManager().GetCache("state", CacheOptions{Uncycled: true})
		keep := func(string, bool) (string, bool) { return "", false }

		wrote, err := c.Update(ctx, "k", keep)
		require.NoError(t, err)
		assert.False(t, wrote)
		_, found, _, err := c.Get(ctx, "k")
		require.NoError(t, err)
		assert.False(t, found, "write=false writes nothing")

		// Concurrent increments: every one lands, so none read a stale value.
		increment := func(current string, found bool) (string, bool) {
			n := 0
			if found {
				n, _ = strconv.Atoi(current)
			}
			return strconv.Itoa(n + 1), true
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				_, err := c.Update(ctx, "n", increment, WithTTL(time.Hour))
				assert.NoError(t, err)
			})
		}
		wg.Wait()
		val, _, _, err := c.Get(ctx, "n")
		require.NoError(t, err)
		assert.Equal(t, "8", val)
	})
}

// ScanGenerations reaches the entries a class holds under every generation,
// including the ones no current read can reach any more.
func TestScanGenerations(t *testing.T) {
	eachBackend(t, func(t *testing.T, newManager func() CacheManager) {
		ctx := context.Background()
		m := newManager()
		c := m.GetCache("revocations", CacheOptions{})
		// Neither a class whose name extends this one's, nor one that
		// extends it past a ":", is this class.
		for _, other := range []string{"revocations-v2", "revocations:sub"} {
			require.NoError(t, m.GetCache(other, CacheOptions{Uncycled: true}).Set(ctx, "not-this-class", "x"))
		}

		require.NoError(t, m.Cycle("1", false))
		require.NoError(t, c.Set(ctx, "a", "a1", WithTTL(time.Hour)))
		require.NoError(t, m.Cycle("2", false))
		require.NoError(t, c.Set(ctx, "a", "a2", WithTTL(time.Hour)))
		require.NoError(t, c.Set(ctx, "b", "b2", WithTTL(time.Hour)))

		var got []string
		require.NoError(t, m.ScanGenerations(ctx, "revocations", func(e Entry) error {
			assert.Positive(t, e.TTL, e.Key)
			assert.LessOrEqual(t, e.TTL, time.Hour, e.Key)
			got = append(got, e.Generation+"/"+e.Key+"="+e.Value)
			return nil
		}))
		sort.Strings(got)
		assert.Equal(t, []string{"1/a=a1", "2/a=a2", "2/b=b2"}, got)
	})
}

package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reconciler adopts stranded revocations in the background, at startup
// and again each time the legacy class moves to a new generation, and not on
// every reconcile: the sweep scans the whole cache keyspace. See
// kdex-tech/host-manager#245. LEGACY(#259).
func TestAdoptStrandedRevocations_OncePerLegacyGeneration(t *testing.T) {
	ctx := context.Background()
	cm, err := cache.NewCacheManager("", "adopt-host", nil)
	require.NoError(t, err)
	r := &KDexInternalHostReconciler{HostHandler: host.NewHostHandler(nil, "adopt-host", "default", logr.Discard(), cm)}
	store, legacy := apitoken.RevocationCaches(cm)
	tm, err := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)

	strand := func(jti string) {
		t.Helper()
		require.NoError(t, legacy.Set(ctx, jti, "revoked", cache.WithTTL(time.Hour)))
	}
	reconcile := func() {
		t.Helper()
		r.adoptStrandedRevocationsInBackground(ctx, tm)
		require.Eventually(t, func() bool {
			r.revocationSweep.mu.Lock()
			defer r.revocationSweep.mu.Unlock()
			return !r.revocationSweep.running
		}, 5*time.Second, time.Millisecond)
	}
	adopted := func(jti string) bool {
		t.Helper()
		_, found, _, err := store.Get(ctx, jti)
		require.NoError(t, err)
		return found
	}

	strand("at-startup")
	reconcile()
	assert.True(t, adopted("at-startup"), "the first reconcile sweeps")

	strand("same-generation")
	reconcile()
	assert.False(t, adopted("same-generation"), "a reconcile in the same generation does not sweep again")

	require.NoError(t, cm.Cycle("next", false))
	reconcile()
	assert.True(t, adopted("same-generation"), "a new generation sweeps, before the old one falls out of reach")

	r.adoptStrandedRevocationsInBackground(ctx, nil) // a host without API tokens is a no-op
}

// cyclingDuringScan moves the host to a new generation, once, while a sweep's
// scan is under way, after stranding one more revocation in the old one.
type cyclingDuringScan struct {
	cache.CacheManager
	once sync.Once
}

func (c *cyclingDuringScan) ScanGenerations(ctx context.Context, class string, fn func(cache.Entry) error) error {
	err := c.CacheManager.ScanGenerations(ctx, class, fn)
	c.once.Do(func() {
		_, legacy := apitoken.RevocationCaches(c.CacheManager)
		_ = legacy.Set(ctx, "written-mid-pass", "revoked", cache.WithTTL(time.Hour))
		_ = c.Cycle("moved-mid-pass", false)
	})
	return err
}

// A generation change during a sweep is swept before the sweep stops, not
// left for a reconcile that may not come.
func TestAdoptStrandedRevocations_SweepsAGenerationChangeDuringAPass(t *testing.T) {
	ctx := context.Background()
	base, err := cache.NewCacheManager("", "adopt-host", nil)
	require.NoError(t, err)
	cm := &cyclingDuringScan{CacheManager: base}
	r := &KDexInternalHostReconciler{HostHandler: host.NewHostHandler(nil, "adopt-host", "default", logr.Discard(), cm)}
	store, legacy := apitoken.RevocationCaches(cm)
	tm, err := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)

	r.adoptStrandedRevocationsInBackground(ctx, tm)
	require.Eventually(t, func() bool {
		r.revocationSweep.mu.Lock()
		defer r.revocationSweep.mu.Unlock()
		return !r.revocationSweep.running
	}, 5*time.Second, time.Millisecond)

	_, found, _, err := store.Get(ctx, "written-mid-pass")
	require.NoError(t, err)
	assert.True(t, found)
	r.revocationSweep.mu.Lock()
	defer r.revocationSweep.mu.Unlock()
	assert.Equal(t, legacy.Checksum(), r.revocationSweep.adopted)
}

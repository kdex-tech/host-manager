package controller

import (
	"context"
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

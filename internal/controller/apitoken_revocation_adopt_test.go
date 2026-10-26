package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
)

// The reconciler adopts stranded revocations once per process, not on every
// reconcile: the sweep scans the whole cache keyspace. See
// kdex-tech/host-manager#245.
func TestAdoptStrandedRevocations_OncePerProcess(t *testing.T) {
	ctx := context.Background()
	cm, err := cache.NewCacheManager("", "adopt-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &KDexInternalHostReconciler{HostHandler: host.NewHostHandler(nil, "adopt-host", "default", logr.Discard(), cm)}
	store := cm.GetCache(apitoken.RevocationClass, apitoken.RevocationCacheOptions())
	tm, err := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), store)
	if err != nil {
		t.Fatal(err)
	}
	legacy := cm.GetCache(apitoken.LegacyRevocationClass, cache.CacheOptions{})
	strand := func(jti string) {
		t.Helper()
		if err := legacy.Set(ctx, jti, "revoked", cache.WithTTL(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	strand("first")
	r.adoptStrandedRevocations(ctx, tm)
	strand("second")
	r.adoptStrandedRevocations(ctx, tm)

	if _, found, _, _ := store.Get(ctx, "first"); !found {
		t.Fatal("the first reconcile did not adopt the stranded revocation")
	}
	if _, found, _, _ := store.Get(ctx, "second"); found {
		t.Fatal("a later reconcile swept again")
	}
	r.adoptStrandedRevocations(ctx, nil) // a host without API tokens is a no-op
}

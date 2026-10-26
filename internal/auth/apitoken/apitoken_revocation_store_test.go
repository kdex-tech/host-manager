package apitoken

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Revocations are state a request created, so they live in the class that
// survives host generations; until v0.28.0 they lived in a cycled class and
// were abandoned by a reconfiguration. See kdex-tech/host-manager#245.

// valkeyTokenManager wires a TokenManager the way the controller does: the
// surviving store plus the legacy cycled class it replaced.
func valkeyTokenManager(t *testing.T) (*TokenManager, cache.CacheManager) {
	t.Helper()
	s := miniredis.RunT(t)
	cm, err := cache.NewCacheManager(s.Addr(), "host-a", nil)
	require.NoError(t, err)
	tm, err := NewTokenManager("test-issuer", GenerateDevmodeKeyPair(),
		cm.GetCache(RevocationClass, RevocationCacheOptions()))
	require.NoError(t, err)
	tm.WithLegacyRevocationCache(cm.GetCache(LegacyRevocationClass, cache.CacheOptions{}))
	return tm, cm
}

func TestRevocation_SurvivesHostReconfigurations(t *testing.T) {
	ctx := context.Background()
	tm, cm := valkeyTokenManager(t)
	token, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)
	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", 0))

	for _, generation := range []string{"g1", "g2", "g3", "g3"} {
		require.NoError(t, cm.Cycle(generation, false))
	}

	_, err = tm.ValidateToken(ctx, token, "aud")
	assert.Error(t, err)
}

// During a rolling upgrade a replica still on v0.27.x writes only the legacy
// class, and a rollback reads only it; both directions must see a revocation.
func TestRevocation_LegacyClassIsReadAndWritten(t *testing.T) {
	ctx := context.Background()
	tm, cm := valkeyTokenManager(t)
	legacy := cm.GetCache(LegacyRevocationClass, cache.CacheOptions{})

	t.Run("read", func(t *testing.T) {
		token, err := tm.MintStatelessKey("aud", "bob", "ci", "", time.Hour)
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
		require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "bob", "ci"),
			time.Now().UTC().Format(time.RFC3339Nano), cache.WithTTL(time.Hour)))

		_, err = tm.ValidateToken(ctx, token, "aud")
		assert.Error(t, err, "a revocation an old replica wrote is honoured")
	})

	t.Run("write", func(t *testing.T) {
		require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "carol", "laptop", 0))
		_, found, _, err := legacy.Get(ctx, GenerateJTI("aud", "carol", "laptop"))
		require.NoError(t, err)
		assert.True(t, found, "an old replica, or a rollback, sees the revocation")
	})
}

func TestRevokeSubject_RevokesEveryTokenIssuedUpToIt(t *testing.T) {
	ctx := context.Background()
	tm, _ := valkeyTokenManager(t)
	mint := func(aud, sub, act string) string {
		t.Helper()
		token, err := tm.MintStatelessKey(aud, sub, act, "", time.Hour)
		require.NoError(t, err)
		return token
	}
	laptop := mint("aud", "alice", "laptop")
	unrecorded := mint("aud", "alice", "never-recorded")
	otherAudience := mint("other-aud", "alice", "laptop")
	otherSubject := mint("aud", "bob", "laptop")

	require.NoError(t, tm.RevokeSubject(ctx, "aud", "alice", 0))
	time.Sleep(time.Millisecond)
	resignup := mint("aud", "alice", "laptop")

	for name, token := range map[string]string{"laptop": laptop, "unrecorded act": unrecorded} {
		_, err := tm.ValidateToken(ctx, token, "aud")
		assert.Error(t, err, name)
	}
	_, err := tm.ValidateToken(ctx, otherAudience, "other-aud")
	assert.NoError(t, err, "a subject is revoked per audience")
	_, err = tm.ValidateToken(ctx, otherSubject, "aud")
	assert.NoError(t, err, "another subject is untouched")
	_, err = tm.ValidateToken(ctx, resignup, "aud")
	assert.NoError(t, err, "a token minted after the cutoff (a re-signup) is valid")
}

func TestRevokeSubject_CannotBeShortenedOrMovedBack(t *testing.T) {
	ctx := context.Background()
	tm, _ := valkeyTokenManager(t)
	key := subjectRevocationKey("aud", "alice")
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	require.NoError(t, tm.revocationCache.Set(ctx, key, later))

	require.NoError(t, tm.RevokeSubject(ctx, "aud", "alice", time.Millisecond))

	stored, found, _, err := tm.revocationCache.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, later, stored)
}

// The subject key cannot be produced by any (aud, sub, act), and an aud or
// sub containing the separator cannot impersonate another pair.
func TestSubjectRevocationKey_IsUnambiguous(t *testing.T) {
	assert.NotEqual(t, subjectRevocationKey("a:b", "c"), subjectRevocationKey("a", "b:c"))
	assert.NotEqual(t, subjectRevocationKey("aud", "alice"), GenerateJTI("aud", "alice", ""))
}

// The one-time sweep recovers the revocations earlier generations stranded.
func TestAdoptStrandedRevocations(t *testing.T) {
	ctx := context.Background()
	tm, cm := valkeyTokenManager(t)
	legacy := cm.GetCache(LegacyRevocationClass, cache.CacheOptions{})
	at := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339Nano) }

	stranded, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)

	require.NoError(t, cm.Cycle("g1", false))
	require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "alice", "laptop"), at(time.Minute), cache.WithTTL(time.Hour)))
	require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "dave", "ci"), "revoked", cache.WithTTL(time.Hour)))
	require.NoError(t, cm.Cycle("g2", false))
	// An older revocation of the same key in a later generation: the sweep
	// keeps the latest time, whichever generation holds it.
	require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "alice", "laptop"), at(-time.Hour), cache.WithTTL(time.Hour)))
	require.NoError(t, cm.Cycle("g3", false))
	require.NoError(t, cm.Cycle("g4", false))

	// A revocation already in the surviving store is never overwritten.
	current := at(2 * time.Hour)
	require.NoError(t, tm.revocationCache.Set(ctx, GenerateJTI("aud", "dave", "ci"), current))

	_, err = tm.ValidateToken(ctx, stranded, "aud")
	require.NoError(t, err, "precondition: four generations later the revocation is unreachable")

	adopted, err := tm.AdoptStrandedRevocations(ctx, cm)
	require.NoError(t, err)
	assert.Equal(t, 1, adopted)

	_, err = tm.ValidateToken(ctx, stranded, "aud")
	assert.Error(t, err, "the stranded revocation is in force again")

	stored, _, _, err := tm.revocationCache.Get(ctx, GenerateJTI("aud", "dave", "ci"))
	require.NoError(t, err)
	assert.Equal(t, current, stored)

	again, err := tm.AdoptStrandedRevocations(ctx, cm)
	require.NoError(t, err)
	assert.Zero(t, again, "the sweep is idempotent")
}

// A legacy entry with no timestamp revokes outright, so it outranks any time.
func TestLatestRevocation(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	t2 := time.Date(2026, 1, 1, 0, 0, 0, 5, time.UTC).Format(time.RFC3339Nano)
	assert.Equal(t, t2, latestRevocation(t1, t2))
	assert.Equal(t, t2, latestRevocation(t2, t1))
	assert.Equal(t, "revoked", latestRevocation(t2, "revoked"))
	assert.Equal(t, "revoked", latestRevocation("revoked", t1))
}

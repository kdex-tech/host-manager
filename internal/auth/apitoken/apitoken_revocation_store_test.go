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

// Revocations are state a request created, so they live in the scope that
// survives host generations; until v0.28.0 they lived in a cycled class and
// were abandoned by a reconfiguration. See kdex-tech/host-manager#245.

// valkeyTokenManager wires a TokenManager the way the controller does, from
// RevocationCaches.
func valkeyTokenManager(t *testing.T) (*TokenManager, cache.CacheManager) {
	t.Helper()
	s := miniredis.RunT(t)
	cm, err := cache.NewCacheManager(s.Addr(), "host-a", nil)
	require.NoError(t, err)
	store, legacy := RevocationCaches(cm)
	tm, err := NewTokenManager("test-issuer", GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	tm.WithLegacyRevocationCache(legacy)
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
// LEGACY(#259).
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
	resource := mint("https://host/mcp", "alice", "mcp")
	otherSubject := mint("aud", "bob", "laptop")

	require.NoError(t, tm.RevokeSubject(ctx, "alice", 0))
	time.Sleep(time.Millisecond)
	resignup := mint("aud", "alice", "laptop")

	for name, tc := range map[string]struct{ token, aud string }{
		"recorded act":      {laptop, "aud"},
		"unrecorded act":    {unrecorded, "aud"},
		"resource audience": {resource, "https://host/mcp"},
	} {
		_, err := tm.ValidateToken(ctx, tc.token, tc.aud)
		assert.Error(t, err, name)
	}
	_, err := tm.ValidateToken(ctx, otherSubject, "aud")
	assert.NoError(t, err, "another subject is untouched")
	_, err = tm.ValidateToken(ctx, resignup, "aud")
	assert.NoError(t, err, "a token minted after the cutoff (a re-signup) is valid")
}

// The paths that issue new credentials ask whether the authentication behind
// a request predates the subject's revocation.
func TestSubjectRevokedSince(t *testing.T) {
	ctx := context.Background()
	tm, _ := valkeyTokenManager(t)
	before := time.Now()

	revoked, err := tm.SubjectRevokedSince(ctx, "alice", before)
	require.NoError(t, err)
	assert.False(t, revoked, "never revoked")

	require.NoError(t, tm.RevokeSubject(ctx, "alice", 0))
	revoked, err = tm.SubjectRevokedSince(ctx, "alice", before)
	require.NoError(t, err)
	assert.True(t, revoked, "authenticated before the cutoff")

	revoked, err = tm.SubjectRevokedSince(ctx, "alice", time.Now().Add(time.Second))
	require.NoError(t, err)
	assert.False(t, revoked, "authenticated after the cutoff")

	revoked, err = tm.SubjectRevokedSince(ctx, "bob", before)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRevokeSubject_CannotBeShortenedOrMovedBack(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	cm, err := cache.NewCacheManager(s.Addr(), "host-a", nil)
	require.NoError(t, err)
	store, _ := RevocationCaches(cm)
	tm, err := NewTokenManager("test-issuer", GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	key := subjectRevocationKey("alice")
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	require.NoError(t, tm.revocationCache.Set(ctx, key, later, cache.WithTTL(time.Minute)))

	require.NoError(t, tm.RevokeSubject(ctx, "alice", time.Millisecond))

	stored, found, _, err := tm.revocationCache.Get(ctx, key)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, later, stored)
	full := ""
	for _, k := range s.Keys() {
		if len(k) > 3 && k[len(k)-len(key):] == key {
			full = k
		}
	}
	assert.Greater(t, s.TTL(full), RevocationHorizon/2, "the ttl is raised to the revocation lifetime")
}

func TestSubjectRevocationKey_CannotCollideWithAJTI(t *testing.T) {
	assert.NotEqual(t, subjectRevocationKey("alice"), GenerateJTI("", "alice", ""))
	assert.Regexp(t, `^sub:[0-9a-f]{64}$`, subjectRevocationKey("alice"))
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

	// A newer revocation already in the store is kept; an older one gives way
	// to the newer one a v0.27.x replica stranded (revoke, re-mint, revoke).
	current := at(2 * time.Hour)
	require.NoError(t, tm.revocationCache.Set(ctx, GenerateJTI("aud", "erin", "ci"), current))
	require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "erin", "ci"), at(time.Hour), cache.WithTTL(time.Hour)))
	require.NoError(t, tm.revocationCache.Set(ctx, GenerateJTI("aud", "frank", "ci"), at(-2*time.Hour)))
	require.NoError(t, legacy.Set(ctx, GenerateJTI("aud", "frank", "ci"), at(time.Hour), cache.WithTTL(time.Hour)))

	_, err = tm.ValidateToken(ctx, stranded, "aud")
	require.NoError(t, err, "precondition: four generations later the revocation is unreachable")

	adopted, err := tm.AdoptStrandedRevocations(ctx, cm)
	require.NoError(t, err)
	assert.Equal(t, 3, adopted, "alice and dave adopted, frank strengthened, erin kept")

	_, err = tm.ValidateToken(ctx, stranded, "aud")
	assert.Error(t, err, "the stranded revocation is in force again")

	stored, _, _, err := tm.revocationCache.Get(ctx, GenerateJTI("aud", "erin", "ci"))
	require.NoError(t, err)
	assert.Equal(t, current, stored)
	stored, _, _, err = tm.revocationCache.Get(ctx, GenerateJTI("aud", "frank", "ci"))
	require.NoError(t, err)
	assert.Equal(t, at(time.Hour)[:16], stored[:16], "the newer stranded revocation wins")
	stored, _, _, err = tm.revocationCache.Get(ctx, GenerateJTI("aud", "dave", "ci"))
	require.NoError(t, err)
	assert.Equal(t, "revoked", stored, "an outright legacy revocation is adopted as is")

	again, err := tm.AdoptStrandedRevocations(ctx, cm)
	require.NoError(t, err)
	assert.Zero(t, again, "the sweep is idempotent")
}

// Two times compare as times; a timed value is a later write than an untimed
// one, which predates revocation timestamps, whichever argument holds it.
func TestLatestRevocation(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	t2 := time.Date(2026, 1, 1, 0, 0, 0, 5, time.UTC).Format(time.RFC3339Nano)
	assert.Equal(t, t2, latestRevocation(t1, t2))
	assert.Equal(t, t2, latestRevocation(t2, t1))
	assert.Equal(t, t1, latestRevocation(t1, "revoked"))
	assert.Equal(t, t1, latestRevocation("revoked", t1))
	assert.Equal(t, "revoked", latestRevocation("revoked", "also-untimed"))
}

// A key revoked before revocations carried a time, then re-revoked (which
// replaced the untimed value with a time) and re-minted, must not be revoked
// outright again by the sweep finding the untimed value in an old generation.
func TestAdoptStrandedRevocations_DoesNotReimposeAnUntimedRevocation(t *testing.T) {
	ctx := context.Background()
	tm, cm := valkeyTokenManager(t)
	legacy := cm.GetCache(LegacyRevocationClass, cache.CacheOptions{})
	jti := GenerateJTI("aud", "alice", "laptop")

	require.NoError(t, cm.Cycle("g1", false))
	require.NoError(t, legacy.Set(ctx, jti, "revoked", cache.WithTTL(time.Hour)))
	require.NoError(t, cm.Cycle("g2", false))
	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", 0))
	time.Sleep(time.Millisecond)
	reminted, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)

	_, err = tm.AdoptStrandedRevocations(ctx, cm)
	require.NoError(t, err)

	_, err = tm.ValidateToken(ctx, reminted, "aud")
	assert.NoError(t, err)
}

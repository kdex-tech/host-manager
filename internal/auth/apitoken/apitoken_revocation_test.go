package apitoken

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A revocation must outlive every token it revokes, and nobody may shorten it.
// It records when it happened, so it revokes the tokens issued up to then and
// not a key re-minted under the same name afterwards. See
// kdex-tech/host-manager#238 (quad 2).

func nextSecond() {
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 20*time.Millisecond)))
}

func TestRevokeByMetadata_RevokesTokensIssuedUpToTheRevocationOnly(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)

	before, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)
	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", 0))
	nextSecond()
	after, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)

	_, err = tm.ValidateToken(ctx, before, "aud")
	assert.Error(t, err, "a token issued before the revocation is revoked")
	_, err = tm.ValidateToken(ctx, after, "aud")
	assert.NoError(t, err, "a key re-minted under the same name after the revocation is not")
}

func TestRevokeByMetadata_CannotBeShortened(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)
	token, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)

	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", time.Millisecond))
	time.Sleep(20 * time.Millisecond)

	_, err = tm.ValidateToken(ctx, token, "aud")
	assert.Error(t, err, "a 1ms revocation is raised to the revocation lifetime, so the token stays revoked")
}

// Entries written before revocations carried a timestamp still revoke.
func TestValidateToken_LegacyRevocationStillRevokes(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)
	token, err := tm.MintStatelessKey("aud", "alice", "laptop", "", time.Hour)
	require.NoError(t, err)
	require.NoError(t, tm.revocationCache.Set(ctx, GenerateJTI("aud", "alice", "laptop"), "revoked"))

	_, err = tm.ValidateToken(ctx, token, "aud")
	assert.Error(t, err)
}

func TestRevocationTTL(t *testing.T) {
	tm := subjectlessTokenManager(t)
	assert.Equal(t, RevocationHorizon, tm.RevocationTTL(), "an unbounded host revokes for the horizon")
	tm.WithMaxTTL(2 * RevocationHorizon)
	assert.Equal(t, 2*RevocationHorizon, tm.RevocationTTL(), "never shorter than the longest mintable token")
}

// Two host reconfigurations rotate a cycled cache's generations away, and a
// revocation with them.
func TestRevocationCacheOptions_AreUncycled(t *testing.T) {
	assert.True(t, RevocationCacheOptions().Uncycled)
}

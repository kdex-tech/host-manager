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

func TestRevokeByMetadata_RevokesTokensIssuedUpToTheRevocationOnly(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)

	before, err := tm.MintStatelessKey("aud", "alice", "User", "laptop", "", time.Hour)
	require.NoError(t, err)
	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", 0))
	// iat carries sub-second precision, so a key re-minted in the same second
	// as the revocation is not revoked on arrival.
	time.Sleep(time.Millisecond)
	after, err := tm.MintStatelessKey("aud", "alice", "User", "laptop", "", time.Hour)
	require.NoError(t, err)

	_, err = tm.ValidateToken(ctx, before, "aud")
	assert.Error(t, err, "a token issued before the revocation is revoked")
	_, err = tm.ValidateToken(ctx, after, "aud")
	assert.NoError(t, err, "a key re-minted under the same name after the revocation is not")
}

func TestRevokeByMetadata_CannotBeShortened(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)
	token, err := tm.MintStatelessKey("aud", "alice", "User", "laptop", "", time.Hour)
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
	token, err := tm.MintStatelessKey("aud", "alice", "User", "laptop", "", time.Hour)
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

// A re-revocation on a replica whose clock lags must not move the revocation
// back in time and re-admit the tokens issued in between.
func TestRevoke_NeverMovesARevocationBackInTime(t *testing.T) {
	ctx := context.Background()
	tm := subjectlessTokenManager(t)
	jti := GenerateJTI("aud", "alice", "laptop")
	later := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	require.NoError(t, tm.revocationCache.Set(ctx, jti, later))

	require.NoError(t, tm.RevokeByMetadata(ctx, "aud", "alice", "laptop", 0))

	stored, found, _, err := tm.revocationCache.Get(ctx, jti)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, later, stored)
}

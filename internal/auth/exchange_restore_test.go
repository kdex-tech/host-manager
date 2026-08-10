package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errRotateWriteFailed = errors.New("rotate write failed")

// restoreTestCache fails the ROTATION's write while letting the restore of
// the original record through, which is what isolates the #172 trigger: the
// token is consumed, minting succeeds, and only the write of the SUCCESSOR
// fails. Keyed on the token id because the rotation writes a fresh random id
// while the restore writes the consumed one back.
//
// failAllSets escalates to the case where the restore ITSELF cannot land.
type restoreTestCache struct {
	cache.Cache
	consumedID  string
	armed       atomic.Bool
	failAllSets atomic.Bool
	restoreTTL  atomic.Pointer[time.Duration]
}

func (c *restoreTestCache) Set(ctx context.Context, key, value string, opts ...cache.SetOption) error {
	if c.armed.Load() {
		if c.failAllSets.Load() {
			return errRotateWriteFailed
		}
		if key != c.consumedID {
			// The rotation's successor token.
			return errRotateWriteFailed
		}
		// The restore. Capture the TTL it asked for.
		var so cache.SetOptions
		for _, o := range opts {
			o(&so)
		}
		if so.TTL != nil {
			c.restoreTTL.Store(so.TTL)
		}
	}
	return c.Cache.Set(ctx, key, value, opts...)
}

// newRestoreFixture creates a live refresh token and wraps the refresh cache
// so the next redemption's rotation write fails.
func newRestoreFixture(t *testing.T) (*Exchanger, *restoreTestCache, string) {
	t.Helper()
	ex := newRotationTestExchanger(t)

	tokenID, err := ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Scope:      "openid",
		Subject:    "alice",
	})
	require.NoError(t, err)

	c := &restoreTestCache{Cache: ex.refreshTokenCache, consumedID: tokenID}
	ex.refreshTokenCache = c
	return ex, c, tokenID
}

// TestRedeemRefreshToken_RestoresSessionOnRotateFailure pins
// kdex-tech/host-manager#172.
//
// GetAndDelete consumes the token BEFORE any validation or minting, which is
// what makes rotation single-use (#71). But if a later step fails for an
// infrastructure reason, the token is already gone: the client gets a 500
// ("retryable"), retries with the same token, and is told 400 invalid_grant
// ("your credential is dead, re-authorize"). One transient blip logs the user
// out of a 72h session.
//
// A compensating restore on the ErrServerError paths gives the retry
// something to succeed against.
func TestRedeemRefreshToken_RestoresSessionOnRotateFailure(t *testing.T) {
	ex, c, tokenID := newRestoreFixture(t)
	ctx := context.Background()

	c.armed.Store(true)
	_, err := ex.RedeemRefreshToken(ctx, tokenID, "app")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a failed rotation write is OUR infrastructure and must stay classified as a server error")

	// The retry the client will actually make.
	c.armed.Store(false)
	ts, err := ex.RedeemRefreshToken(ctx, tokenID, "app")

	require.NoError(t, err,
		"the consumed record must have been restored, so the client's retry succeeds instead of being told to re-authorize")
	assert.NotEmpty(t, ts.RefreshToken, "the successful retry must rotate normally")
}

// TestRedeemRefreshToken_RestoreKeepsRemainingTTL guards the detail a naive
// restore gets wrong. The refresh-token cache is created with a DEFAULT TTL
// of refreshTokenTTL, and createRefreshToken writes with no explicit TTL — so
// a plain Set on the restore path silently renews the record for a fresh full
// term, extending it past its original expiry.
func TestRedeemRefreshToken_RestoreKeepsRemainingTTL(t *testing.T) {
	ex, c, tokenID := newRestoreFixture(t)

	c.armed.Store(true)
	_, err := ex.RedeemRefreshToken(context.Background(), tokenID, "app")
	require.Error(t, err)

	ttl := c.restoreTTL.Load()
	require.NotNil(t, ttl,
		"the restore must pass an explicit TTL; without one the cache's default renews the record for a full fresh term")
	assert.LessOrEqual(t, *ttl, ex.refreshTokenTTL,
		"the restored record must never outlive the original's expiry")
	assert.Greater(t, *ttl, time.Duration(0),
		"the restored record must still be usable")
}

// TestRedeemRefreshToken_DoesNotRestoreOnUnmarshalFailure is the ruling that
// an unparseable record is NOT put back. Restoring it would guarantee a
// repeat of the same failure on every future redemption for the remaining
// term — a poison pill — where dropping it costs one re-authorization and
// self-heals.
func TestRedeemRefreshToken_DoesNotRestoreOnUnmarshalFailure(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	require.NoError(t, ex.refreshTokenCache.Set(ctx, "corrupt-token", "{not valid json"))

	_, err := ex.RedeemRefreshToken(ctx, "corrupt-token", "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError), "an unparseable stored record is our problem, not the caller's")

	_, err = ex.RedeemRefreshToken(ctx, "corrupt-token", "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGrantFailure),
		"the corrupt record must be GONE, so the retry gets a clean not-found and the client re-authorizes rather than looping on 500s")
}

// TestRedeemRefreshToken_DoesNotRestoreOnGrantFailure covers the other half
// of the gate: the three rejections that are genuinely ABOUT the presented
// grant are legitimate consumptions. Restoring those would hand back a token
// the server just decided was invalid.
func TestRedeemRefreshToken_DoesNotRestoreOnGrantFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		claims     RefreshTokenClaims
		redeemWith string
	}{
		{
			name: "expired",
			claims: RefreshTokenClaims{
				AuthMethod: AuthMethodLocal, ClientID: "app", Subject: "alice",
				ExpiresAt: time.Now().Add(-time.Hour).Unix(),
			},
			redeemWith: "app",
		},
		{
			name: "client mismatch",
			claims: RefreshTokenClaims{
				AuthMethod: AuthMethodLocal, ClientID: "app", Subject: "alice",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			redeemWith: "someone-else",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newRotationTestExchanger(t)
			ctx := context.Background()

			payload, err := json.Marshal(tc.claims)
			require.NoError(t, err)
			require.NoError(t, ex.refreshTokenCache.Set(ctx, "grant-fail-token", string(payload)))

			_, err = ex.RedeemRefreshToken(ctx, "grant-fail-token", tc.redeemWith)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrGrantFailure), "precondition: this must be a grant failure, not a server error")

			_, err = ex.RedeemRefreshToken(ctx, "grant-fail-token", tc.redeemWith)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrGrantFailure),
				"a legitimately rejected token must stay consumed; restoring it would resurrect a credential the server just rejected")
		})
	}
}

// TestRedeemRefreshToken_RestoreFailureReturnsOriginalError: if the
// compensating write itself fails, the caller must still see the failure that
// actually happened. Masking it with the restore's error would report a
// different outage than the one that occurred.
func TestRedeemRefreshToken_RestoreFailureReturnsOriginalError(t *testing.T) {
	ex, c, tokenID := newRestoreFixture(t)

	c.armed.Store(true)
	c.failAllSets.Store(true)

	_, err := ex.RedeemRefreshToken(context.Background(), tokenID, "app")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a failed restore must degrade to today's behaviour, still classified as a server error")
	assert.Contains(t, err.Error(), "rotate",
		"the ORIGINAL failure must be what surfaces, not the restore's own error")
}

// TestRedeemRefreshToken_SuccessfulRotationDoesNotRestore is the #71
// non-regression guard, stated as behaviour rather than as a comment.
//
// The restore is safe only because no ErrServerError return exists downstream
// of a successful createRefreshToken — publishToGrace failing is logged, not
// returned — so a restored predecessor can never coexist with a live
// successor. If someone later adds an ErrServerError return after the
// rotation, this test fails and the single-lineage guarantee is visibly at
// risk rather than silently broken.
func TestRedeemRefreshToken_SuccessfulRotationDoesNotRestore(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal, ClientID: "app", Subject: "alice",
	})
	require.NoError(t, err)

	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err, "precondition: this rotation must succeed")

	raw, found, _, err := ex.refreshTokenCache.GetAndDelete(ctx, tokenID)
	require.NoError(t, err)
	assert.False(t, found,
		"a successfully rotated predecessor must stay consumed — restoring it alongside its live successor would create the second lineage #71 exists to prevent")
	assert.Empty(t, raw)
}

// TestRedeemRefreshToken_RestoreDoesNotResurrectARevokedToken closes the hole
// the quad review found in #172.
//
// RevokeRefreshToken revokes BY DELETING. The #172 restore is a blind Set with
// no way to tell "consumed by me" from "revoked while I held it", so a logout
// racing a failing redemption is silently undone:
//
//  1. RedeemRefreshToken consumes T via GetAndDelete.
//  2. The user logs out. RevokeRefreshToken(T) finds nothing — already
//     consumed — clears the grace records and returns success.
//  3. The redemption then fails with ErrServerError.
//  4. The deferred restore writes T back with its remaining TTL.
//
// T is live again for the rest of its term (72h on the knowdrive dev host), so
// the session survives an explicit logout. That is the replay window #84 exists
// to close, reopened by the compensation for #172.
func TestRedeemRefreshToken_RestoreDoesNotResurrectARevokedToken(t *testing.T) {
	ex, c, tokenID := newRestoreFixture(t)
	ctx := context.Background()

	// The user logs out WHILE the redemption below is in flight. At this point
	// the token is not yet consumed, so this is the ordinary revoke path.
	require.NoError(t, ex.RevokeRefreshToken(ctx, tokenID))

	// Re-seed as though the redemption had consumed it first: this is the race
	// window — consumed, then revoked, then the redemption fails.
	payload, err := json.Marshal(RefreshTokenClaims{
		AuthMethod: AuthMethodLocal, ClientID: "app", Scope: "openid", Subject: "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	require.NoError(t, ex.refreshTokenCache.Set(ctx, tokenID, string(payload)))
	require.NoError(t, ex.RevokeRefreshToken(ctx, tokenID))
	require.NoError(t, ex.refreshTokenCache.Set(ctx, tokenID, string(payload)))

	c.armed.Store(true)
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrServerError), "precondition: the rotation write must fail")

	// The restore must NOT have resurrected a revoked token.
	c.armed.Store(false)
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")

	require.Error(t, err,
		"a revoked refresh token must stay dead; the #172 restore must not undo a logout")
	assert.True(t, errors.Is(err, ErrGrantFailure),
		"the resurrected-token redemption must be rejected as a grant failure, not succeed")
}

// lateRestoreCache models the loser's exact position in a concurrent burst:
// its GetAndDelete MISSES (the winner consumed the record first), and by the
// time the grace poll gives up the winner's #172 restore has landed, so a
// direct Get now finds the record.
type lateRestoreCache struct {
	cache.Cache
	tokenID string
	raw     string
}

func (c lateRestoreCache) GetAndDelete(ctx context.Context, key string) (string, bool, bool, error) {
	if key == c.tokenID {
		return "", false, false, nil // the winner got there first
	}
	return c.Cache.GetAndDelete(ctx, key)
}

func (c lateRestoreCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	if key == c.tokenID {
		return c.raw, true, true, nil // the restore has since landed
	}
	return c.Cache.Get(ctx, key)
}

// TestRedeemRefreshToken_LoserGetsRetryableErrorWhenTokenWasRestored closes the
// gap the quad review found between #169 and #172.
//
// #169 documents concurrent refresh bursts of 4-5 as ROUTINE. When the winner
// of such a burst fails with ErrServerError, #172 restores the record — but the
// losers are already past their own GetAndDelete and are polling the grace
// cache. They see the marker cleared, fall through to not-found, and are told
// 400 invalid_grant: "your credential is dead, re-authorize". Standard OAuth
// clients discard a refresh token on invalid_grant.
//
// So #172's compensation was defeated for every caller but one, in exactly the
// scenario #169 calls normal. A loser must instead be told the failure is
// RETRYABLE, because the token it presented is live again.
func TestRedeemRefreshToken_LoserGetsRetryableErrorWhenTokenWasRestored(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	raw, err := json.Marshal(RefreshTokenClaims{
		AuthMethod: AuthMethodLocal, ClientID: "app", Scope: "openid", Subject: "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	ex.refreshTokenCache = lateRestoreCache{
		Cache: ex.refreshTokenCache, tokenID: "consumed-by-winner", raw: string(raw),
	}

	_, err = ex.RedeemRefreshToken(ctx, "consumed-by-winner", "app")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"the presented token is demonstrably live again, so the loser must get a RETRYABLE "+
			"error; invalid_grant makes standard OAuth clients discard a working credential")
	assert.False(t, errors.Is(err, ErrGrantFailure),
		"it must not be classified as a fact about the grant")
}

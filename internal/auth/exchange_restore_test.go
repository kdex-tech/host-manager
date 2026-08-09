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

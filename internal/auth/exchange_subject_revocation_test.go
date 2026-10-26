package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A subject revoked on the host (/-/apitokens/revoke with all) ends every
// refresh lineage that authenticated before the revocation, or it would keep
// minting credentials, resource PATs included, past the cutoff. A lineage
// from a later authentication (a re-signup) is unaffected. See
// kdex-tech/host-manager#257.
func TestRedeemRefreshToken_EndsALineageFromBeforeTheSubjectWasRevoked(t *testing.T) {
	ctx := context.Background()
	ex := newRotationTestExchanger(t)
	cm, err := cache.NewCacheManager("", "subject-revocation-test", nil)
	require.NoError(t, err)
	store, _ := apitoken.RevocationCaches(cm)
	tm, err := apitoken.NewTokenManager("test-iss", apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	ex.config.TokenManager = tm

	lineage := func(sub string, authenticatedAt time.Time) string {
		t.Helper()
		id, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod:       AuthMethodLocal,
			ClientID:         "app",
			OriginalIssuedAt: authenticatedAt.Unix(),
			Scope:            "openid",
			Subject:          sub,
		})
		require.NoError(t, err)
		return id
	}
	stale := lineage("alice", time.Now().Add(-time.Minute))
	other := lineage("bob", time.Now().Add(-time.Minute))
	require.NoError(t, tm.RevokeSubject(ctx, "alice", 0))
	fresh := lineage("alice", time.Now().Add(2*time.Second))

	_, err = ex.RedeemRefreshToken(ctx, stale, "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGrantFailure), "the session is over, not a server fault: %v", err)

	_, err = ex.RedeemRefreshToken(ctx, other, "app")
	assert.NoError(t, err, "another subject is untouched")
	_, err = ex.RedeemRefreshToken(ctx, fresh, "app")
	assert.NoError(t, err, "a lineage from after the revocation is valid")
}

// A browser session from before the subject's revocation cannot open a new
// lineage through /-/oauth/authorize: it is treated as signed out, so a
// re-login recovers it. A code it issued before the revocation cannot be
// redeemed after it either.
func TestAuthorize_ASessionFromBeforeTheSubjectWasRevokedMustSignInAgain(t *testing.T) {
	f := newConsentFixture(t)
	cm, err := cache.NewCacheManager("", "authorize-revocation-test", nil)
	require.NoError(t, err)
	store, _ := apitoken.RevocationCaches(cm)
	tm, err := apitoken.NewTokenManager(consentIssuer, apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	f.ex.config.TokenManager = tm
	session := func(iat time.Time) map[string]any {
		s := map[string]any{"iat": float64(iat.Unix())}
		for k, v := range aliceSession {
			s[k] = v
		}
		return s
	}
	stale := session(time.Now().Add(-time.Minute))

	codeFrom(t, f.allow(t, f.query(appRedirect, nil))) // consent is held, so authorize issues a code
	early := codeFrom(t, f.authorize(f.query(appRedirect, nil), stale, COOKIE))
	require.NoError(t, tm.RevokeSubject(context.Background(), "alice", 0))

	w := f.authorize(f.query(appRedirect, nil), stale, COOKIE)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "/-/login", loc.Path)
	assert.Equal(t, "login", loc.Query().Get("prompt"), "a forced login, or the cookie sends the browser straight back")

	w = f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), stale, COOKIE)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err = w.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "login_required", loc.Query().Get("error"))

	_, err = f.ex.RedeemAuthorizationCode(context.Background(), early, f.clientID, appRedirect, f.verifier)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGrantFailure), "a code from before the revocation: %v", err)

	codeFrom(t, f.authorize(f.query(appRedirect, nil), session(time.Now().Add(2*time.Second)), COOKIE))
}

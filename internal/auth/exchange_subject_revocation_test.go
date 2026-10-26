package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"

	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// revocationTokenManager is a TokenManager on its own in-memory revocation
// store, wired as the controller wires one (apitoken.RevocationCaches).
func revocationTokenManager(t *testing.T, issuer string) *apitoken.TokenManager {
	t.Helper()
	cm, err := cache.NewCacheManager("", "subject-revocation-test", nil)
	require.NoError(t, err)
	store, _ := apitoken.RevocationCaches(cm)
	tm, err := apitoken.NewTokenManager(issuer, apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	return tm
}

// A subject revoked on the host (/-/apitokens/revoke with all) ends every
// refresh lineage that authenticated before the revocation, or it would keep
// minting credentials, resource PATs included, past the cutoff. A lineage
// from a later authentication (a re-signup) is unaffected. See
// kdex-tech/host-manager#257.
func TestRedeemRefreshToken_EndsALineageFromBeforeTheSubjectWasRevoked(t *testing.T) {
	ctx := context.Background()
	ex := newRotationTestExchanger(t)
	tm := revocationTokenManager(t, "test-iss")
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

	_, err := ex.RedeemRefreshToken(ctx, stale, "app")
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
	tm := revocationTokenManager(t, consentIssuer)
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

// canonicalizingProvider is a credential store that vouches for a login under
// its canonical subject, whatever spelling the user typed.
type canonicalizingProvider struct{ rotationStubIdentityProvider }

func (canonicalizingProvider) FindInternal(username, _ string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"sub": strings.ToLower(strings.TrimSpace(username))}, nil
}

// A local login's session carries the subject the credential store vouched
// for, not the spelling the user typed: on its first refresh it would
// otherwise re-sign under the typed name, out of reach of a revocation (and
// a role binding) written for the canonical one.
func TestLoginLocal_SessionCarriesTheVouchedSubjectNotTheTypedOne(t *testing.T) {
	ctx := context.Background()
	ex := newRotationTestExchanger(t)
	ex.sp = canonicalizingProvider{}
	tm := revocationTokenManager(t, "test-iss")
	ex.config.TokenManager = tm

	ts, err := ex.LoginLocal(ctx, "Alice@X.com ", "pw", "", "app", AuthMethodLocal)
	require.NoError(t, err)
	assert.Equal(t, "alice@x.com", ts.Subject)

	refreshed, err := ex.RedeemRefreshToken(ctx, ts.RefreshToken, "app")
	require.NoError(t, err)
	parsed, _, err := jwt.NewParser().ParseUnverified(refreshed.AccessToken, jwt.MapClaims{})
	require.NoError(t, err)
	sub, err := parsed.Claims.GetSubject()
	require.NoError(t, err)
	assert.Equal(t, "alice@x.com", sub, "the refreshed token keeps the vouched subject")

	require.NoError(t, tm.RevokeSubject(ctx, "alice@x.com", 0))
	_, err = ex.RedeemRefreshToken(ctx, refreshed.RefreshToken, "app")
	assert.True(t, errors.Is(err, ErrGrantFailure), "revoke-all by the canonical subject ends the lineage: %v", err)
}

// A local login's events carry the vouched subject, as the OIDC path's do and
// as the session's refresh and logout events will, with the typed name
// beside it, so a hook keying on subject sees one identity per session and
// an enforcing gate decides on the identity that is minted.
func TestLoginLocal_EventsCarryTheVouchedSubjectAndTheTypedName(t *testing.T) {
	bodies := make(chan EventPayload, 1)
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p EventPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		bodies <- p
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer gate.Close()
	d := NewEventDispatcher("h", []*httpEventHook{hookTo(t, "gate", gate.URL, "login", "enforcing", nil)}, logr.Discard())
	ex := newLoginTestExchangerFor(t, d, canonicalizingProvider{})

	_, err := ex.LoginLocal(context.Background(), "Alice@X.com ", "pw", "", "client", AuthMethodLocal)
	require.NoError(t, err)

	p := <-bodies
	assert.Equal(t, "alice@x.com", p.Subject)
	assert.Equal(t, "Alice@X.com ", p.LoginName)
}

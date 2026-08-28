package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// oidcFixture wires a live mock OIDC provider to a fully-built Exchanger, the
// same shape TestNewExchanger's OIDC cases assemble inline. Extracted here
// because kdex-tech/host-manager#189 and #190 need the whole
// authorization-code -> ID token -> local session -> rotation round trip, not
// just one leg of it.
type oidcFixture struct {
	ex  *Exchanger
	cfg *Config
	ctx context.Context
}

func newOIDCFixture(t *testing.T, scopes ...string) *oidcFixture {
	t.Helper()

	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	t.Cleanup(server.Close)

	cacheManager, err := cache.NewCacheManager("", "foo", new(1*time.Hour))
	require.NoError(t, err)

	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(
		cacheManager,
	).Build(&v1alpha1.Auth{
		OIDCProvider: &v1alpha1.OIDCProvider{
			OIDCProviderURL: server.URL,
			Scopes:          scopes,
		},
	})
	require.NoError(t, err)

	ih.Handler = MockOIDCProvider(*cfg)

	ex, err := NewExchanger(ctx, *cfg, cacheManager, scopeProviderForOIDC())
	require.NoError(t, err)

	return &oidcFixture{ex: ex, cfg: cfg, ctx: ctx}
}

func scopeProviderForOIDC() InternalIdentityProvider {
	return &mockScopeProvider{
		resolveIdentity: func(subject, password string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": subject}, nil
		},
		resolveRolesAndEntitlements: func(subject string) ([]string, []string, error) {
			return nil, []string{"page:read"}, nil
		},
	}
}

// TestExchangeToken_MintsARefreshToken pins kdex-tech/host-manager#189.
//
// The OIDC callback path returned a bare access token, so no refresh token
// was ever created for an OIDC session and AutoExtendSession -- which is
// gated on the `<cookie>_refresh` cookie -- could never fire. The user was
// hard-logged-out at jwt.tokenTTL no matter what refreshTokenTTL said.
func TestExchangeToken_MintsARefreshToken(t *testing.T) {
	f := newOIDCFixture(t)

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	assert.NotEmpty(t, ts.AccessToken, "the OIDC callback must mint an access token")
	assert.NotEmpty(t, ts.RefreshToken,
		"the OIDC callback must mint a refresh token, or AutoExtendSession can never "+
			"extend an OIDC session (#189)")
}

// claimsOf parses a signed token without verifying it -- the tests here care
// about what the mint PUT in the token, not about the signature, which
// TestNewExchanger already covers.
func claimsOf(t *testing.T, signed string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := new(jwt.Parser).ParseUnverified(signed, claims)
	require.NoError(t, err)
	return claims
}

// TestRedeemRefreshToken_PreservesOIDCClaims pins the half of
// kdex-tech/host-manager#189 that a naive fix silently breaks.
//
// ExchangeToken folds the IdP's OWN claims out of the verified ID token into
// the session. Rotation re-mints through mintTokensFromSubject, which knows
// only what FindInternalRolesAndEntitlements returns -- so unless the refresh
// record carries the login-time IdP claims, every one of them vanishes at the
// first rotation. That is not cosmetic: a host whose claimMappings read an
// IdP-supplied claim (public's read `vs_entitlements`) silently loses
// entitlements an hour into the session.
func TestRedeemRefreshToken_PreservesOIDCClaims(t *testing.T) {
	f := newOIDCFixture(t)

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)
	require.Equal(t, "email@foo.bar", claimsOf(t, ts.AccessToken)["email"],
		"precondition: the login token carries the IdP's email claim")

	// The middleware redeems a cookie session with an empty client_id.
	rotated, err := f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	require.NoError(t, err)

	got := claimsOf(t, rotated.AccessToken)
	assert.Equal(t, "email@foo.bar", got["email"],
		"a rotated OIDC session must still carry the IdP-supplied claims (#189)")
}

// TestRedeemRefreshToken_RotatedOIDCSessionMatchesLogin is the invariant
// #189 actually needs: whatever the login token carried, the rotated token
// carries too. Asserting one claim at a time (email) proves the carrier
// works but not that the SHAPE agrees -- and a session whose claim set
// changes an hour in is the bug, whichever claim moved.
//
// The JWT envelope (exp/iat/jti) is expected to differ; nothing else is.
func TestRedeemRefreshToken_RotatedOIDCSessionMatchesLogin(t *testing.T) {
	f := newOIDCFixture(t)

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	rotated, err := f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	require.NoError(t, err)

	assert.Equal(t, claimNames(t, ts.AccessToken), claimNames(t, rotated.AccessToken),
		"a rotated OIDC session must carry the same claims the login session did (#189)")
}

// claimNames returns the sorted claim names of a signed token, minus the
// per-mint envelope values that are expected to change on every mint.
func claimNames(t *testing.T, signed string) []string {
	t.Helper()
	names := []string{}
	for name := range claimsOf(t, signed) {
		switch name {
		case "exp", "iat", "jti":
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// TestOAuthGet_SetsBothSessionCookies pins the browser-visible half of
// kdex-tech/host-manager#189.
//
// Minting a refresh token is not enough: both AutoExtendSession branches
// (middleware.go) look the session up by the `<cookie>_refresh` COOKIE, so a
// callback that writes only the access cookie leaves the feature dead no
// matter what the exchanger produced. LoginPost (internal/host/login.go)
// writes both; this handler wrote one.
func TestOAuthGet_SetsBothSessionCookies(t *testing.T) {
	f := newOIDCFixture(t)

	o := &OAuth2{AuthConfig: f.cfg, AuthExchanger: f.ex}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/-/oauth/callback?code=alice&state=/home", nil)
	o.OAuthGet(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code, "the callback must redirect on success")

	cookies := map[string]string{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c.Value
	}

	assert.NotEmpty(t, cookies[f.cfg.CookieName],
		"the callback must set the access cookie")
	assert.NotEmpty(t, cookies[f.cfg.CookieName+"_refresh"],
		"the callback must set the refresh cookie, or AutoExtendSession can never "+
			"find the session it is meant to extend (#189)")
}

// TestAuthCodeURL_RequestsOfflineAccessWhenScoped pins the first half of
// kdex-tech/host-manager#190.
//
// AuthCodeURL passed no AuthCodeOption at all, so the provider was never
// asked for a refresh token. `offline_access` (OIDC Core 11) is the scope
// that requests one; Google's spelling is the access_type auth-URL param,
// which reading the scope alone never produces. prompt=consent rides along
// because without it Google returns a refresh token only on a user's very
// first consent for the client -- some sessions would have one and some
// would not, which is worse than none having one.
func TestAuthCodeURL_RequestsOfflineAccessWhenScoped(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	got := f.ex.AuthCodeURL("/home")

	assert.Contains(t, got, "access_type=offline",
		"offline_access in the configured scopes must reach the provider as access_type=offline (#190)")
	assert.Contains(t, got, "prompt=consent",
		"offline_access must force consent, or the refresh token is issued only once ever (#190)")
	assert.Contains(t, got, "offline_access",
		"the standard scope must still be sent for providers that honour it")
}

// TestAuthCodeURL_NoOfflineAccessByDefault is the other side of the opt-in:
// forcing a consent screen on every login is a real cost, so a host that did
// not ask for offline access must not pay it.
func TestAuthCodeURL_NoOfflineAccessByDefault(t *testing.T) {
	f := newOIDCFixture(t)

	got := f.ex.AuthCodeURL("/home")

	assert.NotContains(t, got, "access_type=offline")
	assert.NotContains(t, got, "prompt=consent")
}

// TestExchangeCode_ReturnsUpstreamRefreshToken pins the second half of
// kdex-tech/host-manager#190: ExchangeCode pulled id_token out of the
// exchanged token and dropped the *oauth2.Token, so a provider that DID
// return a refresh token had it silently discarded.
func TestExchangeCode_ReturnsUpstreamRefreshToken(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	got, err := f.ex.ExchangeCode(f.ctx, "offline-alice")
	require.NoError(t, err)

	assert.NotEmpty(t, got.RawIDToken, "the ID token is still the primary result")
	assert.Equal(t, "upstream-rt-offline-alice", got.UpstreamRefreshToken,
		"a refresh token returned by the provider must not be discarded (#190)")
}

// TestRedeemRefreshToken_RefetchesLiveClaimsFromIdP is what
// kdex-tech/host-manager#190 exists for. #189 made the login-time IdP claims
// survive rotation by replaying them; replaying them is still a snapshot, so
// a session kept its login-time view of the user for the whole of
// maxSessionAge (720h on public). With an upstream refresh token the session
// can be re-derived from the IdP instead of replayed.
//
// The mock answers the refresh grant with email=live@foo.bar, distinct from
// the email@foo.bar the authorization-code exchange issued, so a replayed
// snapshot and a re-fetch are told apart by the value itself.
func TestRedeemRefreshToken_RefetchesLiveClaimsFromIdP(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "offline-alice")
	require.NoError(t, err)
	require.NotEmpty(t, oidcTokens.UpstreamRefreshToken)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)
	require.Equal(t, "email@foo.bar", claimsOf(t, ts.AccessToken)["email"])

	rotated, err := f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	require.NoError(t, err)

	assert.Equal(t, "live@foo.bar", claimsOf(t, rotated.AccessToken)["email"],
		"rotation must re-derive the claims from the IdP when an upstream "+
			"refresh token is held, not replay the login-time snapshot (#190)")
}

// TestRedeemRefreshToken_SurvivesUnreachableIdP pins the degrade half of the
// kdex-tech/host-manager#190 trade-off. Re-deriving the session from the IdP
// is worth having only if the IdP being DOWN does not log every user of the
// tenant out at their next hourly rotation. A transport failure must fall
// back to the stored claim set -- the #189 behaviour -- not end the session.
func TestRedeemRefreshToken_SurvivesUnreachableIdP(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "offline-down")
	require.NoError(t, err)
	require.NotEmpty(t, oidcTokens.UpstreamRefreshToken)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	rotated, err := f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	require.NoError(t, err,
		"an IdP outage must not end the session (#190)")
	assert.Equal(t, "email@foo.bar", claimsOf(t, rotated.AccessToken)["email"],
		"an unreachable IdP degrades to the stored claim set, not to no claims")
}

// TestRedeemRefreshToken_EndsSessionWhenIdPRevokesTheGrant is the security
// win kdex-tech/host-manager#190 is for, and the one outcome that must NOT
// take the degrade path above. `invalid_grant` is the IdP saying this grant
// is dead -- consent withdrawn, account disabled, token revoked -- and
// replaying the stored claims there would keep a revoked user signed in for
// the whole of maxSessionAge.
func TestRedeemRefreshToken_EndsSessionWhenIdPRevokesTheGrant(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "offline-revoked")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	_, err = f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	require.Error(t, err,
		"a grant the IdP has revoked must end the session, not degrade (#190)")
	assert.False(t, errors.Is(err, ErrServerError),
		"a revoked upstream grant is a fact about the grant, not our outage -- "+
			"marking it ErrServerError would tell the client to retry a dead session")
}

// TestRedeemRefreshToken_RejectsARefreshedTokenForAnotherSubject guards the
// case where the IdP answers successfully but names someone else. Every
// downstream check -- roles, entitlements, audit -- keys on `sub`, so
// accepting it would rebind a live session to another identity. Degrading is
// not an option either: that would mint the session under the OLD subject
// carrying claims the IdP asserted about a DIFFERENT one.
func TestRedeemRefreshToken_RejectsARefreshedTokenForAnotherSubject(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "offline-imposter")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	_, err = f.ex.RedeemRefreshToken(f.ctx, ts.RefreshToken, "")
	assert.Error(t, err,
		"a refreshed id_token naming a different subject must end the session (#190)")
}

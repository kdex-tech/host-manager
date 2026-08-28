package auth

import (
	"context"
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

	rawIDToken, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, rawIDToken)
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

	rawIDToken, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, rawIDToken)
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

	rawIDToken, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)

	ts, err := f.ex.ExchangeToken(f.ctx, rawIDToken)
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

package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capabilityCookie signs a capability token exactly as mint_token.go does
// (host audience, CapUsesClaim injected past the projection) and provisions
// its bounded-use counter, so the real middleware accepts it from the cookie.
func (f *consentFixture) capabilityCookie(t *testing.T) *http.Cookie {
	t.Helper()
	cfg := &f.ex.config
	cm, err := cache.NewCacheManager("", "consent-cap-test", nil)
	require.NoError(t, err)
	cfg.MintTokenEnabled = true
	cfg.MintCapCache = cm.GetCache("cap", cache.CacheOptions{Uncycled: true})

	signer, err := sign.NewSigner(cfg.Audience, time.Minute, cfg.Issuer, &cfg.ActivePair.Private, cfg.ActivePair.KeyId, nil)
	require.NoError(t, err)
	projected, err := signer.Project(jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []string{"functions:/api/v1/files:read"},
	})
	require.NoError(t, err)
	projected[CapUsesClaim] = true
	token, err := signer.SignProjected(projected)
	require.NoError(t, err)

	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	jti, _ := parsed.Claims.(jwt.MapClaims)["jti"].(string)
	require.NotEmpty(t, jti)
	require.NoError(t, cfg.MintCapCache.Set(context.Background(), "uses:"+jti, "32", cache.WithTTL(time.Minute)))

	return &http.Cookie{Name: cfg.CookieName, Value: token}
}

// A capability token is a host-audience JWT the middleware accepts from the
// session cookie like any session. Through the real middleware it must not
// reach the consent page, record a consent, or get a code for a dynamically
// registered client, even with a same-origin Origin on the POST.
func TestConsent_CapabilityTokenInTheCookieGetsNoCodeThroughTheMiddleware(t *testing.T) {
	f := newConsentFixture(t)
	cookie := f.capabilityCookie(t)
	authorize := f.ex.config.WithAuthentication(f.ex)(http.HandlerFunc(f.o.AuthorizeHandler))
	consent := f.ex.config.WithAuthentication(f.ex)(http.HandlerFunc(f.o.ConsentPost))
	q := f.query(appRedirect, nil)

	get := func(q url.Values) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, OAuthAuthorizePath+"?"+q.Encode(), nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		authorize.ServeHTTP(w, r)
		return w
	}
	noCode := func(w *httptest.ResponseRecorder, step string) {
		t.Helper()
		loc, _ := url.Parse(w.Header().Get("Location"))
		if loc != nil {
			assert.Empty(t, loc.Query().Get("code"), "%s: no code", step)
		}
	}

	w := get(q)
	assert.Equal(t, http.StatusSeeOther, w.Code, "authorize: treated as signed out")
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"), "authorize: login redirect, not the page")
	noCode(w, "authorize")

	// The page would have carried a sealed request for this subject.
	sealed, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: q.Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)
	form := url.Values{"request": {sealed}, "decision": {"allow"}}
	r := httptest.NewRequest(http.MethodPost, OAuthConsentPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", consentIssuer)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	consent.ServeHTTP(w, r)
	assert.Equal(t, http.StatusForbidden, w.Code, "consent POST refused")
	assert.Empty(t, w.Header().Get("Location"))

	ok, err := f.ex.config.DCRConsent.Covers(context.Background(), "alice", f.clientID, appRedirect, nil)
	require.NoError(t, err)
	assert.False(t, ok, "no consent recorded")

	w = get(q)
	noCode(w, "authorize after the POST")
	w = get(f.query(appRedirect, url.Values{"prompt": {"none"}}))
	noCode(w, "prompt=none")
}

// consentMiddleware is the authorize and consent handlers behind the real
// WithAuthentication, driven with a session cookie.
type consentMiddleware struct {
	f         *consentFixture
	authorize http.Handler
	consent   http.Handler
}

func (f *consentFixture) middleware() *consentMiddleware {
	mw := f.ex.config.WithAuthentication(f.ex)
	return &consentMiddleware{
		f:         f,
		authorize: mw(http.HandlerFunc(f.o.AuthorizeHandler)),
		consent:   mw(http.HandlerFunc(f.o.ConsentPost)),
	}
}

func (m *consentMiddleware) get(q url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, OAuthAuthorizePath+"?"+q.Encode(), nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	m.authorize.ServeHTTP(w, r)
	return w
}

// post sends a decision with a same-origin Origin, which a script can forge.
func (m *consentMiddleware) post(sealed, decision string, cookie *http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"request": {sealed}, "decision": {decision}}
	r := httptest.NewRequest(http.MethodPost, OAuthConsentPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", consentIssuer)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	m.consent.ServeHTTP(w, r)
	return w
}

// allow drives page -> Allow -> back to authorize, and returns the code.
func (m *consentMiddleware) allow(t *testing.T, q url.Values, cookie *http.Cookie) string {
	t.Helper()
	w := m.post(sealedFrom(t, m.get(q, cookie)), "allow", cookie)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	return codeFrom(t, m.get(loc.Query(), cookie))
}

// signedOut asserts authorize answered with the login redirect and no code.
func signedOut(t *testing.T, w *httptest.ResponseRecorder, step string) {
	t.Helper()
	assert.Equal(t, http.StatusSeeOther, w.Code, "%s: %s", step, w.Body.String())
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"), "%s: login redirect, not the page", step)
	assert.NotContains(t, w.Header().Get("Location"), "code=", step)
}

func (f *consentFixture) cookie(token string) *http.Cookie {
	return &http.Cookie{Name: f.ex.config.CookieName, Value: token}
}

func (f *consentFixture) registerClient(t *testing.T, name string) string {
	t.Helper()
	c, err := f.ex.config.DCRStore.Register(context.Background(), dcr.Client{
		RedirectURIs: []string{appRedirect},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ClientName:   name,
	})
	require.NoError(t, err)
	return c.ClientID
}

// Tokens minted for an OAuth client name the user, are signed by this host
// and are accepted from the session cookie. Through the real middleware they
// must not act as the user's browser session for another dynamically
// registered client: no page, no recorded consent, no code, even with a
// same-origin Origin. The user's own login session still completes the flow.
func TestConsent_OAuthClientTokensInTheCookieGetNoCodeThroughTheMiddleware(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	m := f.middleware()

	login, err := f.ex.LoginLocal(ctx, "alice", "pw", "", "", AuthMethodLocal)
	require.NoError(t, err)
	browser := f.cookie(login.AccessToken)

	// Alice allows client A, and A redeems its code.
	code := m.allow(t, f.query(appRedirect, nil), browser)
	issued, err := f.ex.RedeemAuthorizationCode(ctx, code, f.clientID, appRedirect, f.verifier)
	require.NoError(t, err)
	require.NotEmpty(t, issued.IDToken, "openid was granted")

	clientB := f.registerClient(t, "Other App")
	qB := f.queryFor(clientB, appRedirect, nil)

	for name, token := range map[string]string{"access token": issued.AccessToken, "id_token": issued.IDToken} {
		t.Run(name, func(t *testing.T) {
			cookie := f.cookie(token)
			signedOut(t, m.get(qB, cookie), "authorize")

			// The sealed request the page would have carried for alice.
			sealed, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
				Query: qB.Encode(), Exp: time.Now().Add(time.Minute).Unix()})
			require.NoError(t, err)
			w := m.post(sealed, "allow", cookie)
			assert.Equal(t, http.StatusForbidden, w.Code, "consent POST refused")
			assert.Empty(t, w.Header().Get("Location"))

			ok, err := f.ex.config.DCRConsent.HasClient(ctx, "alice", clientB, []string{appRedirect})
			require.NoError(t, err)
			assert.False(t, ok, "no consent recorded")

			signedOut(t, m.get(qB, cookie), "authorize after the POST")
			w = m.get(f.queryFor(clientB, appRedirect, url.Values{"prompt": {"none"}}), cookie)
			loc, err := w.Result().Location()
			require.NoError(t, err)
			assert.Empty(t, loc.Query().Get("code"), "prompt=none")
			assert.Equal(t, "login_required", loc.Query().Get("error"))
		})
	}

	// Alice's own browser session completes the flow for B.
	m.allow(t, qB, browser)
}

// A session minted before auth_method was signed carries none. It is treated
// as signed out for dynamically registered clients, so the user logs in once
// more, and it keeps working for static clients and ordinary pages.
func TestConsent_SessionWithoutAuthMethodIsSignedOutOnlyForDCRClients(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	m := f.middleware()

	// Mint a real local session, then re-sign its claims without
	// auth_method: the token a host signed before the claim was projected.
	login, err := f.ex.LoginLocal(ctx, "alice", "pw", "", "", AuthMethodLocal)
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(login.AccessToken, claims)
	require.NoError(t, err)
	for _, k := range []string{"auth_method", "exp", "iat", "jti"} {
		delete(claims, k)
	}
	token, err := f.ex.config.Signer.SignProjected(claims)
	require.NoError(t, err)
	cookie := f.cookie(token)

	signedOut(t, m.get(f.query(appRedirect, nil), cookie), "dcr client")

	f.ex.config.Clients["static-app"] = AuthClient{ClientID: "static-app", Public: true, RedirectURIs: []string{appRedirect}}
	codeFrom(t, m.get(f.queryFor("static-app", appRedirect, nil), cookie))

	var subject string
	page := f.ex.config.WithAuthentication(f.ex)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ac, ok := GetAuthContext(r.Context()); ok {
			subject, _ = ac.GetSubject()
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "/some/page", nil)
	r.AddCookie(cookie)
	page.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "alice", subject, "an ordinary page still sees the session")
}

package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The browser half of an OIDC login is bound to the browser that started it:
// /-/oauth/login mints a per-login state, PKCE verifier and nonce and keeps
// them in an encrypted cookie, and the callback refuses any code that does not
// arrive with that cookie. Without the binding, anyone holding a code from
// their own IdP login could sign a victim's browser in as themselves (login
// CSRF). See kdex-tech/host-manager#234.

func (f *oidcFixture) oauth2() *OAuth2 {
	return &OAuth2{AuthConfig: f.cfg, AuthExchanger: f.ex}
}

// startLogin drives GET /-/oauth/login and returns the IdP redirect plus the
// per-login cookie it set.
func startLogin(t *testing.T, o *OAuth2, query string) (*url.URL, *http.Cookie) {
	t.Helper()
	req := httptest.NewRequest("GET", OAuthLoginPath+"?"+query, nil)
	w := httptest.NewRecorder()

	o.OAuthLoginGet(w, req)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if strings.HasPrefix(c.Name, o.AuthConfig.CookieName+loginStateCookieInfix) {
			cookie = c
		}
	}
	require.NotNil(t, cookie, "the start endpoint must set the per-login cookie")
	return loc, cookie
}

func TestOAuthLoginGet_BindsTheLoginToThisBrowser(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()

	idp, cookie := startLogin(t, o, "return=%2Fdocs")
	q := idp.Query()

	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)

	assert.NotEmpty(t, q.Get("state"))
	assert.Equal(t, q.Get("state"), st.State, "the cookie carries the state sent to the IdP")
	assert.Equal(t, o.AuthConfig.CookieName+loginStateCookieInfix+st.State, cookie.Name,
		"the cookie is keyed by state so concurrent logins do not overwrite each other")
	assert.Equal(t, "/docs", st.Return, "the return path rides in the cookie, not in state")
	assert.NotContains(t, q.Get("state"), "docs")

	sum := sha256.Sum256([]byte(st.Verifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, st.Nonce)
	assert.Equal(t, st.Nonce, q.Get("nonce"))

	assert.Equal(t, OAuthCallbackPath, cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.Positive(t, cookie.MaxAge)
}

func TestOAuthLoginGet_SanitizesTheReturnPath(t *testing.T) {
	f := newOIDCFixture(t)

	_, cookie := startLogin(t, f.oauth2(), "return="+url.QueryEscape("//evil.example"))

	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)
	assert.Equal(t, "/", st.Return)
}

func TestOAuthLoginGet_PassesPromptAndLoginHintToTheIdP(t *testing.T) {
	f := newOIDCFixture(t)

	idp, _ := startLogin(t, f.oauth2(), "prompt=select_account&login_hint=alice%40example.com")

	assert.Equal(t, "select_account", idp.Query().Get("prompt"))
	assert.Equal(t, "alice@example.com", idp.Query().Get("login_hint"))
}

// offline_access already sends prompt=consent (#190). A per-login prompt is
// added to it, not written over it, or the refresh token silently disappears.
func TestOAuthLoginGet_JoinsPromptWithConfiguredConsent(t *testing.T) {
	f := newOIDCFixture(t, "offline_access")

	idp, _ := startLogin(t, f.oauth2(), "prompt=select_account")

	assert.Equal(t, "consent select_account", idp.Query().Get("prompt"))
	assert.Equal(t, "offline", idp.Query().Get("access_type"))
}

// Only prompt values the OIDC spec defines are forwarded; anything else would
// let a crafted link inject arbitrary text into the IdP request.
func TestOAuthLoginGet_DropsUnknownPromptValues(t *testing.T) {
	f := newOIDCFixture(t)

	idp, _ := startLogin(t, f.oauth2(), "prompt="+url.QueryEscape("select_account bogus"))

	assert.Equal(t, "select_account", idp.Query().Get("prompt"))
}

func callback(o *OAuth2, query string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", OAuthCallbackPath+"?"+query, nil)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	w := httptest.NewRecorder()
	o.OAuthGet(w, req)
	return w
}

func sessionCookie(o *OAuth2, w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == o.AuthConfig.CookieName {
			return c
		}
	}
	return nil
}

func loginCode(sub, nonce, verifier string) string {
	return "login:" + sub + "|" + nonce + "|" + verifier
}

func TestOAuthGet_CompletesABoundLogin(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()
	idp, cookie := startLogin(t, o, "return=%2Fdocs")
	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)

	w := callback(o, url.Values{
		"code":  {loginCode("alice", st.Nonce, st.Verifier)},
		"state": {idp.Query().Get("state")},
	}.Encode(), cookie)

	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.Equal(t, "/docs", w.Header().Get("Location"))
	assert.NotNil(t, sessionCookie(o, w), "a bound login signs the browser in")

	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == cookie.Name && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "the per-login cookie is single-use")
}

// The login CSRF itself: a code delivered to a browser that never started a
// login is refused before it is exchanged.
func TestOAuthGet_RefusesACodeWithoutTheLoginCookie(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()

	w := callback(o, url.Values{"code": {"alice"}, "state": {"/docs"}}.Encode())

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, sessionCookie(o, w))
}

func TestOAuthGet_RefusesAStateThatDoesNotMatchTheCookie(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()
	_, cookie := startLogin(t, o, "return=%2Fdocs")
	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)

	// The cookie's NAME is keyed by state, so present this browser's cookie
	// under the name the attacker's state would select.
	forged := &http.Cookie{Name: o.AuthConfig.CookieName + loginStateCookieInfix + "attackerstate", Value: cookie.Value}
	w := callback(o, url.Values{
		"code":  {loginCode("mallory", st.Nonce, st.Verifier)},
		"state": {"attackerstate"},
	}.Encode(), forged)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, sessionCookie(o, w))
}

func TestOAuthGet_RefusesAnIDTokenWithTheWrongNonce(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()
	idp, cookie := startLogin(t, o, "return=%2Fdocs")
	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)

	w := callback(o, url.Values{
		"code":  {loginCode("alice", "some-other-login", st.Verifier)},
		"state": {idp.Query().Get("state")},
	}.Encode(), cookie)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, sessionCookie(o, w))
}

func TestOAuthGet_ExchangesWithThisLoginsVerifier(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()
	idp, cookie := startLogin(t, o, "return=%2Fdocs")
	st, err := f.ex.openLoginState(cookie.Value)
	require.NoError(t, err)

	// A code issued to a different login (different verifier) does not
	// exchange, even with this browser's state and nonce.
	w := callback(o, url.Values{
		"code":  {loginCode("alice", st.Nonce, "not-this-logins-verifier")},
		"state": {idp.Query().Get("state")},
	}.Encode(), cookie)

	assert.NotEqual(t, http.StatusSeeOther, w.Code)
	assert.Nil(t, sessionCookie(o, w))
}

func TestOAuthGet_TwoConcurrentLoginsBothComplete(t *testing.T) {
	f := newOIDCFixture(t)
	o := f.oauth2()
	idpA, cookieA := startLogin(t, o, "return=%2Fa")
	idpB, cookieB := startLogin(t, o, "return=%2Fb")
	stA, err := f.ex.openLoginState(cookieA.Value)
	require.NoError(t, err)
	stB, err := f.ex.openLoginState(cookieB.Value)
	require.NoError(t, err)

	wB := callback(o, url.Values{
		"code":  {loginCode("alice", stB.Nonce, stB.Verifier)},
		"state": {idpB.Query().Get("state")},
	}.Encode(), cookieA, cookieB)
	wA := callback(o, url.Values{
		"code":  {loginCode("alice", stA.Nonce, stA.Verifier)},
		"state": {idpA.Query().Get("state")},
	}.Encode(), cookieA, cookieB)

	assert.Equal(t, "/b", wB.Header().Get("Location"))
	assert.Equal(t, "/a", wA.Header().Get("Location"))
}

func TestOIDCLoginURL(t *testing.T) {
	assert.Equal(t, "/-/oauth/login?return=%2Fdocs", OIDCLoginURL("/docs", "", ""))
	assert.Equal(t, "/-/oauth/login?login_hint=a%40b.c&prompt=select_account&return=%2F",
		OIDCLoginURL("/", "select_account", "a@b.c"))
}

// --- /-/oauth/authorize: prompt and login_hint (kdex-tech/host-manager#233) ---

func authorizeOAuth2(t *testing.T) *OAuth2 {
	t.Helper()
	o := subjectlessOAuth2(t)
	c := o.AuthConfig.Clients["client-1"]
	c.Public = true
	o.AuthConfig.Clients["client-1"] = c
	return o
}

func authorize(o *OAuth2, extra url.Values, session jwt.MapClaims) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id":     {"client-1"},
		"response_type": {"code"},
		"redirect_uri":  {"http://localhost/cb"},
		"state":         {"xyz"},
	}
	for k, v := range extra {
		q[k] = v
	}
	req := httptest.NewRequest("GET", "/-/oauth/authorize?"+q.Encode(), nil)
	if session != nil {
		req = req.WithContext(SetAuthContext(req.Context(), AuthContext(session)))
	}
	w := httptest.NewRecorder()
	o.AuthorizeHandler(w, req)
	return w
}

// loginRedirect asserts a redirect to /-/login and returns its query, with the
// return URL parsed so a test can check what will come back to authorize.
func loginRedirect(t *testing.T, w *httptest.ResponseRecorder) (url.Values, url.Values) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/-/login", loc.Path)
	ret, err := url.Parse(loc.Query().Get("return"))
	require.NoError(t, err)
	require.Equal(t, "/-/oauth/authorize", ret.Path)
	return loc.Query(), ret.Query()
}

var alice = jwt.MapClaims{"sub": "alice", "email": "alice@example.com"}

func TestAuthorize_PromptLoginReauthenticatesDespiteASession(t *testing.T) {
	for _, prompt := range []string{"login", "select_account"} {
		t.Run(prompt, func(t *testing.T) {
			o := authorizeOAuth2(t)

			login, ret := loginRedirect(t, authorize(o, url.Values{"prompt": {prompt}}, alice))

			assert.Equal(t, prompt, login.Get("prompt"), "the prompt goes on to the login")
			assert.Empty(t, ret.Get("prompt"), "and is removed from the return URL, or authorize loops")
			assert.Equal(t, "xyz", ret.Get("state"), "the rest of the request survives the round trip")
		})
	}
}

func TestAuthorize_LoginHintForAnotherAccountReauthenticates(t *testing.T) {
	o := authorizeOAuth2(t)

	login, ret := loginRedirect(t, authorize(o, url.Values{"login_hint": {"bob@example.com"}}, alice))

	assert.Equal(t, "bob@example.com", login.Get("login_hint"))
	assert.Empty(t, ret.Get("login_hint"), "removed from the return URL, or a wrong pick at the IdP loops")
}

func TestAuthorize_LoginHintForThisAccountIssuesACode(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"login_hint": {"Alice@Example.com"}}, alice)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

func TestAuthorize_PromptNoneWithoutASessionReturnsLoginRequired(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"prompt": {"none"}}, nil)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "localhost", loc.Hostname())
	assert.Equal(t, "/cb", loc.Path)
	assert.Equal(t, "login_required", loc.Query().Get("error"))
	assert.Equal(t, "xyz", loc.Query().Get("state"))
	assert.Empty(t, loc.Query().Get("code"))
}

func TestAuthorize_PromptNoneWithASessionIssuesACode(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"prompt": {"none"}}, alice)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

// prompt=none cannot be combined with another value (OIDC Core 3.1.2.1).
func TestAuthorize_PromptNoneWithAnotherValueIsInvalid(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"prompt": {"none login"}}, alice)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", loc.Query().Get("error"))
}

// prompt=none must never show UI (OIDC Core 3.1.2.1), so a session for
// another account than the hint is an error to the client, not a login page.
func TestAuthorize_PromptNoneWithAMismatchedHintReturnsLoginRequired(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"prompt": {"none"}, "login_hint": {"bob@example.com"}}, alice)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "/cb", loc.Path)
	assert.Equal(t, "login_required", loc.Query().Get("error"))
}

// A login_hint may name the subject rather than an email (a local account has
// no email claim).
func TestAuthorize_LoginHintMatchingTheSubjectIssuesACode(t *testing.T) {
	o := authorizeOAuth2(t)

	w := authorize(o, url.Values{"login_hint": {"carol"}}, jwt.MapClaims{"sub": "carol"})

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

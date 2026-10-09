package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	consentIssuer = "https://host.example"
	appRedirect   = "https://app.example/cb"
	otherRedirect = "https://other.example/cb"
)

type consentFixture struct {
	o        *OAuth2
	ex       *Exchanger
	clientID string
	verifier string
}

func newConsentFixture(t *testing.T) *consentFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, consentIssuer, &cs, "kid", nil)
	require.NoError(t, err)

	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "consent-flow-test", &ttl)
	require.NoError(t, err)
	store := dcr.NewStore(cm, consentIssuer, ttl, 100)
	consent := dcr.NewConsentStore(cm, ttl, 1000)

	cfg := Config{
		Issuer:     consentIssuer,
		Audience:   "test-aud",
		CookieName: "kdex-auth",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "kid", Private: cs},
		Clients:    map[string]AuthClient{},
		DCR:        DCRConfig{Enabled: true, ClientTTL: ttl, AllowedRedirectSchemes: []string{"https"}},
		DCRStore:   store,
		DCRConsent: consent,
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"
	ex, err := NewExchanger(context.Background(), cfg, cm, resourceStubIdentityProvider{}, nil)
	require.NoError(t, err)

	c, err := store.Register(context.Background(), dcr.Client{
		RedirectURIs: []string{appRedirect, otherRedirect},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ClientName:   "Example App",
	})
	require.NoError(t, err)

	o := &OAuth2{
		AuthConfig:    &ex.config,
		AuthExchanger: ex,
		ConsentOriginAllowed: func(r *http.Request) bool {
			return r.Header.Get("Origin") == consentIssuer
		},
	}
	return &consentFixture{o: o, ex: ex, clientID: c.ClientID, verifier: "v-0123456789-0123456789-0123456789-0123"}
}

func (f *consentFixture) query(redirect string, extra url.Values) url.Values {
	sum := sha256.Sum256([]byte(f.verifier))
	q := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"state":                 {"st"},
		"scope":                 {"openid email"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

var aliceSession = jwt.MapClaims{"sub": "alice", "email": "alice@example.com"}

func sessionRequest(method, target string, body *strings.Reader, session jwt.MapClaims, source string) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if session != nil {
		r = r.WithContext(withAuthSource(SetAuthContext(r.Context(), AuthContext(session)), source))
	}
	return r
}

func (f *consentFixture) authorize(q url.Values, session jwt.MapClaims, source string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.o.AuthorizeHandler(w, sessionRequest("GET", OAuthAuthorizePath+"?"+q.Encode(), nil, session, source))
	return w
}

var sealedRe = regexp.MustCompile(`name="request" value="([^"]+)"`)

func sealedFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	m := sealedRe.FindStringSubmatch(w.Body.String())
	require.Len(t, m, 2, "the consent page carries a sealed request")
	return m[1]
}

func (f *consentFixture) post(sealed, decision string, headers map[string]string, session jwt.MapClaims, source string) *httptest.ResponseRecorder {
	form := url.Values{"request": {sealed}, "decision": {decision}}
	r := sessionRequest("POST", OAuthConsentPath, strings.NewReader(form.Encode()), session, source)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.o.ConsentPost(w, r)
	return w
}

var sameOrigin = map[string]string{"Origin": consentIssuer}

func codeFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "an error redirect is not a code: %s", loc)
	return code
}

// allow drives page -> POST allow -> follow the 303 back to authorize.
func (f *consentFixture) allow(t *testing.T, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	sealed := sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
	w := f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, OAuthAuthorizePath, loc.Path)
	return f.authorize(loc.Query(), aliceSession, COOKIE)
}

func TestAuthorize_DCRClientWithoutConsentGetsThePage(t *testing.T) {
	f := newConsentFixture(t)
	w := f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE)

	sealedFrom(t, w)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "same-origin", w.Header().Get("Referrer-Policy"))
	assert.Contains(t, w.Header().Values("Content-Security-Policy"), "frame-ancestors 'none'")
}

func TestConsentPost_AllowThenAuthorizeIssuesACode(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	// same redirect, same or fewer scopes: no page
	q := f.query(appRedirect, url.Values{"scope": {"email read-only"}})
	codeFrom(t, f.authorize(q, aliceSession, COOKIE))

	// a broader supported scope: the page again
	q = f.query(appRedirect, url.Values{"scope": {"openid email roles"}})
	sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
}

func TestConsentForOneRedirectDoesNotCoverAnother(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	w := f.authorize(f.query(otherRedirect, nil), aliceSession, COOKIE)
	sealedFrom(t, w) // page, not a code
}

func TestConsentPost_AllowWithPromptConsentCompletes(t *testing.T) {
	f := newConsentFixture(t)
	q := f.query(appRedirect, url.Values{"prompt": {"consent"}})
	sealed := sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
	w := f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Empty(t, loc.Query().Get("prompt"), "consent is removed from the redirect, so it cannot loop")
	codeFrom(t, f.authorize(loc.Query(), aliceSession, COOKIE))
}

// Authorize reads its query with r.URL.Query(), which drops a malformed pair
// (a ';' separator, a bad escape). The sealed copy must be read the same way,
// or the page is shown but its Allow can never succeed.
func TestConsentPost_AllowWithAMalformedQueryPairCompletes(t *testing.T) {
	for name, junk := range map[string]string{"semicolon": "&utm=a;b", "bad escape": "&utm=%zz"} {
		t.Run(name, func(t *testing.T) {
			f := newConsentFixture(t)
			w := httptest.NewRecorder()
			target := OAuthAuthorizePath + "?" + f.query(appRedirect, nil).Encode() + junk
			f.o.AuthorizeHandler(w, sessionRequest("GET", target, nil, aliceSession, COOKIE))
			sealed := sealedFrom(t, w)

			w = f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
			require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			codeFrom(t, f.authorize(loc.Query(), aliceSession, COOKIE))
		})
	}
}

func TestAuthorize_PromptConsentForcesThePageWhenConsented(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))
	sealedFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"consent"}}), aliceSession, COOKIE))
}

func TestAuthorize_PromptNoneWithoutConsentIsConsentRequired(t *testing.T) {
	f := newConsentFixture(t)
	for _, hint := range []string{"", "alice@example.com", "bob@example.com"} {
		q := f.query(appRedirect, url.Values{"prompt": {"none"}, "login_hint": {hint}})
		w := f.authorize(q, aliceSession, COOKIE)
		require.Equal(t, http.StatusFound, w.Code, hint)
		loc, _ := w.Result().Location()
		assert.Equal(t, "consent_required", loc.Query().Get("error"), "same answer whatever the hint: %q", hint)
	}
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))
	codeFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), aliceSession, COOKIE))
}

func TestAuthorize_BearerSessionIsTreatedAsSignedOutForDCRClients(t *testing.T) {
	f := newConsentFixture(t)
	w := f.authorize(f.query(appRedirect, nil), aliceSession, "header")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"))
}

func TestAuthorize_NilConsentStoreShowsThePage(t *testing.T) {
	f := newConsentFixture(t)
	f.ex.config.DCRConsent = nil
	sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
}

func TestConsentPost_DenyRemovesConsent(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"consent"}}), aliceSession, COOKIE))
	w := f.post(sealed, "deny", sameOrigin, aliceSession, COOKIE)
	require.Equal(t, http.StatusFound, w.Code)
	loc, _ := w.Result().Location()
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, "st", loc.Query().Get("state"))

	sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE)) // asks again
}

func TestConsentPost_Refusals(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	// An existing, narrower consent: a refused deny must not remove it, and a
	// refused allow must not widen it to the sealed request's scopes.
	require.NoError(t, f.ex.config.DCRConsent.Grant(ctx, "alice", f.clientID, appRedirect, []string{"email"}))
	bob := jwt.MapClaims{"sub": "bob"}
	oauth2Session := jwt.MapClaims{"sub": "alice", "email": "alice@example.com", "auth_method": string(AuthMethodOAuth2)}
	capability := jwt.MapClaims{"sub": "alice", "entitlements": []string{"functions:/api/v1/files:read"}, CapUsesClaim: true}

	expired, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(-time.Minute).Unix()})
	require.NoError(t, err)
	otherIss, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: "https://elsewhere",
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)
	unregistered, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query("https://nope.example/cb", nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)

	for name, post := range map[string]func(decision string) *httptest.ResponseRecorder{
		"foreign origin": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, map[string]string{"Origin": "https://evil.example"}, aliceSession, COOKIE)
		},
		"no session": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, sameOrigin, nil, "")
		},
		"bearer session": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, sameOrigin, aliceSession, "header")
		},
		"oauth2 client token in the cookie": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, sameOrigin, oauth2Session, COOKIE)
		},
		"capability token in the cookie": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, sameOrigin, capability, COOKIE)
		},
		"another subject": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed, d, sameOrigin, bob, COOKIE)
		},
		"tampered seal": func(d string) *httptest.ResponseRecorder {
			return f.post(sealed[:len(sealed)-4]+"AAAA", d, sameOrigin, aliceSession, COOKIE)
		},
		"expired seal": func(d string) *httptest.ResponseRecorder {
			return f.post(expired, d, sameOrigin, aliceSession, COOKIE)
		},
		"other issuer": func(d string) *httptest.ResponseRecorder {
			return f.post(otherIss, d, sameOrigin, aliceSession, COOKIE)
		},
		"unregistered uri": func(d string) *httptest.ResponseRecorder {
			return f.post(unregistered, d, sameOrigin, aliceSession, COOKIE)
		},
		"bad decision": func(string) *httptest.ResponseRecorder {
			return f.post(sealed, "maybe", sameOrigin, aliceSession, COOKIE)
		},
	} {
		for _, decision := range []string{"allow", "deny"} {
			w := post(decision)
			assert.Equal(t, http.StatusForbidden, w.Code, "%s (%s)", name, decision)
			assert.Empty(t, w.Header().Get("Location"), "%s (%s)", name, decision)
		}
	}
	// nothing was revoked, and nothing was recorded
	ok, err := f.ex.config.DCRConsent.Covers(ctx, "alice", f.clientID, appRedirect, []string{"email"})
	require.NoError(t, err)
	assert.True(t, ok, "no refusal revokes the existing consent")
	ok, err = f.ex.config.DCRConsent.Covers(ctx, "alice", f.clientID, appRedirect, []string{"email", "openid"})
	require.NoError(t, err)
	assert.False(t, ok, "no refusal records the sealed request's scopes")
}

func TestConsentPost_NilOriginCheckRefusesEverything(t *testing.T) {
	f := newConsentFixture(t)
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	f.o.ConsentOriginAllowed = nil
	w := f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
	assert.Equal(t, http.StatusForbidden, w.Code)
	ok, _ := f.ex.config.DCRConsent.Covers(context.Background(), "alice", f.clientID, appRedirect, nil)
	assert.False(t, ok)
}

func TestAuthorize_BearerSessionIsSignedOutEvenWithConsent(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	w := f.authorize(f.query(appRedirect, nil), aliceSession, "header")
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"))

	w = f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), aliceSession, "header")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, _ := w.Result().Location()
	assert.Equal(t, "login_required", loc.Query().Get("error"))
	assert.Empty(t, loc.Query().Get("code"))
}

func TestAuthorize_OAuth2ClientTokenInTheCookieIsSignedOut(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	session := jwt.MapClaims{"sub": "alice", "email": "alice@example.com", "auth_method": string(AuthMethodOAuth2)}
	w := f.authorize(f.query(appRedirect, nil), session, COOKIE)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"))
}

// A capability token (mint_token) carries no auth_method, so only its
// CapUsesClaim marker tells it from a browser session. Its holder is a script,
// not the person, whatever transport carried it.
func TestAuthorize_CapabilityTokenInTheCookieIsSignedOut(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	capability := jwt.MapClaims{"sub": "alice", "entitlements": []string{"functions:/api/v1/files:read"}, CapUsesClaim: true}
	w := f.authorize(f.query(appRedirect, nil), capability, COOKIE)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"))

	w = f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), capability, COOKIE)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, _ := w.Result().Location()
	assert.Equal(t, "login_required", loc.Query().Get("error"))
	assert.Empty(t, loc.Query().Get("code"))
}

func TestAuthorize_LocalAndOIDCBrowserSessionsKeepWorking(t *testing.T) {
	for name, session := range map[string]jwt.MapClaims{
		"local":                   {"sub": "alice", "email": "alice@example.com", "auth_method": string(AuthMethodLocal)},
		"oidc after refresh":      {"sub": "alice", "email": "alice@example.com", "auth_method": string(AuthMethodOIDC)},
		"oidc with no method yet": {"sub": "alice", "email": "alice@example.com", "idp": "oidc"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newConsentFixture(t)
			sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), session, COOKIE))
			w := f.post(sealed, "allow", sameOrigin, session, COOKIE)
			require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			codeFrom(t, f.authorize(loc.Query(), session, COOKIE))
		})
	}
}

// consentStoreDown is a cache whose reads fail: every consent store
// operation starts with one, so it stands for a store outage.
type consentStoreDown struct{ cache.Cache }

func (consentStoreDown) Get(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errors.New("cache unavailable")
}

func TestAuthorize_ConsentReadFailureShowsThePage(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	f.ex.config.DCRConsent = dcr.NewConsentStoreFromCache(consentStoreDown{}, time.Hour)
	sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE)) // the page, not a code
}

func TestConsentPost_StoreFailureIsUnavailable(t *testing.T) {
	for _, decision := range []string{"allow", "deny"} {
		t.Run(decision, func(t *testing.T) {
			f := newConsentFixture(t)
			sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))

			f.ex.config.DCRConsent = dcr.NewConsentStoreFromCache(consentStoreDown{}, time.Hour)
			w := f.post(sealed, decision, sameOrigin, aliceSession, COOKIE)
			assert.Equal(t, http.StatusServiceUnavailable, w.Code)
			assert.NotEmpty(t, w.Header().Get("Retry-After"))
			assert.Empty(t, w.Header().Get("Location"))
		})
	}
}

func TestConsentPost_DeletedClientIsRefused(t *testing.T) {
	f := newConsentFixture(t)
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	require.NoError(t, f.ex.config.DCRStore.Delete(context.Background(), f.clientID))
	assert.Equal(t, http.StatusForbidden, f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE).Code)
}

func TestAuthorize_StaticClientsNeverSeeThePage(t *testing.T) {
	o := authorizeOAuth2(t) // static public client "client-1" (oidc_login_test.go)
	w := authorize(o, url.Values{"prompt": {"consent"}}, alice)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, _ := w.Result().Location()
	assert.NotEmpty(t, loc.Query().Get("code"))
}

func (f *consentFixture) refreshToken(t *testing.T) string {
	t.Helper()
	id, err := f.ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		Subject:          "alice",
		ClientID:         f.clientID,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		OriginalIssuedAt: time.Now().Unix(),
	})
	require.NoError(t, err)
	return id
}

func TestRedeemRefreshToken_DCRClientWithoutConsentFails(t *testing.T) {
	f := newConsentFixture(t)
	id := f.refreshToken(t)
	_, err := f.ex.RedeemRefreshToken(context.Background(), id, f.clientID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGrantFailure), "invalid_grant, so the client re-authorizes")

	// A grant failure ends the session: the token is consumed, not restored.
	_, err = f.ex.RedeemRefreshToken(context.Background(), id, f.clientID)
	require.Error(t, err)
}

func TestRedeemRefreshToken_DCRClientWithConsentRotates(t *testing.T) {
	f := newConsentFixture(t)
	require.NoError(t, f.ex.config.DCRConsent.Grant(context.Background(), "alice", f.clientID, appRedirect, nil))
	ts, err := f.ex.RedeemRefreshToken(context.Background(), f.refreshToken(t), f.clientID)
	require.NoError(t, err)
	assert.NotEmpty(t, ts.RefreshToken)
}

func TestRedeemRefreshToken_BrowserSessionNeedsNoConsent(t *testing.T) {
	f := newConsentFixture(t)
	id, err := f.ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		Subject: "alice", ClientID: "", ExpiresAt: time.Now().Add(time.Hour).Unix(), OriginalIssuedAt: time.Now().Unix(),
	})
	require.NoError(t, err)
	_, err = f.ex.RedeemRefreshToken(context.Background(), id, "")
	assert.NoError(t, err)
}

func TestRedeemRefreshToken_ConsentStoreErrorIsAServerError(t *testing.T) {
	f := newConsentFixture(t)
	id := f.refreshToken(t)
	f.ex.config.DCRConsent = dcr.NewConsentStoreFromCache(consentStoreDown{}, time.Hour)
	_, err := f.ex.RedeemRefreshToken(context.Background(), id, f.clientID)
	assert.True(t, errors.Is(err, ErrServerError), "a store outage restores the refresh token instead of ending the session")
}

// A client registered anonymously with two redirects: one a user would trust,
// one they would not. No code may reach either redirect without the user's
// Allow, and an Allow for one releases nothing to the other.
func TestDCRClientGetsNoCodeWithoutConsentAtThatRedirect(t *testing.T) {
	f := newConsentFixture(t)

	for _, redirect := range []string{appRedirect, otherRedirect} {
		w := f.authorize(f.query(redirect, nil), aliceSession, COOKIE)
		assert.Empty(t, w.Header().Get("Location"), redirect)
		sealedFrom(t, w)
	}

	assert.NotEmpty(t, codeFrom(t, f.allow(t, f.query(appRedirect, nil))))

	// Consent at appRedirect must not leak to otherRedirect.
	w := f.authorize(f.query(otherRedirect, nil), aliceSession, COOKIE)
	assert.Empty(t, w.Header().Get("Location"), "no redirect without consent")
	sealedFrom(t, w)

	w = f.authorize(f.query(otherRedirect, url.Values{"prompt": {"none"}}), aliceSession, COOKIE)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.Empty(t, loc.Query().Get("code"), "prompt=none must not release a code")
	assert.Equal(t, "consent_required", loc.Query().Get("error"))
}

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	return loc.Query().Get("code")
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
	assert.NotEmpty(t, codeFrom(t, f.allow(t, f.query(appRedirect, nil))))

	// same redirect, same or fewer scopes: no page
	q := f.query(appRedirect, url.Values{"scope": {"email read-only"}})
	assert.NotEmpty(t, codeFrom(t, f.authorize(q, aliceSession, COOKIE)))

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
	assert.NotEmpty(t, codeFrom(t, f.authorize(loc.Query(), aliceSession, COOKIE)))
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
	assert.NotEmpty(t, codeFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), aliceSession, COOKIE)))
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
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	bob := jwt.MapClaims{"sub": "bob"}

	expired, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(-time.Minute).Unix()})
	require.NoError(t, err)
	otherIss, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: "https://elsewhere",
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)
	unregistered, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query("https://nope.example/cb", nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)

	for name, w := range map[string]*httptest.ResponseRecorder{
		"foreign origin":   f.post(sealed, "allow", map[string]string{"Origin": "https://evil.example"}, aliceSession, COOKIE),
		"no session":       f.post(sealed, "allow", sameOrigin, nil, ""),
		"bearer session":   f.post(sealed, "allow", sameOrigin, aliceSession, "header"),
		"another subject":  f.post(sealed, "allow", sameOrigin, bob, COOKIE),
		"tampered seal":    f.post(sealed[:len(sealed)-4]+"AAAA", "allow", sameOrigin, aliceSession, COOKIE),
		"expired seal":     f.post(expired, "allow", sameOrigin, aliceSession, COOKIE),
		"other issuer":     f.post(otherIss, "allow", sameOrigin, aliceSession, COOKIE),
		"unregistered uri": f.post(unregistered, "allow", sameOrigin, aliceSession, COOKIE),
		"bad decision":     f.post(sealed, "maybe", sameOrigin, aliceSession, COOKIE),
	} {
		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Empty(t, w.Header().Get("Location"), name)
	}
	// nothing was recorded by any of them
	ok, _ := f.ex.config.DCRConsent.Covers(context.Background(), "alice", f.clientID, appRedirect, nil)
	assert.False(t, ok)
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

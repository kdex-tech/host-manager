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

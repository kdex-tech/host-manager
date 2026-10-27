package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const (
	consentFlowDomain   = "consent.example"
	consentFlowIssuer   = "https://" + consentFlowDomain
	consentFlowRedirect = "https://app.example/cb"
)

// consentFlowHost is a host serving the consent flow through hh.ServeHTTP: the
// host-wide authentication wrap, the route's own, the scheme and domains
// snapshotted by newOAuth2, and the real consentOriginAllowed.
type consentFlowHost struct {
	hh       *HostHandler
	clientID string
	session  *http.Cookie
}

func newConsentFlowHost(t *testing.T) *consentFlowHost {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var cs crypto.Signer = priv

	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "consent-flow-host-test", &ttl)
	require.NoError(t, err)
	dcrStore := dcr.NewStore(cm, consentFlowIssuer, ttl, 100)

	signer, err := sign.NewSigner(consentFlowIssuer, ttl, consentFlowIssuer, &cs, "kid", nil)
	require.NoError(t, err)
	authConfig := &auth.Config{
		Issuer:     consentFlowIssuer,
		Audience:   consentFlowIssuer,
		CookieName: "kdex-auth",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "kid", Private: cs},
		Clients:    map[string]auth.AuthClient{},
		TokenTTL:   ttl,
		DCR:        auth.DCRConfig{Enabled: true, ClientTTL: ttl, MaxClients: 100, AllowedRedirectSchemes: []string{"https"}},
		DCRStore:   dcrStore,
		DCRConsent: dcr.NewConsentStore(cm, ttl, 1000),
	}
	authConfig.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"
	// The controller hands the exchanger a copy of the config, as here.
	ex, err := auth.NewExchanger(t.Context(), *authConfig, cm, stubInternalIdentityProvider{}, nil)
	require.NoError(t, err)

	client, err := dcrStore.Register(t.Context(), dcr.Client{
		RedirectURIs: []string{consentFlowRedirect},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ClientName:   "Example App",
	})
	require.NoError(t, err)

	hh := &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		cacheManager:  cm,
		host:          &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{consentFlowDomain}}},
		authConfig:    authConfig,
		authExchanger: ex,
	}
	mux := http.NewServeMux()
	hh.authorizeHandler(mux, map[string]ko.PathInfo{})
	hh.Mux = mux

	// A browser session as login issues it: a host-audience JWT in the cookie.
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice", "email": "alice@example.com", "auth_method": string(auth.AuthMethodLocal),
		"iss": consentFlowIssuer, "aud": []string{consentFlowIssuer},
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kid"
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)

	return &consentFlowHost{
		hh:       hh,
		clientID: client.ClientID,
		session:  &http.Cookie{Name: authConfig.CookieName, Value: signed},
	}
}

func (h *consentFlowHost) get(target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host = consentFlowDomain
	r.AddCookie(h.session)
	w := httptest.NewRecorder()
	h.hh.ServeHTTP(w, r)
	return w
}

func (h *consentFlowHost) post(sealed string, headers map[string]string) *httptest.ResponseRecorder {
	form := url.Values{"request": {sealed}, "decision": {"allow"}}
	r := httptest.NewRequest(http.MethodPost, auth.OAuthConsentPath, strings.NewReader(form.Encode()))
	r.Host = consentFlowDomain
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.AddCookie(h.session)
	w := httptest.NewRecorder()
	h.hh.ServeHTTP(w, r)
	return w
}

var consentFlowSealed = regexp.MustCompile(`name="request" value="([^"]+)"`)

func TestHostConsentFlow_PageAllowThenCode(t *testing.T) {
	consentFlowAllowThenCode(t, withUserNavigation(map[string]string{
		"Origin": consentFlowIssuer, "Sec-Fetch-Site": "same-origin"}))
}

// Safari sends no Sec-Fetch-User (bugs.webkit.org 247697), so its Allow must
// pass the wired gate on the WebKit waiver alone (kdex-tech/host-manager#264).
func TestHostConsentFlow_SafariAllowThenCode(t *testing.T) {
	consentFlowAllowThenCode(t, webKitNavigation(map[string]string{
		"Origin": consentFlowIssuer, "User-Agent": uaSafariMac}))
}

// consentFlowAllowThenCode drives page -> refused POSTs -> Allow (submitted
// with userSubmit) -> code through the real host handler.
func consentFlowAllowThenCode(t *testing.T, userSubmit map[string]string) {
	t.Helper()
	h := newConsentFlowHost(t)
	_, challenge := pkcePair(t)
	authorize := auth.OAuthAuthorizePath + "?" + url.Values{
		"client_id":             {h.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {consentFlowRedirect},
		"state":                 {"st"},
		"scope":                 {"openid email"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	page := h.get(authorize)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	assert.Empty(t, page.Header().Get("Location"), "the page, not a code")
	m := consentFlowSealed.FindStringSubmatch(page.Body.String())
	require.Len(t, m, 2, "the consent page carries a sealed request")
	sealed := m[1]

	for name, headers := range map[string]map[string]string{
		"cross-origin":        {"Origin": "https://evil.example"},
		"same-origin fetch()": {"Origin": consentFlowIssuer, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"},
		"Chrome scripted submit, no Sec-Fetch-User": webKitNavigation(map[string]string{
			"Origin": consentFlowIssuer, "User-Agent": uaChromeMac}),
	} {
		w := h.post(sealed, headers)
		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Empty(t, w.Header().Get("Location"), name)
	}
	again := h.get(authorize)
	require.Equal(t, http.StatusOK, again.Code, "a refused POST records nothing: still the page")

	allow := h.post(sealed, userSubmit)
	require.Equal(t, http.StatusSeeOther, allow.Code, allow.Body.String())
	next, err := url.Parse(allow.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, auth.OAuthAuthorizePath, next.Path)

	code := h.get(next.String())
	require.Equal(t, http.StatusFound, code.Code, code.Body.String())
	loc, err := code.Result().Location()
	require.NoError(t, err)
	assert.Equal(t, "app.example", loc.Host)
	assert.NotEmpty(t, loc.Query().Get("code"))
	assert.Equal(t, "st", loc.Query().Get("state"))
}

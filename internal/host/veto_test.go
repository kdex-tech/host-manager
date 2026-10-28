package host

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// The veto (#255): current config is a veto on a credential's kind, never its
// source. A Client credential whose client is no longer configured is
// refused, and so is a User credential whose sub names a client. Each test
// configures vetoClient, issues its credential, removes the client, rebuilds
// the Exchanger on the same cache manager (so the client registry still
// names it, as across a reconcile), and presents the credential.

const (
	vetoClient     = "veto-client"
	vetoSecret     = "s3cret"
	vetoApp        = "veto-app"
	vetoUser       = "bob"
	vetoDomain     = "veto.example"
	vetoIssuer     = "https://" + vetoDomain
	vetoRedirect   = "https://app.example/cb"
	vetoClientRole = "veto-client-role"
	vetoFnPath     = "/v1/api"
	vetoExchangeTo = "https://fn-b.example"
)

// vetoHost serves the credential-accepting surfaces through their real
// wiring: /-/check (the JWT gate, the session-grant refresh and the host PAT
// middleware), /-/apitokens/mint and /-/apitokens/verify,
// /-/oauth/authorize and an apiKey function
// behind the proxy PAT bridge. Roles come from the real role provider, with
// an exact binding for vetoClient and a `*` binding narrowed to [User].
type vetoHost struct {
	t   *testing.T
	cm  cache.CacheManager
	tm  *apitoken.TokenManager
	cfg *auth.Config
	idp auth.InternalIdentityProvider
	rec *acRecordingChecker
	fn  *kdexv1alpha1.KDexFunction
	fat *string // the Authorization header the function last received
	hh  *HostHandler
	mux *http.ServeMux
}

func newVetoHost(t *testing.T) *vetoHost {
	t.Helper()
	logf.SetLogger(logr.Discard())

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var cs crypto.Signer = priv
	ttl := time.Hour

	cm, err := cache.NewCacheManager("", "veto-host-test", nil)
	require.NoError(t, err)
	tm, err := apitoken.NewTokenManager(vetoIssuer, apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}))
	require.NoError(t, err)
	signer, err := sign.NewSigner(vetoIssuer, ttl, vetoIssuer, &cs, "kid", nil)
	require.NoError(t, err)

	cfg := &auth.Config{
		Issuer:       vetoIssuer,
		Audience:     vetoIssuer,
		CookieName:   "kdex-auth",
		Signer:       *signer,
		ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "kid", Private: cs},
		TokenTTL:     ttl,
		TokenManager: tm,
		Clients: map[string]auth.AuthClient{
			vetoClient: {
				ClientID:          vetoClient,
				ClientSecret:      vetoSecret,
				AllowedGrantTypes: []string{auth.GRANT_TYPE_CLIENT_CREDENTIALS},
			},
			vetoApp: {ClientID: vetoApp, RedirectURIs: []string{vetoRedirect}},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	fat := new(string)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*fat = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	fn := apiKeySecuredFunction(vetoFnPath, true)
	fn.Status.URL = upstream.URL

	h := &vetoHost{
		t: t, cm: cm, tm: tm, cfg: cfg, fn: fn, fat: fat,
		idp: roleProviderFor(t,
			roleGrant{name: "veto-client-exact", subject: vetoClient, role: vetoClientRole},
			roleGrant{name: "people", subject: "*", role: kindsUserRole,
				kinds: []kdexv1alpha1.SubjectKind{kdexv1alpha1.SubjectKindUser}},
		),
		rec: &acRecordingChecker{},
	}
	h.rebuild()
	return h
}

// rebuild builds a fresh Exchanger from the current config on the same cache
// manager, and serves every surface through it, as a reconcile does.
func (h *vetoHost) rebuild() {
	h.t.Helper()
	ex, err := auth.NewExchanger(h.t.Context(), *h.cfg, h.cm, h.idp, nil)
	require.NoError(h.t, err)
	h.hh = &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		cacheManager:  h.cm,
		host:          &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{vetoDomain}}},
		authConfig:    h.cfg,
		authExchanger: ex,
		authChecker:   h.rec,
	}
	h.mux = http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	h.hh.checkHandler(h.mux, paths)
	h.hh.apitokensHandler(h.mux, paths)
	h.hh.authorizeHandler(h.mux, paths)
	h.mux.Handle(vetoFnPath, h.hh.reverseProxyHandler(h.fn, vetoIssuer))
}

// setClient configures (or, with configured false, removes) the client id,
// then rebuilds.
func (h *vetoHost) setClient(id string, configured bool) {
	h.t.Helper()
	clients := maps.Clone(h.cfg.Clients)
	if configured {
		clients[id] = auth.AuthClient{ClientID: id, ClientSecret: vetoSecret}
	} else {
		delete(clients, id)
	}
	h.cfg.Clients = clients
	h.rebuild()
}

// pat mints a host-audience PAT for sub recording kind.
func (h *vetoHost) pat(sub string, kind kdexv1alpha1.SubjectKind) string {
	h.t.Helper()
	pat, err := h.tm.MintStatelessKey(vetoIssuer, sub, kind, "act", "s", time.Hour)
	require.NoError(h.t, err)
	return pat
}

// clientJWT is a client_credentials access token for vetoClient.
func (h *vetoHost) clientJWT() string {
	h.t.Helper()
	ts, err := h.hh.authExchanger.LoginClient(h.t.Context(), vetoClient, vetoSecret, "")
	require.NoError(h.t, err)
	return ts.AccessToken
}

func (h *vetoHost) serve(req *http.Request) *httptest.ResponseRecorder {
	req.Host = vetoDomain
	rr := httptest.NewRecorder()
	h.mux.ServeHTTP(rr, req)
	return rr
}

// check presents a credential at /-/check and returns the response and the
// auth context the endpoint saw (nil when it saw none).
func (h *vetoHost) check(present func(*http.Request)) (*httptest.ResponseRecorder, auth.AuthContext) {
	h.rec.ac = nil
	req := httptest.NewRequest(http.MethodPost, "/-/check", strings.NewReader(`{"checks":[]}`))
	present(req)
	return h.serve(req), h.rec.ac
}

// proxy presents a PAT to the function and returns the auth context its gate
// saw and the FAT it forwarded ("" when it forwarded none).
func (h *vetoHost) proxy(pat string) (auth.AuthContext, string) {
	h.rec.ac = nil
	*h.fat = ""
	req := httptest.NewRequest(http.MethodGet, vetoFnPath, nil)
	req.Header.Set("X-API-TOKEN", pat)
	h.serve(req)
	return h.rec.ac, *h.fat
}

// fatFor is the FAT the proxy projects from pat.
func (h *vetoHost) fatFor(pat string) string {
	h.t.Helper()
	_, fat := h.proxy(pat)
	require.True(h.t, strings.HasPrefix(fat, "Bearer "), "the proxy projected no FAT")
	return strings.TrimPrefix(fat, "Bearer ")
}

// mint self-mints a PAT through /-/apitokens/mint with the bearer jwt.
func (h *vetoHost) mint(jwt string) *httptest.ResponseRecorder {
	return h.mintFor(jwt, vetoClient)
}

// mintFor mints a PAT for sub through /-/apitokens/mint with the bearer jwt:
// a self-mint when jwt is sub's own, else an impersonating one.
func (h *vetoHost) mintFor(jwt, sub string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(MintRequest{Audience: vetoIssuer, Sub: sub, Action: "key-1", TTL: "1h"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+jwt)
	return h.serve(req)
}

// authorize starts an authorization-code flow for vetoApp, presenting the
// credential as present does.
func (h *vetoHost) authorize(present func(*http.Request)) *httptest.ResponseRecorder {
	target := auth.OAuthAuthorizePath + "?" + url.Values{
		"client_id":     {vetoApp},
		"response_type": {"code"},
		"redirect_uri":  {vetoRedirect},
		"state":         {"st"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	present(req)
	return h.serve(req)
}

// verify asks /-/apitokens/verify about pat.
func (h *vetoHost) verify(pat string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(VerifyRequest{Token: pat})
	return h.serve(httptest.NewRequest(http.MethodPost, "/-/apitokens/verify", bytes.NewBuffer(body)))
}

// assertVerifiesAsRevoked: verify answers pat exactly as it answers a
// revoked PAT, so a consumer deciding liveness through it refuses pat too.
func (h *vetoHost) assertVerifiesAsRevoked(t *testing.T, pat string) {
	t.Helper()
	revoked := h.pat("someone-revoked", kdexv1alpha1.SubjectKindUser)
	require.NoError(t, h.tm.RevokeToken(t.Context(), revoked))
	want := h.verify(revoked)
	require.Equal(t, http.StatusUnauthorized, want.Code, "precondition: verify refuses a revoked PAT")

	got := h.verify(pat)
	assert.Equal(t, want.Code, got.Code)
	assert.Equal(t, want.Body.String(), got.Body.String())
}

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func (h *vetoHost) cookie(token string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: h.cfg.CookieName, Value: token}) }
}

// issuedCode is the authorization code a response redirected with, if any.
func issuedCode(rr *httptest.ResponseRecorder) string {
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		return ""
	}
	return loc.Query().Get("code")
}

// clearsSession reports whether the response cleared the session cookie.
func clearsSession(rr *httptest.ResponseRecorder, name string) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// assertPATRefused presents pat at the host PAT middleware and at the proxy
// PAT bridge. Each refuses it as it refuses an invalid PAT: the request stays
// anonymous, so no role reaches either gate and the proxy projects no FAT.
func (h *vetoHost) assertPATRefused(t *testing.T, pat string) {
	t.Helper()
	_, ac := h.check(bearer(pat))
	assert.Nil(t, ac, "the host PAT middleware accepted the credential")
	ac, fat := h.proxy(pat)
	assert.Nil(t, ac, "the proxy PAT bridge accepted the credential")
	assert.Empty(t, fat, "the proxy projected a FAT")
}

// assertPATAccepted presents pat at both PAT sites, each of which must
// resolve exactly role for it.
func (h *vetoHost) assertPATAccepted(t *testing.T, pat, role string) {
	t.Helper()
	_, ac := h.check(bearer(pat))
	require.NotNil(t, ac, "the host PAT middleware refused the credential")
	assert.Equal(t, []string{role}, stringSliceFromClaim(ac["roles"]), "host PAT middleware")
	ac, fat := h.proxy(pat)
	require.NotNil(t, ac, "the proxy PAT bridge refused the credential")
	assert.Equal(t, []string{role}, stringSliceFromClaim(ac["roles"]), "proxy PAT bridge")
	assert.NotEmpty(t, fat, "the proxy projected no FAT")
}

func TestVeto_RemovedClientPATRefused(t *testing.T) {
	h := newVetoHost(t)
	pat := h.pat(vetoClient, kdexv1alpha1.SubjectKindClient)
	h.setClient(vetoClient, false)

	h.assertPATRefused(t, pat)
}

func TestVeto_RemovedClientKindlessPATRefused(t *testing.T) { // LEGACY(#268)
	h := newVetoHost(t)
	pat := kindlessPAT(vetoIssuer, vetoIssuer, vetoClient)
	h.setClient(vetoClient, false)
	require.Equal(t, kdexv1alpha1.SubjectKindClient, h.hh.authExchanger.SubjectKindOf(vetoClient),
		"precondition: the registry still classifies the removed client as a Client")

	h.assertPATRefused(t, pat)
}

func TestVeto_RemovedClientJWTRefused(t *testing.T) {
	h := newVetoHost(t)
	jwt := h.clientJWT()
	h.setClient(vetoClient, false)

	rr, ac := h.check(bearer(jwt))
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "the answer an invalid bearer gets")
	assert.Contains(t, rr.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	assert.Nil(t, ac, "the gate accepted the credential")
}

func TestVeto_RemovedClientFATExchangeRefused(t *testing.T) {
	h := newVetoHost(t)
	fat := h.fatFor(h.pat(vetoClient, kdexv1alpha1.SubjectKindClient))
	h.setClient(vetoClient, false)

	_, err := h.hh.authExchanger.ExchangeSubjectToken(fat, vetoExchangeTo)
	require.ErrorIs(t, err, auth.ErrCredentialKindRefused)
	assert.NotErrorIs(t, err, auth.ErrServerError,
		"the token endpoint answers it as it answers an invalid subject_token")
}

func TestVeto_RemovedClientSelfMintRefused(t *testing.T) {
	h := newVetoHost(t)
	jwt := h.clientJWT()
	h.setClient(vetoClient, false)

	rr := h.mint(jwt)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var resp MintResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	assert.Empty(t, resp.Token, "a PAT was minted")
}

// TestVeto_ImpersonatingMintForDeadClientRefused: an impersonating mint
// whose target classifies as a Client that is not configured -- a removed
// client the registry remembers, or a dcr_ id -- would hand back a PAT every
// site vetoes. The mint refuses it with a 400 that does not name the target,
// and mints nothing. The controls mint for a configured client and a user.
func TestVeto_ImpersonatingMintForDeadClientRefused(t *testing.T) {
	const removed = "removed-client"
	h := newVetoHost(t)
	h.setClient(removed, true)
	h.setClient(removed, false)
	jwt := h.clientJWT()

	for name, sub := range map[string]string{
		"a removed client":            removed,
		"a dynamically registered id": dcr.ClientIDPrefix + "0123abcd",
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, kdexv1alpha1.SubjectKindClient, h.hh.authExchanger.SubjectKindOf(sub),
				"precondition: the target classifies as a Client")
			rr := h.mintFor(jwt, sub)
			assert.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			assert.NotContains(t, rr.Body.String(), sub, "the refusal names the target")
			var resp MintResponse
			_ = json.Unmarshal(rr.Body.Bytes(), &resp)
			assert.Empty(t, resp.Token, "a PAT was minted")
		})
	}
	for name, sub := range map[string]string{
		"control: a configured client": vetoApp,
		"control: a user":              vetoUser,
	} {
		t.Run(name, func(t *testing.T) {
			rr := h.mintFor(jwt, sub)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var resp MintResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			assert.NotEmpty(t, resp.Token)
		})
	}
}

func TestVeto_RemovedClientAuthorizeRefused(t *testing.T) {
	h := newVetoHost(t)
	jwt := h.clientJWT()
	h.setClient(vetoClient, false)

	t.Run("as a bearer token", func(t *testing.T) {
		rr := h.authorize(bearer(jwt))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Empty(t, issuedCode(rr), "an authorization code was issued")
	})
	t.Run("as the session cookie", func(t *testing.T) {
		rr := h.authorize(h.cookie(jwt))
		assert.Equal(t, http.StatusSeeOther, rr.Code, "signed out: sent to log in")
		assert.Empty(t, issuedCode(rr), "an authorization code was issued")
		assert.True(t, clearsSession(rr, h.cfg.CookieName), "the session cookie was kept")
	})
}

func TestVeto_RemovedClientSessionGrantRefused(t *testing.T) {
	h := newVetoHost(t)
	jwt := h.clientJWT()
	h.setClient(vetoClient, false)

	rr, ac := h.check(h.cookie(jwt))
	assert.Nil(t, ac, "the session was accepted, with whatever grants it refreshed to")
	assert.True(t, clearsSession(rr, h.cfg.CookieName), "the session cookie was kept")
}

func TestVeto_UserPATNamingClientRefused(t *testing.T) {
	h := newVetoHost(t)
	pat := h.pat(vetoUser, kdexv1alpha1.SubjectKindUser)
	h.setClient(vetoUser, true)

	h.assertPATRefused(t, pat)
	t.Run("at /-/apitokens/verify", func(t *testing.T) {
		h.assertVerifiesAsRevoked(t, pat)
	})
}

// TestVeto_RemovedClientVerifyRefused: verify is how a consumer decides a
// PAT is live, so a removed client's PAT verifies as a revoked one does
// (Ruling 14).
func TestVeto_RemovedClientVerifyRefused(t *testing.T) {
	h := newVetoHost(t)
	clientPAT := h.pat(vetoClient, kdexv1alpha1.SubjectKindClient)
	kindless := kindlessPAT(vetoIssuer, vetoIssuer, vetoClient)
	h.setClient(vetoClient, false)

	t.Run("a Client PAT", func(t *testing.T) {
		h.assertVerifiesAsRevoked(t, clientPAT)
	})
	t.Run("a kind-less PAT", func(t *testing.T) { // LEGACY(#268)
		h.assertVerifiesAsRevoked(t, kindless)
	})
}

// TestVeto_ConfiguredClientAccepted is the control: every credential the
// TestVeto_ tests present is accepted while its client is still configured,
// across the same rebuild on the same cache manager.
func TestVeto_ConfiguredClientAccepted(t *testing.T) {
	h := newVetoHost(t)
	clientPAT := h.pat(vetoClient, kdexv1alpha1.SubjectKindClient)
	kindless := kindlessPAT(vetoIssuer, vetoIssuer, vetoClient)
	userPAT := h.pat(vetoUser, kdexv1alpha1.SubjectKindUser)
	jwt := h.clientJWT()
	fat := h.fatFor(clientPAT)
	h.rebuild()

	t.Run("a Client PAT", func(t *testing.T) {
		h.assertPATAccepted(t, clientPAT, vetoClientRole)
	})
	t.Run("a kind-less PAT", func(t *testing.T) { // LEGACY(#268)
		h.assertPATAccepted(t, kindless, vetoClientRole)
	})
	t.Run("a User PAT for a user", func(t *testing.T) {
		h.assertPATAccepted(t, userPAT, kindsUserRole)
	})
	for name, tc := range map[string]struct {
		pat  string
		sub  string
		kind kdexv1alpha1.SubjectKind
	}{
		"verify: a Client PAT":    {clientPAT, vetoClient, kdexv1alpha1.SubjectKindClient},
		"verify: a kind-less PAT": {kindless, vetoClient, ""}, // LEGACY(#268)
		"verify: a User PAT":      {userPAT, vetoUser, kdexv1alpha1.SubjectKindUser},
	} {
		t.Run(name, func(t *testing.T) {
			rr := h.verify(tc.pat)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
			var data apitoken.TokenData
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &data))
			assert.Equal(t, tc.sub, data.Subject)
			assert.Equal(t, tc.kind, data.SubjectKind, "verify reports the kind the PAT records")
		})
	}
	t.Run("a client_credentials JWT", func(t *testing.T) {
		rr, ac := h.check(bearer(jwt))
		assert.Equal(t, http.StatusOK, rr.Code)
		require.NotNil(t, ac)
		assert.Equal(t, vetoClient, ac["sub"])
	})
	t.Run("a FAT exchange", func(t *testing.T) {
		ts, err := h.hh.authExchanger.ExchangeSubjectToken(fat, vetoExchangeTo)
		require.NoError(t, err)
		assert.NotEmpty(t, ts.AccessToken)
	})
	t.Run("a self-mint", func(t *testing.T) {
		rr := h.mint(jwt)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		var resp MintResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.Token)
	})
	t.Run("/-/oauth/authorize", func(t *testing.T) {
		// The gate accepts the credential, so authorize issues a code. Its
		// redemption is refused by #243 (the code names a client); that is
		// not the veto's to pin.
		rr := h.authorize(bearer(jwt))
		assert.Equal(t, http.StatusFound, rr.Code, rr.Body.String())
		assert.NotEmpty(t, issuedCode(rr))
	})
	t.Run("the session cookie", func(t *testing.T) {
		rr, ac := h.check(h.cookie(jwt))
		require.NotNil(t, ac)
		assert.Equal(t, vetoClient, ac["sub"])
		assert.False(t, clearsSession(rr, h.cfg.CookieName))
	})
}

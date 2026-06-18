/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
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

const (
	e2eDomain   = "dev.knowdrive.ai"
	e2eIssuer   = "https://" + e2eDomain
	e2eBasePath = "/api/v1/mcp"
	e2eResource = e2eIssuer + e2eBasePath
	e2eScope    = "functions:" + e2eBasePath + ":read"
	e2eSubject  = "mcp-alice"
	e2eRedirect = "http://127.0.0.1:33418/cb"
)

// e2eHarness wires up the full MCP/OAuth2 chain for an oauth2-protected
// /api/v1/mcp function on host dev.knowdrive.ai, backed by an httptest.Server.
//
// It returns:
//   - endpoints: a mux serving /-/oauth/register, /-/token and the RFC 9728
//     /.well-known/oauth-protected-resource endpoints (the authorization-server
//     surface a remote MCP client talks to over HTTP).
//   - gate: the reverse-proxy handler for the function (PAT-on-Bearer gate -> FAT).
//   - tm: the TokenManager that mints/validates resource-bound PATs; its issuer
//     matches the host issuer so a PAT with aud=resource validates.
//   - ex: the Exchanger (used to synthesize the authorization code, standing in
//     for the browser-login leg of /-/oauth/authorize).
//   - backendFAT: pointer to the Authorization header the upstream observed.
//   - backendURL: the upstream Service origin (the expected FAT audience).
type e2eHarness struct {
	endpoints  http.Handler
	gate       http.Handler
	tm         *apitoken.TokenManager
	ex         *auth.Exchanger
	backendFAT *string
	backendURL string
}

func newE2EHarness(t *testing.T) *e2eHarness {
	t.Helper()
	logf.SetLogger(logr.Discard())

	// Backend MCP server: captures the forwarded Authorization (FAT) so the
	// test can prove a FAT (not the spec-facing PAT) is sent inside, with the
	// backend Service origin as its audience.
	backendFAT := new(string)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*backendFAT = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	ttl := time.Hour
	cacheManager, err := cache.NewCacheManager("", "mcp-e2e-test", &ttl)
	require.NoError(t, err)

	// TokenManager issuer MUST equal the host issuer: the proxy gate validates
	// the PAT against issuer+basePath as the resource audience.
	tm, err := apitoken.NewTokenManager(e2eIssuer, apitoken.GenerateDevmodeKeyPair(), nil)
	require.NoError(t, err)

	// JWT signer used by the authorization_code redemption path (mintTokensFromCode
	// signs an intermediate JWT before the resource-PAT branch replaces it).
	signer, err := sign.NewSigner(
		e2eIssuer, ttl, e2eIssuer, &signerKey, "e2e-kid", nil,
	)
	require.NoError(t, err)

	// Stub identity provider: the test subject resolves to the entitlement the
	// gate requires, so request-time role resolution authorizes the call.
	idp := stubInternalIdentityProvider{
		roles: []string{"mcp-role"},
		ents:  []string{e2eScope},
	}

	dcrStore := dcr.NewStore(cacheManager, e2eDomain, ttl, 100)

	// Exchanger config: owns BlockKey (auth-code JWE), Signer, TokenManager
	// (resource PAT mint) and the DCR store (so GetClient resolves the
	// dynamically-registered client).
	exCfg := auth.Config{
		Signer:       *signer,
		TokenManager: tm,
		TokenTTL:     ttl,
		DCRStore:     dcrStore,
	}
	exCfg.OIDC.BlockKey = "e2e-block-key-0123456789abcdef"

	ex, err := auth.NewExchanger(t.Context(), exCfg, cacheManager, idp)
	require.NoError(t, err)

	fn := newReadyFunctionWithOAuth2(t, e2eBasePath, []string{e2eScope})
	fn.Status.URL = upstream.URL

	// authConfig drives the HTTP endpoints: ActivePair gates IsAuthEnabled
	// (token endpoint), DCR enables /-/oauth/register, TokenManager+TokenTTL
	// feed the resource-PAT mint and the proxy gate.
	authConfig := &auth.Config{
		ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "e2e-kid", Private: signerKey},
		Audience:     "https://api-host.example.com",
		TokenManager: tm,
		TokenTTL:     ttl,
		DCR: auth.DCRConfig{
			Enabled:                true,
			ClientTTL:              ttl,
			MaxClients:             100,
			AllowedRedirectSchemes: []string{"https", "http-loopback"},
		},
		DCRStore: dcrStore,
	}

	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  &entitlementGateChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{e2eDomain}},
		},
		functions:     []kdexv1alpha1.KDexFunction{fn},
		authConfig:    authConfig,
		authExchanger: ex,
	}

	// Authorization-server endpoints exposed over HTTP. tokenHandler records
	// itself into registeredPaths (must be non-nil).
	mux := http.NewServeMux()
	registeredPaths := map[string]ko.PathInfo{}
	hh.registerHandler(mux, registeredPaths)
	hh.tokenHandler(mux, registeredPaths)
	hh.protectedResourceHandler(mux, registeredPaths)

	return &e2eHarness{
		endpoints:  mux,
		gate:       hh.reverseProxyHandler(&fn, e2eIssuer),
		tm:         tm,
		ex:         ex,
		backendFAT: backendFAT,
		backendURL: upstream.URL,
	}
}

// pkcePair returns an RFC 7636 (verifier, S256 challenge) pair.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// register performs RFC 7591 DCR over HTTP and returns the new client_id.
func (h *e2eHarness) register(t *testing.T) string {
	t.Helper()
	body := `{"redirect_uris":["` + e2eRedirect + `"],"client_name":"Claude MCP"}`
	req := httptest.NewRequest("POST", "/-/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.endpoints.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, "register body=%s", rr.Body.String())
	var resp struct {
		ClientID string `json:"client_id"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ClientID, "register must return a client_id")
	return resp.ClientID
}

// TestMCPOAuth2E2E exercises the full load-bearing chain end-to-end:
// DCR -> (synthesized) authorization-code + PKCE + resource -> /-/token PAT
// -> proxy gate -> FAT, plus the RFC 9728 metadata and 401 challenge surfaces.
func TestMCPOAuth2E2E(t *testing.T) {
	h := newE2EHarness(t)

	// --- Step 1: Dynamic Client Registration (RFC 7591) over HTTP. ---
	clientID := h.register(t)

	// --- Step 2: PKCE pair + synthesized authorization code. ---
	// Driving the full browser-login of /-/oauth/authorize requires an
	// authenticated session (cookie/JWT); the brief permits synthesizing that
	// leg by minting the code the authorize handler would have produced. This
	// keeps the test honest on the load-bearing chain (register -> code ->
	// /-/token PAT -> gate -> FAT) without reimplementing the login UI. The
	// subject resolves (via the stub scopeProvider) to the entitlement the
	// gate requires.
	verifier, challenge := pkcePair(t)
	code, err := h.ex.CreateAuthorizationCode(t.Context(), auth.AuthorizationCodeClaims{
		AuthMethod:          auth.AuthMethodOAuth2,
		ClientID:            clientID,
		RedirectURI:         e2eRedirect,
		Scope:               e2eScope,
		Subject:             e2eSubject,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Resource:            e2eResource,
		Exp:                 time.Now().Add(10 * time.Minute).Unix(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// --- Step 3: /-/token (authorization_code) over HTTP mints an aud-bound PAT. ---
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"redirect_uri":  {e2eRedirect},
		"resource":      {e2eResource},
	}
	req := httptest.NewRequest("POST", "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.endpoints.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "token body=%s", rr.Body.String())
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &tok))
	require.NotEmpty(t, tok.AccessToken, "token endpoint must return an access_token")
	assert.Equal(t, "Bearer", tok.TokenType)

	// The access_token is an audience-bound PAT: it validates ONLY against the
	// resource it was minted for (RFC 8707), and is rejected for any other.
	td, err := h.tm.ValidateToken(t.Context(), tok.AccessToken, e2eResource)
	require.NoError(t, err, "PAT must validate against its bound resource audience")
	require.NotNil(t, td)
	_, err = h.tm.ValidateToken(t.Context(), tok.AccessToken, e2eIssuer+"/api/v1/other")
	require.Error(t, err, "PAT must be REJECTED for a different audience")

	// --- Step 4: proxy gate accepts the Bearer PAT, mints a FAT for the backend. ---
	mcpReq := httptest.NewRequest("POST", e2eBasePath, strings.NewReader("{}"))
	mcpReq.Host = e2eDomain
	mcpReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	mcpRec := httptest.NewRecorder()
	h.gate.ServeHTTP(mcpRec, mcpReq)

	require.Equal(t, http.StatusOK, mcpRec.Code, "Bearer PAT must pass the gate and reach the backend")
	require.NotEmpty(t, *h.backendFAT, "backend must receive a forwarded Authorization header")

	// The forwarded credential is a FAT (JWT), NOT the inbound PAT, and its aud
	// is the backend Service origin (NOT the spec-facing resource URI). This is
	// the "spec-compliant PAT outside, FAT-with-correct-aud inside" invariant.
	require.NotEqual(t, "Bearer "+tok.AccessToken, *h.backendFAT,
		"inbound PAT must NOT be forwarded verbatim; a FAT is minted instead")
	fatClaims := decodeFAT(t, *h.backendFAT)
	assert.Equal(t, e2eSubject, fatClaims["sub"], "FAT subject must be the PAT subject")
	assertAudEquals(t, fatClaims, h.backendURL)
	assertAudNotEquals(t, fatClaims, e2eResource)

	// --- Step 5a: RFC 9728 protected-resource metadata over HTTP. ---
	pr := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource"+e2eBasePath, nil)
	pr.Host = e2eDomain
	prRec := httptest.NewRecorder()
	h.endpoints.ServeHTTP(prRec, pr)

	require.Equal(t, http.StatusOK, prRec.Code, "metadata body=%s", prRec.Body.String())
	var md ProtectedResourceMetadata
	require.NoError(t, json.Unmarshal(prRec.Body.Bytes(), &md))
	assert.Equal(t, e2eResource, md.Resource)
	assert.Equal(t, []string{e2eIssuer}, md.AuthorizationServers)
	assert.Contains(t, md.ScopesSupported, e2eScope)

	// --- Step 5b: unauthenticated MCP request gets a 401 + WWW-Authenticate. ---
	unauth := httptest.NewRequest("POST", e2eBasePath, strings.NewReader("{}"))
	unauth.Host = e2eDomain
	unauthRec := httptest.NewRecorder()
	h.gate.ServeHTTP(unauthRec, unauth)

	require.Equal(t, http.StatusUnauthorized, unauthRec.Code,
		"unauthenticated oauth2-protected request must be challenged")
	assert.NotEmpty(t, unauthRec.Header().Get("WWW-Authenticate"),
		"401 challenge must carry a WWW-Authenticate header")
}

// assertAudEquals asserts the FAT's aud claim (string or single-element array)
// equals want.
func assertAudEquals(t *testing.T, claims jwt.MapClaims, want string) {
	t.Helper()
	auds := normalizeAud(t, claims)
	require.Len(t, auds, 1, "FAT should carry exactly one audience")
	assert.Equal(t, want, auds[0],
		"FAT audience must be the backend Service origin, not the resource URI")
}

// assertAudNotEquals asserts the FAT's aud does NOT contain notWant.
func assertAudNotEquals(t *testing.T, claims jwt.MapClaims, notWant string) {
	t.Helper()
	for _, a := range normalizeAud(t, claims) {
		assert.NotEqual(t, notWant, a,
			"FAT audience must NOT be the spec-facing resource URI")
	}
}

func normalizeAud(t *testing.T, claims jwt.MapClaims) []string {
	t.Helper()
	aud, ok := claims["aud"]
	require.True(t, ok, "FAT must carry an aud claim")
	switch v := aud.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			s, ok := x.(string)
			require.True(t, ok, "aud array element must be a string")
			out = append(out, s)
		}
		return out
	default:
		t.Fatalf("unexpected aud claim type %T: %v", aud, aud)
		return nil
	}
}

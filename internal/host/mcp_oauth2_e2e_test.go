/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"context"
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
	entitlements "github.com/kdex-tech/entitlements/go"
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

	// e2eOtherScope is an entitlement for a DIFFERENT resource. The negative
	// subject resolves to this (and only this); it is a valid entitlement but
	// does NOT satisfy the gate's required functions:/api/v1/mcp:read.
	e2eOtherScope = "functions:/something/else:read"
	// e2eDeniedSubject is the negative-path subject: it holds a valid,
	// resource-bound PAT for e2eResource but, via role resolution, lacks
	// e2eScope. The gate must deny it.
	e2eDeniedSubject = "mcp-mallory"
)

// e2ePerSubjectIDP resolves each subject to a fixed roles/entitlements set,
// keyed by subject. Unlike stubInternalIdentityProvider (which returns the same
// entitlements for every subject), this lets the e2e drive both an authorized
// subject (holds e2eScope) and a denied subject (holds only e2eOtherScope)
// through the SAME PAT flow, so the gate's authorization is exercised on the
// subject's role-resolved entitlements rather than on PAT possession alone.
type e2ePerSubjectIDP struct {
	roles map[string][]string
	ents  map[string][]string
}

func (e2ePerSubjectIDP) FindInternal(string, string) (jwt.MapClaims, error) {
	return nil, nil
}

func (p e2ePerSubjectIDP) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	return p.roles[subject], p.ents[subject], nil
}

// e2eEntitlementGateChecker drives the proxy gate through the REAL entitlements
// engine (auth.AuthorizationChecker) so the e2e proves SPECIFICITY: the gate
// authorizes only when the subject's role-resolved entitlements actually
// satisfy the required functions:/api/v1/mcp:read, not merely when SOME
// entitlement is present.
//
// Every method delegates to the real checker UNMODIFIED — including
// VerifyResourceParsedEntitlements, which now receives the function's REAL
// parsed requirements ({oauth2: ["functions:/api/v1/mcp:read"]}) verbatim from
// the proxy gate. This proves the §4 fix end-to-end: a PAT-bridge caller's
// role-resolved entitlements are mirrored into the "oauth2" bucket by
// GetParsedEntitlements, so the authorized subject satisfies the oauth2-ONLY
// requirement while the wrong-entitlement subject is denied. (Previously this
// shim discarded the requirements and passed entitlements.ParsedRequirements{},
// which silently bypassed — and hid — the defect.)
type e2eEntitlementGateChecker struct {
	real *auth.AuthorizationChecker
}

func (g *e2eEntitlementGateChecker) CalculateRequirements(resource, resourceName string, reqs []kdexv1alpha1.SecurityRequirement, verbs ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return g.real.CalculateRequirements(resource, resourceName, reqs, verbs...)
}

func (g *e2eEntitlementGateChecker) CheckAccess(ctx context.Context, resource, resourceName string, reqs []kdexv1alpha1.SecurityRequirement, verbs ...string) (bool, error) {
	return g.real.CheckAccess(ctx, resource, resourceName, reqs, verbs...)
}

func (g *e2eEntitlementGateChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	return g.real.GetParsedEntitlements(ctx)
}

func (g *e2eEntitlementGateChecker) ParseRequirements(reqs []kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return g.real.ParseRequirements(reqs)
}

func (g *e2eEntitlementGateChecker) VerifyResourceParsedEntitlements(resource, resourceName string, ents entitlements.ParsedEntitlements, reqs entitlements.ParsedRequirements, verbs ...string) (bool, error) {
	// Pass the function's REAL parsed requirements through verbatim. The proxy
	// gate computes these from the operation's {oauth2: [...]} security and the
	// resource identity; authorization must turn on whether the subject's
	// role-resolved entitlements satisfy them. Do NOT shortcut with empty
	// requirements — that bypassed (and hid) the §4 oauth2-bucket defect.
	return g.real.VerifyResourceParsedEntitlements(resource, resourceName, ents, reqs, verbs...)
}

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

	// Per-subject identity provider: the authorized subject resolves to the
	// entitlement the gate requires; the denied subject resolves to a DIFFERENT
	// (valid but insufficient) entitlement. Request-time role resolution — not
	// PAT possession — decides authorization, so both subjects can drive the
	// identical PAT flow and only the authorized one reaches the backend.
	idp := e2ePerSubjectIDP{
		roles: map[string][]string{
			e2eSubject:       {"mcp-role"},
			e2eDeniedSubject: {"other-role"},
		},
		ents: map[string][]string{
			e2eSubject:       {e2eScope},
			e2eDeniedSubject: {e2eOtherScope},
		},
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
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "e2e-kid", Private: signerKey},
		// Audience is the host JWT audience (used for non-oauth2 apiKey bridge
		// callers). It deliberately differs from the TokenManager issuer
		// (e2eIssuer) that mints PATs: an oauth2-protected PAT is validated
		// against the function's RFC 8707 RESOURCE audience (e2eResource), not
		// this host audience, so these two values must NOT be confused.
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
		authChecker:  &e2eEntitlementGateChecker{real: auth.NewAuthorizationChecker(nil, logr.Discard())},
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

// mintPATForSubject drives the full spec-facing OAuth2 flow for the given
// subject: DCR -> (synthesized) authorization-code + PKCE + resource -> /-/token
// PAT. The resulting access_token is an aud-bound PAT for e2eResource regardless
// of subject (the resource binding is from the authorization request, not from
// role resolution), which is exactly what lets the negative case prove that a
// VALID, correctly-bound PAT is still denied when the subject lacks the
// required entitlement.
func (h *e2eHarness) mintPATForSubject(t *testing.T, subject string) string {
	t.Helper()

	clientID := h.register(t)

	verifier, challenge := pkcePair(t)
	code, err := h.ex.CreateAuthorizationCode(t.Context(), auth.AuthorizationCodeClaims{
		AuthMethod:          auth.AuthMethodOAuth2,
		ClientID:            clientID,
		RedirectURI:         e2eRedirect,
		Scope:               e2eScope,
		Subject:             subject,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Resource:            e2eResource,
		Exp:                 time.Now().Add(10 * time.Minute).Unix(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, code)

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
	require.Equal(t, "Bearer", tok.TokenType)
	return tok.AccessToken
}

// TestMCPOAuth2E2E exercises the full load-bearing chain end-to-end:
// DCR -> (synthesized) authorization-code + PKCE + resource -> /-/token PAT
// -> proxy gate -> FAT, plus the RFC 9728 metadata and 401 challenge surfaces.
func TestMCPOAuth2E2E(t *testing.T) {
	// --- Positive: an authorized subject reaches the backend. ---
	t.Run("authorized subject reaches backend", func(t *testing.T) {
		h := newE2EHarness(t)

		// --- Steps 1-3: DCR -> (synthesized) authorization-code + PKCE +
		// resource -> /-/token mints an aud-bound PAT for e2eSubject. Driving
		// the full browser-login of /-/oauth/authorize requires an
		// authenticated session (cookie/JWT); the brief permits synthesizing
		// that leg by minting the code the authorize handler would have
		// produced. This keeps the test honest on the load-bearing chain
		// (register -> code -> /-/token PAT -> gate -> FAT) without
		// reimplementing the login UI. e2eSubject resolves (via the per-subject
		// scopeProvider) to e2eScope, the entitlement the gate requires.
		accessToken := h.mintPATForSubject(t, e2eSubject)

		// The access_token is an audience-bound PAT: it validates ONLY against
		// the resource it was minted for (RFC 8707), and is rejected for any
		// other.
		td, err := h.tm.ValidateToken(t.Context(), accessToken, e2eResource)
		require.NoError(t, err, "PAT must validate against its bound resource audience")
		require.NotNil(t, td)
		_, err = h.tm.ValidateToken(t.Context(), accessToken, e2eIssuer+"/api/v1/other")
		require.Error(t, err, "PAT must be REJECTED for a different audience")

		// --- Step 4: proxy gate accepts the Bearer PAT, mints a FAT for the backend. ---
		mcpReq := httptest.NewRequest("POST", e2eBasePath, strings.NewReader("{}"))
		mcpReq.Host = e2eDomain
		mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
		mcpRec := httptest.NewRecorder()
		h.gate.ServeHTTP(mcpRec, mcpReq)

		require.Equal(t, http.StatusOK, mcpRec.Code, "Bearer PAT must pass the gate and reach the backend")
		require.NotEmpty(t, *h.backendFAT, "backend must receive a forwarded Authorization header")

		// The forwarded credential is a FAT (JWT), NOT the inbound PAT, and its
		// aud is the backend Service origin (NOT the spec-facing resource URI).
		// This is the "spec-compliant PAT outside, FAT-with-correct-aud inside"
		// invariant.
		require.NotEqual(t, "Bearer "+accessToken, *h.backendFAT,
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
	})

	// --- Negative: a subject WITHOUT the required entitlement is denied even
	// with a valid, correctly-resource-bound PAT. This is the load-bearing
	// specificity assertion: authorization comes from role resolution
	// (functions:/api/v1/mcp:read), NOT from PAT possession. e2eDeniedSubject
	// resolves only to e2eOtherScope (a valid but insufficient entitlement). ---
	t.Run("subject without required entitlement is denied", func(t *testing.T) {
		h := newE2EHarness(t)

		// Drive the IDENTICAL flow (register -> authcode+PKCE+resource ->
		// /-/token PAT) for the denied subject. The minted PAT is genuine and
		// correctly bound to e2eResource (resource binding comes from the
		// authorization request, not from role resolution).
		accessToken := h.mintPATForSubject(t, e2eDeniedSubject)

		// Sanity: the PAT really is valid for the resource — so denial below is
		// NOT a token/audience failure, it is an entitlement (authorization)
		// failure. This is what distinguishes the gate's specific-entitlement
		// check from the resource-audience check already covered above.
		td, err := h.tm.ValidateToken(t.Context(), accessToken, e2eResource)
		require.NoError(t, err, "denied subject's PAT must still be a VALID resource-bound token")
		require.NotNil(t, td)

		mcpReq := httptest.NewRequest("POST", e2eBasePath, strings.NewReader("{}"))
		mcpReq.Host = e2eDomain
		mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
		mcpRec := httptest.NewRecorder()
		h.gate.ServeHTTP(mcpRec, mcpReq)

		// The request MUST be denied: the subject's role-resolved entitlements
		// (e2eOtherScope) do not satisfy the required functions:/api/v1/mcp:read.
		assert.Empty(t, *h.backendFAT,
			"denied subject must NOT reach the backend (no FAT forwarded)")
		assert.Contains(t, []int{http.StatusUnauthorized, http.StatusNotFound}, mcpRec.Code,
			"gate must deny a subject lacking the required entitlement (401 or 404)")
	})
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

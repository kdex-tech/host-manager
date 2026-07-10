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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// stubInternalIdentityProvider resolves any subject to a fixed set of roles
// and entitlements, standing in for the cluster-backed scopeProvider.
type stubInternalIdentityProvider struct {
	roles    []string
	ents     []string
	resolved jwt.MapClaims // #138: fresh-resolved backend claims (e.g. vs_entitlements)
}

func (s stubInternalIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return nil, nil
}

func (s stubInternalIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return s.roles, s.ents, nil
}

// ResolveClaims lets the stub satisfy the Exchanger's optional resolve capability
// (#138), standing in for the cluster-backed scopeProvider's Lookup resolve.
func (s stubInternalIdentityProvider) ResolveClaims(string) jwt.MapClaims {
	return s.resolved
}

const apitokenBridgeHostAudience = "https://api-host.example.com"

// apitokenBridgeFixture builds a HostHandler + reverse-proxy handler for a
// function and returns the handler plus a TokenManager minting tokens the host
// will accept. The upstream echoes back the inbound Authorization (FAT) and the
// preserved X-API-TOKEN cookie so the test can inspect what the function sees.
func apitokenBridgeFixture(t *testing.T, fn *kdexv1alpha1.KDexFunction, idp auth.InternalIdentityProvider) (http.Handler, *apitoken.TokenManager, *string, *string) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	fatHeader := new(string)
	apiTokenCookie := new(string)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*fatHeader = r.Header.Get("Authorization")
		if c, err := r.Cookie("X-API-TOKEN"); err == nil {
			*apiTokenCookie = c.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	fn.Status.URL = upstream.URL

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cacheManager, _ := cache.NewCacheManager("", "apitoken-bridge-test", nil)
	tm, err := apitoken.NewTokenManager("api-token-issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	require.NoError(t, err)

	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cacheManager, idp)
	require.NoError(t, err)

	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		// Permissive gate: this suite isolates the PASETO->authContext bridge
		// and the FAT mint, not the identity gate.
		authChecker: &mockAuthChecker{},
		authConfig: &auth.Config{
			ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
			Audience:     apitokenBridgeHostAudience,
			TokenManager: tm,
		},
		authExchanger: ex,
	}

	return hh.reverseProxyHandler(fn, "https://api-host.example.com"), tm, fatHeader, apiTokenCookie
}

func apiKeySecuredFunction(basePath string, withAPIKey bool) *kdexv1alpha1.KDexFunction {
	security := `"security":[{"apiKeyCookie":[]},{"apiKeyHeader":[]},{"apiKeyQuery":[]}],`
	if !withAPIKey {
		security = ""
	}
	raw := []byte(`{` + security + `"responses":{"200":{"description":"ok"}}}`)
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-apikey", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: basePath,
				Paths: map[string]kdexv1alpha1.PathItem{
					basePath: {Get: &runtime.RawExtension{Raw: raw}},
				},
			},
		},
	}
}

func decodeFAT(t *testing.T, header string) jwt.MapClaims {
	t.Helper()
	require.True(t, strings.HasPrefix(header, "Bearer "), "expected Bearer FAT, got %q", header)
	// ParseUnverified is deliberate: these tests assert on the FAT's CLAIMS
	// (sub/aud), not its signature, and the FAT signing key is internal to the
	// proxy and not exposed to the test scope. Signature verification is covered
	// elsewhere; here we only need to read the minted claims.
	parsed, _, err := jwt.NewParser().ParseUnverified(strings.TrimPrefix(header, "Bearer "), jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

// TestProxy_APITokenBridge_MintsFAT pins the happy path of
// kdex-tech/host-manager#103: a valid PASETO X-API-TOKEN on an apiKey-declaring
// function is bridged into authContext, the proxy mints a FAT carrying the
// subject's resolved roles/entitlements (plus the token's static scope), and
// the raw PASETO is still forwarded to the backend.
func TestProxy_APITokenBridge_MintsFAT(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, tm, fatHeader, apiTokenCookie := apitokenBridgeFixture(t, fn, idp)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	claims := decodeFAT(t, *fatHeader)
	assert.Equal(t, "api-bob", claims["sub"], "FAT subject must be the PASETO subject")
	assert.Contains(t, jwtClaimsToString(t, claims), "functions:read",
		"FAT must carry the subject's resolved entitlements")
	assert.Equal(t, "scope:abc", claims["scp"], "FAT must preserve the token's static scope")
	assert.Equal(t, token, *apiTokenCookie, "raw PASETO must still be forwarded to the backend")
}

// TestProxy_APITokenBridge_HeaderAndQuery verifies the bridge accepts the token
// from the X-API-TOKEN header and the api_token query parameter, not just the
// cookie.
func TestProxy_APITokenBridge_HeaderAndQuery(t *testing.T) {
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}

	t.Run("header", func(t *testing.T) {
		fn := apiKeySecuredFunction("/v1/api", true)
		handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)
		token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/v1/api", nil)
		req.Header.Set("X-API-TOKEN", token)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, "api-bob", decodeFAT(t, *fatHeader)["sub"])
	})

	t.Run("query", func(t *testing.T) {
		fn := apiKeySecuredFunction("/v1/api", true)
		handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)
		token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
		require.NoError(t, err)
		req := httptest.NewRequest("GET", "/v1/api?api_token="+token, nil)
		handler.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, "api-bob", decodeFAT(t, *fatHeader)["sub"])
	})
}

// TestProxy_APITokenBridge_NoOptIn verifies the bridge does NOT fire for a
// function that doesn't declare an apiKey* scheme: the caller stays anonymous
// and no FAT is minted (Authorization is stripped outbound).
func TestProxy_APITokenBridge_NoOptIn(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", false)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, *fatHeader, "bridge must not fire (no apiKey scheme declared); no FAT expected")
}

// TestProxy_APITokenBridge_InvalidToken verifies an invalid PASETO leaves the
// request anonymous (no FAT minted).
func TestProxy_APITokenBridge_InvalidToken(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, _, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: "v4.public.not-a-real-token"})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Empty(t, *fatHeader, "invalid token must not populate authContext; no FAT expected")
}

// TestProxy_APITokenBridge_JWTWins verifies JWT precedence on mixed-token
// requests: when WithAuthentication already populated authContext, the bridge
// no-ops (the FAT carries the JWT subject) while the raw PASETO still forwards.
func TestProxy_APITokenBridge_JWTWins(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, tm, fatHeader, apiTokenCookie := apitokenBridgeFixture(t, fn, idp)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
	require.NoError(t, err)

	jwtCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "jwt-alice",
		"entitlements": []any{"functions:read"},
	})
	req := httptest.NewRequest("GET", "/v1/api", nil).WithContext(jwtCtx)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, "jwt-alice", decodeFAT(t, *fatHeader)["sub"], "JWT identity must win over PASETO")
	assert.Equal(t, token, *apiTokenCookie, "raw PASETO must still be forwarded alongside the JWT-derived FAT")
}

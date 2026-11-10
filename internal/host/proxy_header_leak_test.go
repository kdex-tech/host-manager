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

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TestProxy_FATDoesNotLeakSensitiveHeaders pins the fix for
// kdex-tech/host-manager#90. Pre-fix the Rewrite callback copied every
// inbound header into authContext["headers"] verbatim. Functions with
// ClaimMappings that extracted `self.headers.authorization`,
// `self.headers.cookie`, or `self.headers.x-forwarded-for` embedded
// the sensitive values (the user's host token / session cookies /
// attacker-spoofed XFF) into the signed FAT JWT.
//
// Post-fix Authorization, Cookie, and X-Forwarded-* headers are
// stripped from the headers map before signing — even a mapper that
// asks for them can't get the values out of authContext.
func TestProxy_FATDoesNotLeakSensitiveHeaders(t *testing.T) {
	// The function's ClaimMappings try to lift the three sensitive header
	// families into JWT claims.
	handler, fatHeader := leakFixture(t, "fn-leak", []dmapper.MappingRule{
		{Required: false, SourceExpression: `self.headers["Authorization"][0]`, TargetPropPath: "leak_authorization"},
		{Required: false, SourceExpression: `self.headers["Cookie"][0]`, TargetPropPath: "leak_cookie"},
		{Required: false, SourceExpression: `self.headers["X-Forwarded-For"][0]`, TargetPropPath: "leak_xff"},
	})

	authedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "alice",
		"entitlements": []any{"pages:read"},
	})

	const (
		sensitiveAuth   = "SENSITIVE-USER-TOKEN-DO-NOT-LEAK"
		sensitiveCookie = "session=SENSITIVE-SESSION-COOKIE"
		spoofedXFF      = "10.0.0.1, 192.168.0.1"
	)

	req := httptest.NewRequest("GET", "/v1/leak", nil).WithContext(authedCtx)
	req.Header.Set("Authorization", "Bearer "+sensitiveAuth)
	req.Header.Set("Cookie", sensitiveCookie)
	req.Header.Set("X-Forwarded-For", spoofedXFF)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)

	// Render the claims to a string and assert the sensitive values
	// don't appear anywhere — not under the mapping's TargetPropPath,
	// not in any other claim.
	serialized := jwtClaimsToString(t, claims)
	assert.NotContains(t, serialized, sensitiveAuth,
		"FAT must NOT carry the user's Authorization header value (#90)")
	assert.NotContains(t, serialized, sensitiveCookie,
		"FAT must NOT carry the user's Cookie header value (#90)")
	assert.NotContains(t, serialized, "10.0.0.1",
		"FAT must NOT carry the inbound (attacker-spoofable) X-Forwarded-For value (#90)")
}

func jwtClaimsToString(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	var b strings.Builder
	for k, v := range claims {
		b.WriteString(k)
		b.WriteString(": ")
		switch vv := v.(type) {
		case string:
			b.WriteString(vv)
		case []any:
			for _, x := range vv {
				if s, ok := x.(string); ok {
					b.WriteString(s)
					b.WriteString(",")
				}
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// The #90 fix stripped the Cookie header from the snapshot the mapper reads,
// but the proxy also parses the cookie jar into authContext["cookies"], and a
// function author's claimMappings run over it. A rule reading
// `self.cookies.auth_token` would put every caller's HttpOnly session token
// (or refresh token) into the FAT, and the backend could replay it at the host
// as that caller. The host's own credential cookies never reach the mapper;
// any other cookie still does.
func TestProxy_FATDoesNotLeakHostCredentialCookies(t *testing.T) {
	credentials := map[string]string{
		"auth_token":          "SESSION-TOKEN",
		"auth_token_refresh":  "REFRESH-TOKEN",
		"auth_token_oidc_abc": "LOGIN-STATE",
		"oidc_hint_0":         "ID-TOKEN-CHUNK",
		"X-API-TOKEN":         "API-TOKEN",
	}
	var rules []dmapper.MappingRule
	for name := range credentials {
		rules = append(rules, dmapper.MappingRule{
			SourceExpression: `self.cookies["` + name + `"]`, TargetPropPath: "leak_" + strings.ReplaceAll(name, "-", "_"),
		})
	}
	rules = append(rules, dmapper.MappingRule{SourceExpression: `self.cookies["theme"]`, TargetPropPath: "theme"})

	handler, fatHeader := leakFixture(t, "fn-cookie-leak", rules)

	authedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "alice",
		"entitlements": []any{"pages:read"},
	})
	req := httptest.NewRequest("GET", "/v1/leak", nil).WithContext(authedCtx)
	for name, value := range credentials {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	serialized := jwtClaimsToString(t, claims)
	for name, value := range credentials {
		assert.NotContains(t, serialized, value, "the FAT must not carry the %s cookie", name)
	}
	assert.Equal(t, "dark", claims["theme"], "a cookie that is not a host credential still maps")
}

// The API token travels as a header too, and the header snapshot is what a
// `self.headers` rule reads: it must not carry the token any more than the
// cookie jar does. An ordinary header beside it still maps, so a rule that
// silently read nothing cannot pass for the strip.
func TestProxy_FATDoesNotLeakTheAPITokenHeader(t *testing.T) {
	handler, fatHeader := leakFixture(t, "fn-header-leak", []dmapper.MappingRule{
		{SourceExpression: `self.headers["X-Api-Token"][0]`, TargetPropPath: "leak_api_token"},
		{SourceExpression: `self.headers["X-Theme"][0]`, TargetPropPath: "theme"},
	})

	req := httptest.NewRequest("GET", "/v1/leak", nil).WithContext(
		auth.SetAuthContext(t.Context(), auth.AuthContext{"sub": "alice"}))
	req.Header.Set("X-API-TOKEN", "API-TOKEN-HEADER")
	req.Header.Set("X-Theme", "dark")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	assert.NotContains(t, jwtClaimsToString(t, claims), "API-TOKEN-HEADER")
	assert.Equal(t, "dark", claims["theme"], "an ordinary header still maps")
}

// leakFixture is a proxy handler for a function with these claimMappings, and
// the Authorization (the FAT) its upstream last received.
func leakFixture(t *testing.T, name string, rules []dmapper.MappingRule) (http.Handler, *string) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	fatHeader := new(string)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*fatHeader = r.Header.Get("Authorization")
	}))
	t.Cleanup(upstream.Close)

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef:       corev1.LocalObjectReference{Name: "h"},
			API:           kdexv1alpha1.API{BasePath: "/v1/leak"},
			ClaimMappings: rules,
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: upstream.URL},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv
	cacheManager, _ := cache.NewCacheManager("", name+"-test", nil)
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authConfig: &auth.Config{
			CookieName: "auth_token",
			ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
		},
	}
	return hh.reverseProxyHandler(fn, "https://test-host.example.com"), fatHeader
}

func TestWithoutQueryParam(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"api_token=x":                   "",
		"a=1&api_token=x&b=%2F":         "a=1&b=%2F",
		"api%5Ftoken=x&api_token=y&c=3": "c=3",
		"api_tokens=x&b":                "api_tokens=x&b",
	} {
		assert.Equal(t, want, withoutQueryParam(in, "api_token"), in)
	}
}

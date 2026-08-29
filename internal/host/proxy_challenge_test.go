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
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// challengeFixtureAuthConfig builds a minimal auth.Config with a real key pair
// but no TokenManager, so the PAT bridge is skipped and every request arrives
// at the gate as anonymous.
func challengeFixtureAuthConfig(t *testing.T) *auth.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv
	return &auth.Config{
		ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "challenge-kid", Private: signerKey},
		Audience:     "https://api-host.example.com",
		TokenManager: nil, // no PAT bridge
	}
}

// newOAuth2ProtectedHandler builds an http.Handler for an oauth2-protected
// function at basePath on the given domain, with no valid credential
// preconfigured. The entitlementGateChecker from proxy_pat_test.go is reused
// (it denies all anonymous requests), so any unauthenticated hit will fail the
// gate.
func newOAuth2ProtectedHandler(t *testing.T, domain, basePath string) http.Handler {
	t.Helper()
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fn := newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"})
	fn.Status.URL = upstream.URL

	issuer := "https://" + domain
	cacheManager, _ := cache.NewCacheManager("", "challenge-test-oauth2", nil)

	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  &entitlementGateChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{domain}},
		},
		// oauth2ProtectedResources() enumerates over hh.functions; the function
		// must be present for the handler to detect itself as oauth2-protected.
		functions:  []kdexv1alpha1.KDexFunction{fn},
		authConfig: challengeFixtureAuthConfig(t),
	}

	return hh.reverseProxyHandler(&fn, issuer)
}

// newBearerOnlyHandler builds an http.Handler for a bearer-only (non-oauth2)
// gated function at basePath on the given domain, with no credential.
func newBearerOnlyHandler(t *testing.T, domain, basePath string) http.Handler {
	t.Helper()
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fn := newReadyFunctionBearerOnly(t, basePath)
	fn.Status.URL = upstream.URL

	issuer := "https://" + domain
	cacheManager, _ := cache.NewCacheManager("", "challenge-test-bearer", nil)

	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  &entitlementGateChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{domain}},
		},
		// bearer-only function: NOT listed as oauth2-protected.
		functions:  []kdexv1alpha1.KDexFunction{fn},
		authConfig: challengeFixtureAuthConfig(t),
	}

	return hh.reverseProxyHandler(&fn, issuer)
}

func TestUnauthorizedOAuth2PathReturns401Challenge(t *testing.T) {
	h := newOAuth2ProtectedHandler(t, "dev.knowdrive.ai", "/api/v1/mcp")
	req := httptest.NewRequest("POST", "/api/v1/mcp", strings.NewReader("{}"))
	req.Host = "dev.knowdrive.ai"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	wa := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `resource_metadata="https://dev.knowdrive.ai/.well-known/oauth-protected-resource/api/v1/mcp"`) {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
}

// A bearer-only (non-oauth2) function used to return the anti-enumeration
// 404 here. That concealed nothing -- /-/openapi publishes the same path to
// the same anonymous caller -- so the contract returns an actionable 401
// with a realm challenge instead.
func TestUnauthorizedBearerOnlyPathReturns401WithRealm(t *testing.T) {
	h := newBearerOnlyHandler(t, "dev.knowdrive.ai", "/v1/admin")
	req := httptest.NewRequest("GET", "/v1/admin", nil)
	req.Host = "dev.knowdrive.ai"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (anti-enum 404 retired)", rr.Code)
	}
	got := rr.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer realm="`) {
		t.Fatalf("challenge = %q, want a Bearer realm challenge", got)
	}
	if strings.Contains(got, "error=") {
		t.Fatalf("challenge = %q; RFC 6750 3.1 omits error= when no credentials were sent", got)
	}
}

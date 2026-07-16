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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	patProxyDomain   = "dev.knowdrive.ai"
	patProxyIssuer   = "https://" + patProxyDomain
	patProxyBasePath = "/api/v1/mcp"
	patProxyResource = patProxyIssuer + patProxyBasePath
	patProxyHostAud  = "https://api-host.example.com"
)

// entitlementGateChecker only authorizes when the request's authContext carries
// resolved entitlements (i.e. the PAT bridge successfully validated the token
// and populated identity). An anonymous request — including one whose PAT failed
// the resource-audience check — has no entitlements and is denied. This lets the
// proxy PAT test distinguish "reached the backend" from "blocked at the gate".
// The proxy gate calls GetParsedEntitlements then VerifyResourceParsedEntitlements
// sequentially per request, so the authed flag carries across the pair.
type entitlementGateChecker struct {
	authed bool
}

func (entitlementGateChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (entitlementGateChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return true, nil
}

func (g *entitlementGateChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	authContext, _ := auth.GetAuthContext(ctx)
	ents, _ := authContext.GetEntitlements()
	g.authed = len(ents) > 0
	return entitlements.ParsedEntitlements{}
}

func (entitlementGateChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (entitlementGateChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}

func (g *entitlementGateChecker) VerifyResourceParsedEntitlements(_, _ string, _ entitlements.ParsedEntitlements, _ entitlements.ParsedRequirements, _ ...string) (bool, error) {
	return g.authed, nil
}

// patProxyFixture builds an oauth2-protected /api/v1/mcp reverse-proxy handler
// backed by an httptest.Server, plus a TokenManager whose issuer matches the
// host issuer so a minted PAT with aud=patProxyResource validates against the
// resource. backendReached reports whether the upstream was hit (gate passed).
func patProxyFixture(t *testing.T, idp auth.InternalIdentityProvider) (http.Handler, *apitoken.TokenManager, *bool) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	backendReached := new(bool)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*backendReached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cacheManager, _ := cache.NewCacheManager("", "pat-proxy-test", nil)

	// TokenManager issuer MUST match the host issuer: ValidateToken enforces
	// IssuedBy(tm.issuer), and the resource URI the bridge expects is
	// issuerAddress()+basePath. Aligning them lets a resource-bound PAT validate.
	tm, err := apitoken.NewTokenManager(patProxyIssuer, apitoken.GenerateDevmodeKeyPair(), nil)
	require.NoError(t, err)

	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cacheManager, idp)
	require.NoError(t, err)

	fn := newReadyFunctionWithOAuth2(t, patProxyBasePath, []string{"functions:" + patProxyBasePath + ":read"})
	fn.Status.URL = upstream.URL

	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  &entitlementGateChecker{},
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{patProxyDomain}},
		},
		// oauth2ProtectedResources() enumerates over hh.functions; this function
		// must be present for the handler to detect itself as oauth2-protected.
		functions: []kdexv1alpha1.KDexFunction{fn},
		authConfig: &auth.Config{
			ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
			Audience:     patProxyHostAud,
			TokenManager: tm,
		},
		authExchanger: ex,
	}

	return hh.reverseProxyHandler(&fn, patProxyIssuer), tm, backendReached
}

// TestProxyPAT_BearerResourceBound covers Plan B Task 9: a PASETO PAT minted for
// the function's RESOURCE audience and presented as `Authorization: Bearer <pat>`
// is recognized and authenticated at the proxy gate with the resource audience,
// reaching the backend. A PAT minted for a DIFFERENT audience fails the
// resource-audience check and never reaches the backend.
func TestProxyPAT_BearerResourceBound(t *testing.T) {
	idp := stubInternalIdentityProvider{
		roles: []string{"mcp-role"},
		ents:  []string{"functions:" + patProxyBasePath + ":read"},
	}

	t.Run("resource-bound PAT reaches backend", func(t *testing.T) {
		handler, tm, backendReached := patProxyFixture(t, idp)
		pat, err := tm.MintStatelessKey(patProxyResource, "mcp-bob", "act", "scope:x", time.Hour)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", patProxyBasePath, nil)
		req.Header.Set("Authorization", "Bearer "+pat)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, *backendReached, "resource-bound Bearer PAT must reach the backend")
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("wrong-audience PAT does not reach backend", func(t *testing.T) {
		handler, tm, backendReached := patProxyFixture(t, idp)
		// Minted for a DIFFERENT resource (another function's audience).
		pat, err := tm.MintStatelessKey(patProxyIssuer+"/api/v1/other", "mcp-eve", "act", "scope:x", time.Hour)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", patProxyBasePath, nil)
		req.Header.Set("Authorization", "Bearer "+pat)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.False(t, *backendReached, "wrong-audience PAT must NOT reach the backend")
		// Task 10: the 401 + WWW-Authenticate challenge is now emitted for
		// oauth2-protected functions; assert exact status and header presence.
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"), "oauth2-protected gate must emit WWW-Authenticate challenge")
	})
}

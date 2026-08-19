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
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TestSetHostInstallsOAuth2ResourceMetadata is the wiring half of
// kdex-tech/host-manager#180.
//
// auth.Config.OAuth2ResourceMetadata is what lets WithAuthentication name the
// resource in its 401 challenge, and the middleware wraps the whole mux so it
// cannot work the mapping out for itself. SetHost is the one place that knows
// both halves — the host's functions and its auth config — so it must install
// the snapshot. Without this the unit-level challenge behaviour is real but
// permanently inert in production: every 401 would omit resource_metadata
// because the map is always nil.
//
// Driven through ServeHTTP rather than by reading the field, so the assertion
// is the response a stuck MCP client would actually receive.
func TestSetHostInstallsOAuth2ResourceMetadata(t *testing.T) {
	logf.SetLogger(logr.Discard())

	const domain = "dev.knowdrive.ai"
	const basePath = "/api/v1/mcp"
	issuer := "https://" + domain

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cacheManager, _ := cache.NewCacheManager("", "expired-bearer-wiring", nil)
	hh := NewHostHandler(nil, "rsi-dev", "dev", logr.Discard(), cacheManager)

	authConfig := &auth.Config{
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "wiring-kid", Private: signerKey},
		Audience:   issuer,
		Issuer:     issuer,
		CookieName: "auth_token",
	}

	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{
			BrandName: "KnowDrive",
			Routing:   kdexv1alpha1.Routing{Domains: []string{domain}},
		},
		&kdexv1alpha1.KDexObjectStatus{Conditions: []metav1.Condition{{
			Type:   string(kdexv1alpha1.ConditionTypeReady),
			Status: metav1.ConditionTrue,
		}}},
		nil, nil, nil, "", nil,
		[]kdexv1alpha1.KDexFunction{
			newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"}),
		},
		nil, authConfig, "https", nil, time.Now(),
	)

	expired := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice",
		"aud": issuer,
		"iss": issuer,
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})
	signed, err := expired.SignedString(priv)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", basePath, strings.NewReader("{}"))
	req.Host = domain
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()

	hh.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"),
		`resource_metadata="`+issuer+`/.well-known/oauth-protected-resource`+basePath+`"`,
		"SetHost must hand the oauth2-protected resource map to the auth config, "+
			"or the challenge can never name the resource")
}

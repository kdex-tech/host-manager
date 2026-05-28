/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mintScopeStubIdentityProvider struct{}

func (mintScopeStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (mintScopeStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return []string{"admin", "billing-write"}, []string{"pages:write", "billing:*"}, nil
}

func newMintScopeExchanger(t *testing.T) (*Exchanger, *keys.KeyPair) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:          "test-iss",
		Audience:        "test-aud",
		Signer:          *signer,
		ActivePair:      &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		RefreshTokenTTL: time.Hour,
		Clients:         map[string]AuthClient{"app": {ClientID: "app"}},
	}

	cm, err := cache.NewCacheManager("", "mint-scope-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, mintScopeStubIdentityProvider{})
	require.NoError(t, err)
	return ex, cfg.ActivePair
}

// decodeUnverified returns the JWT claims without verifying the signature.
// We use this in tests because we only care about which claims the
// signer placed into the token, not whether the signature is fresh.
func decodeUnverified(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	return claims
}

// TestMintTokensFromCode_StripsClaimsOutsideGrantedScope pins the fix
// for kdex-tech/host-manager#80. Pre-fix mintTokensFromCode set
// `roles` and `entitlements` on the signing context unconditionally,
// then filtered only the `scope` claim — the access-token JWT carried
// the full claims regardless of whether the client requested those
// scopes. mintTokensFromSubject (refresh path) already does the right
// thing; this aligns mintTokensFromCode.
func TestMintTokensFromCode_StripsClaimsOutsideGrantedScope(t *testing.T) {
	ex, _ := newMintScopeExchanger(t)

	t.Run("scope=openid email: roles/entitlements absent from access token", func(t *testing.T) {
		ts, err := ex.mintTokensFromCode(context.Background(), AuthorizationCodeClaims{
			Subject:    "alice",
			ClientID:   "app",
			Scope:      "openid email",
			AuthMethod: AuthMethodLocal,
		})
		require.NoError(t, err)
		require.NotEmpty(t, ts.AccessToken)

		claims := decodeUnverified(t, ts.AccessToken)

		scope, _ := claims["scope"].(string)
		assert.NotContains(t, strings.Fields(scope), "entitlements",
			"control: granted scope should not contain entitlements")
		assert.NotContains(t, strings.Fields(scope), "roles",
			"control: granted scope should not contain roles")

		_, hasRoles := claims["roles"]
		_, hasEnt := claims["entitlements"]
		assert.False(t, hasRoles,
			"roles claim must NOT be present when scope=openid email (#80)")
		assert.False(t, hasEnt,
			"entitlements claim must NOT be present when scope=openid email (#80)")
	})

	t.Run("scope=openid roles entitlements: both claims present", func(t *testing.T) {
		ts, err := ex.mintTokensFromCode(context.Background(), AuthorizationCodeClaims{
			Subject:    "alice",
			ClientID:   "app",
			Scope:      "openid roles entitlements",
			AuthMethod: AuthMethodLocal,
		})
		require.NoError(t, err)

		claims := decodeUnverified(t, ts.AccessToken)

		_, hasRoles := claims["roles"]
		_, hasEnt := claims["entitlements"]
		assert.True(t, hasRoles, "roles must be present when requested")
		assert.True(t, hasEnt, "entitlements must be present when requested")
	})
}

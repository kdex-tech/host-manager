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

// stubIdentityProvider is the minimum required to let mintTokensFromCode
// reach its return. The replay-protection logic runs BEFORE mint, so the
// success-path behaviour here is only exercised on the legitimate
// first-redemption.
type stubIdentityProvider struct{}

func (stubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (stubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newReplayTestExchanger(t *testing.T) *Exchanger {
	t.Helper()

	// Real signer so mintTokensFromCode can complete on the first
	// (legitimate) redemption.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	// 32 bytes of "random" for the JWE block key. The Exchanger
	// SHA-256s it before using as the A256GCM key, so any 32-byte
	// string is fine.
	cfg := Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs}, // IsM2MEnabled requires ActivePair
		Clients: map[string]AuthClient{
			"app": {
				ClientID:     "app",
				RedirectURIs: []string{"https://app.example.com/cb"},
			},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "auth-replay-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, stubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

// TestRedeemAuthorizationCode_IsSingleUse pins the fix for
// kdex-tech/host-manager#65. Pre-fix, the JWE auth code was stateless
// — RedeemAuthorizationCode decrypted, validated, and minted tokens
// without ever recording the code as consumed. Anyone who captured the
// code (server log, Referer leak, browser history) could replay it
// within the 10-minute Exp window and mint a parallel session that
// rotation never detects. RFC 6749 §10.5 explicitly forbids this.
//
// Post-fix, redemption is gated by a one-time-use cache (same shape as
// RedeemRefreshToken). The second redemption is rejected before mint.
func TestRedeemAuthorizationCode_IsSingleUse(t *testing.T) {
	ex := newReplayTestExchanger(t)
	ctx := context.Background()

	code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
		ClientID:    "app",
		RedirectURI: "https://app.example.com/cb",
		Subject:     "alice",
		Exp:         time.Now().Add(time.Minute).Unix(),
		Scope:       "openid",
	})
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// First redemption — must succeed.
	ts1, err1 := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
	require.NoError(t, err1, "first redemption must succeed (#65)")
	require.NotEmpty(t, ts1.AccessToken)

	// Second redemption of the SAME code — must fail with replay
	// detection. Pre-fix this returned a second TokenSet; the attacker
	// got a parallel session.
	_, err2 := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
	require.Error(t, err2, "second redemption of the same code MUST fail (#65, RFC 6749 §10.5)")
	assert.True(t,
		strings.Contains(strings.ToLower(err2.Error()), "consumed") ||
			strings.Contains(strings.ToLower(err2.Error()), "already used") ||
			strings.Contains(strings.ToLower(err2.Error()), "replay"),
		"second-redeem error should clearly signal replay; got: %q", err2.Error())
}

// TestCreateAuthorizationCode_DistinctJTIs pins the precondition for
// the replay defence: two codes minted with identical claims must have
// distinct JTIs, otherwise the cache key collides and consuming one
// invalidates the other.
func TestCreateAuthorizationCode_DistinctJTIs(t *testing.T) {
	ex := newReplayTestExchanger(t)
	ctx := context.Background()

	claims := AuthorizationCodeClaims{
		ClientID:    "app",
		RedirectURI: "https://app.example.com/cb",
		Subject:     "alice",
		Exp:         time.Now().Add(time.Minute).Unix(),
	}

	code1, err := ex.CreateAuthorizationCode(ctx, claims)
	require.NoError(t, err)
	code2, err := ex.CreateAuthorizationCode(ctx, claims)
	require.NoError(t, err)

	// Distinct JTIs → distinct JWE outputs (because the encrypted
	// payload differs).
	assert.NotEqual(t, code1, code2,
		"two codes with identical claims must encode distinct JTIs (#65) so consuming one doesn't invalidate the other")
}

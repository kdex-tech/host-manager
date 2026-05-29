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
	"crypto/sha256"
	"encoding/base64"
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

type pkceStubIdentityProvider struct{}

func (pkceStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (pkceStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newPKCETestExchanger(t *testing.T) *Exchanger {
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
		Clients:         map[string]AuthClient{"app": {ClientID: "app", RedirectURIs: []string{"https://app/cb"}}},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "pkce-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, pkceStubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

// TestRedeemAuthorizationCode_RejectsPlainAndEmptyPKCE pins the fix
// for kdex-tech/host-manager#96. Pre-fix RedeemAuthorizationCode
// accepted code_challenge_method=plain and "" (empty), making the
// verifier check a literal string compare against the unhashed
// challenge — defeating PKCE. The attacker initiates their own flow
// with plain/empty, intercepts the code, and exchanges it with any
// matching verifier.
//
// Post-fix only S256 is accepted; plain and empty are rejected with
// an explicit error.
func TestRedeemAuthorizationCode_RejectsPlainAndEmptyPKCE(t *testing.T) {
	ex := newPKCETestExchanger(t)
	ctx := context.Background()

	mintCode := func(t *testing.T, method, challenge string) string {
		t.Helper()
		code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
			Subject:             "alice",
			ClientID:            "app",
			RedirectURI:         "https://app/cb",
			Scope:               "openid",
			Exp:                 time.Now().Add(time.Minute).Unix(),
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
		})
		require.NoError(t, err)
		return code
	}

	t.Run("plain method is rejected (#96)", func(t *testing.T) {
		code := mintCode(t, "plain", "abc")
		_, err := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app/cb", "abc")
		require.Error(t, err, "code_challenge_method=plain must NOT be accepted (#96)")
		msg := strings.ToLower(err.Error())
		assert.True(t,
			strings.Contains(msg, "s256") || strings.Contains(msg, "plain") || strings.Contains(msg, "method"),
			"rejection should mention the method or S256 requirement; got %q", err.Error())
	})

	t.Run("empty method is rejected (#96)", func(t *testing.T) {
		code := mintCode(t, "", "abc")
		_, err := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app/cb", "abc")
		require.Error(t, err, "empty code_challenge_method must NOT be accepted (#96)")
	})

	t.Run("S256 with matching verifier succeeds (positive control)", func(t *testing.T) {
		verifier := "the-correct-verifier-value-with-enough-entropy"
		h := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])

		code := mintCode(t, "S256", challenge)
		ts, err := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app/cb", verifier)
		require.NoError(t, err)
		assert.NotEmpty(t, ts.AccessToken)
	})

	t.Run("S256 with wrong verifier is rejected", func(t *testing.T) {
		h := sha256.Sum256([]byte("real"))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])

		code := mintCode(t, "S256", challenge)
		_, err := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app/cb", "wrong")
		require.Error(t, err)
	})
}

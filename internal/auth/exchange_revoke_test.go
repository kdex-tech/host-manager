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

type revokeStubIdentityProvider struct{}

func (revokeStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (revokeStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newRevokeTestExchanger(t *testing.T) *Exchanger {
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

	cm, err := cache.NewCacheManager("", "revoke-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, revokeStubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

// TestRevokeRefreshToken_InvalidatesRedemption pins the fix for
// kdex-tech/host-manager#84. Pre-fix LogoutPost cleared the browser
// cookies but left the refresh-token entry in the server-side cache
// until natural TTL — a stolen `_refresh` cookie value survived
// logout and could be replayed for up to 12h.
//
// Post-fix Exchanger exposes RevokeRefreshToken which deletes the
// cache entry. A subsequent RedeemRefreshToken on the same tokenID
// fails with "not found or expired".
func TestRevokeRefreshToken_InvalidatesRedemption(t *testing.T) {
	ex := newRevokeTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	t.Run("revoke then redeem fails", func(t *testing.T) {
		require.NoError(t, ex.RevokeRefreshToken(ctx, tokenID),
			"RevokeRefreshToken must succeed on a known tokenID")

		_, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "not found",
			"a revoked refresh token must be rejected as not-found (#84)")
	})

	t.Run("revoke is idempotent (no error on unknown tokenID)", func(t *testing.T) {
		// Stolen-but-already-revoked, or never-existed, or expired —
		// the LogoutPost call site treats this as fire-and-forget
		// and we want it to silently succeed rather than fail loudly.
		assert.NoError(t, ex.RevokeRefreshToken(ctx, "no-such-token"),
			"RevokeRefreshToken on an unknown tokenID must not error")
	})
}

// TestRevokeRefreshToken_ClearsGraceRecords pins quad-findings item 7.
// Deleting the refresh token is no longer enough once the #169 grace window
// exists: a grace record is keyed by the CONSUMED token id, so it outlives
// the token whose revocation is supposed to end the session. Logout gained
// a replay window it did not have before, on the credentials of a session
// the user has explicitly ended.
func TestRevokeRefreshToken_ClearsGraceRecords(t *testing.T) {
	// The grace window must actually be on for this to mean anything, so
	// this uses the rotation fixture rather than newRevokeTestExchanger.
	t.Run("revoking the rotated successor kills its predecessor's replay", func(t *testing.T) {
		ex := newRotationTestExchanger(t)
		ctx := context.Background()

		t1, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: AuthMethodLocal,
			ClientID:   "app",
			Subject:    "alice",
			Scope:      "openid",
		})
		require.NoError(t, err)

		// T1 -> T2. The grace record now lives under T1; the cookie holds T2.
		winner, err := ex.RedeemRefreshToken(ctx, t1, "app")
		require.NoError(t, err)
		t2 := winner.RefreshToken
		require.NotEmpty(t, t2)

		// The user logs out. The cookie value is T2.
		require.NoError(t, ex.RevokeRefreshToken(ctx, t2))

		_, err = ex.RedeemRefreshToken(ctx, t2, "app")
		require.Error(t, err, "the revoked token itself must be dead")

		_, err = ex.RedeemRefreshToken(ctx, t1, "app")
		assert.Error(t, err,
			"presenting the PREDECESSOR after logout must not replay the winner's access and ID "+
				"tokens (quad-findings item 7): the grace record is keyed by the consumed token, "+
				"which revoking the successor alone never reaches")
	})

	t.Run("revoking a token that is itself already graced kills its replay", func(t *testing.T) {
		ex := newRotationTestExchanger(t)
		ctx := context.Background()

		t1, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: AuthMethodLocal,
			ClientID:   "app",
			Subject:    "alice",
			Scope:      "openid",
		})
		require.NoError(t, err)

		_, err = ex.RedeemRefreshToken(ctx, t1, "app")
		require.NoError(t, err)

		// A logout that races its own rotation still presents T1.
		require.NoError(t, ex.RevokeRefreshToken(ctx, t1))

		_, err = ex.RedeemRefreshToken(ctx, t1, "app")
		assert.Error(t, err,
			"revoking an already-consumed token must also drop its own grace record")
	})
}

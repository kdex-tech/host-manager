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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rotationStubIdentityProvider struct{}

func (rotationStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (rotationStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newRotationTestExchanger(t *testing.T) *Exchanger {
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
		Clients: map[string]AuthClient{
			"app": {ClientID: "app"},
		},
	}

	cm, err := cache.NewCacheManager("", "rotation-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, rotationStubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

// TestRedeemRefreshToken_ConcurrentRedemptionsHaveSingleWinner pins
// the fix for kdex-tech/host-manager#71. Pre-fix, the Get-then-Delete
// pattern in RedeemRefreshToken let two concurrent redemptions of the
// same refresh token both pass Get before either reached Delete: both
// minted parallel session lineages (same OriginalIssuedAt, same
// Subject), defeating the rotation-based theft-detection guarantee.
//
// Post-fix, GetAndDelete on cache.Cache produces exactly one winner.
func TestRedeemRefreshToken_ConcurrentRedemptionsHaveSingleWinner(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	// Mint one refresh token via the internal helper (avoids needing a
	// full auth-code flow to seed it).
	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	const goroutines = 32
	var winners atomic.Int32
	var notFound atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ts, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
			if err == nil && ts.AccessToken != "" {
				winners.Add(1)
				return
			}
			// Losers see "refresh token not found or expired" — the
			// atomic GetAndDelete observed the entry was already gone.
			notFound.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	assert.EqualValues(t, 1, winners.Load(),
		"exactly one of %d concurrent redemptions must succeed (#71); pre-fix the Get-then-Delete pattern let multiple win and minted parallel session lineages", goroutines)
	assert.EqualValues(t, goroutines-1, notFound.Load(),
		"every loser must be rejected as not-found (atomic GetAndDelete contract)")
}

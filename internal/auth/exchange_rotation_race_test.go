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

// newRotationTestExchanger builds the package's shared rotation fixture with
// the #169 grace window ON, so the concurrency tests exercise the replay
// path without wiring it up individually.
func newRotationTestExchanger(t *testing.T) *Exchanger {
	t.Helper()
	return newRotationTestExchangerWithGrace(t, 10*time.Second)
}

// newRotationTestExchangerWithGrace builds the same fixture with an explicit
// Config.RefreshGraceWindow, so a test can exercise the window THROUGH THE
// CONFIG PATH rather than by reaching into the built Exchanger's fields.
// That is what makes the `cfg.RefreshGraceWindow > 0` gate in NewExchanger
// (and its clamp) observable at all — see quad-findings items 4 and 10.
func newRotationTestExchangerWithGrace(t *testing.T, window time.Duration) *Exchanger {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:             "test-iss",
		Audience:           "test-aud",
		Signer:             *signer,
		ActivePair:         &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		RefreshTokenTTL:    time.Hour,
		RefreshGraceWindow: window,
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

// TestRedeemRefreshToken_StrictModeHasSingleWinner preserves the original
// kdex-tech/host-manager#71 assertion. Pre-#71, the Get-then-Delete pattern
// let two concurrent redemptions both pass Get before either reached
// Delete: both minted parallel session lineages, defeating rotation-based
// theft detection. The atomic GetAndDelete produces exactly one winner.
//
// With the #169 grace window DISABLED (0), this is still the observable
// behavior, which is why the grace window is configurable rather than
// unconditional.
//
// The window is disabled THROUGH THE CONFIG, not by assigning
// ex.refreshGraceCache = nil after construction. Quad-findings item 10: the
// hand-assignment left the design's claim that `RefreshGraceWindow: 0`
// restores single-winner rotation entirely unconstrained — the
// `cfg.RefreshGraceWindow > 0` gate in NewExchanger could have been
// inverted and every test still passed.
func TestRedeemRefreshToken_StrictModeHasSingleWinner(t *testing.T) {
	ex := newRotationTestExchangerWithGrace(t, 0)
	ctx := context.Background()

	require.Nil(t, ex.refreshGraceCache,
		"RefreshGraceWindow: 0 must leave the grace cache unwired (quad-findings item 10): "+
			"the strict-mode guarantee is a property of the config gate, not of a test fixture")
	require.Zero(t, ex.refreshGraceWindow,
		"RefreshGraceWindow: 0 must leave the window at zero")

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
			notFound.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	assert.EqualValues(t, 1, winners.Load(),
		"with the grace window off, exactly one of %d concurrent redemptions must succeed (#71)", goroutines)
	assert.EqualValues(t, goroutines-1, notFound.Load(),
		"every loser must be rejected as not-found (atomic GetAndDelete contract)")
}

// TestRedeemRefreshToken_ConcurrentRedemptionsShareOneRotation pins
// kdex-tech/host-manager#169. Real clients fire 4-5 refreshes within a few
// hundred milliseconds; strict rotation failed all but one, and combined
// with #168's missing invalid_grant signal that left clients unrecoverable.
//
// Every concurrent caller must now succeed with the IDENTICAL pair, and
// exactly one rotation must have occurred — that second assertion is what
// keeps #71 intact. Losers replay the winner's result; they mint nothing.
func TestRedeemRefreshToken_ConcurrentRedemptionsShareOneRotation(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	const goroutines = 32
	results := make([]TokenSet, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = ex.RedeemRefreshToken(ctx, tokenID, "app")
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d lost the rotation race (#169)", i)
		require.NotEmpty(t, results[i].AccessToken, "caller %d got an empty access token", i)
	}

	// Every caller holds the SAME rotated refresh token -> exactly one
	// rotation happened -> exactly one session lineage exists (#71 holds).
	want := results[0].RefreshToken
	require.NotEmpty(t, want)
	for i, got := range results {
		assert.Equal(t, want, got.RefreshToken,
			"caller %d received a different refresh token; that would mean a second lineage was minted (#71)", i)
	}

	// And that one rotated token is live, while the consumed one is not.
	_, found, _, err := ex.refreshTokenCache.Get(ctx, want)
	require.NoError(t, err)
	assert.True(t, found, "the single rotated refresh token must be live")

	_, found, _, err = ex.refreshTokenCache.Get(ctx, tokenID)
	require.NoError(t, err)
	assert.False(t, found, "the consumed refresh token must be gone")
}

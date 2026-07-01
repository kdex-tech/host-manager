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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCapUsesTestConfig builds a Config carrying MintTokenEnabled + a real
// in-memory MintCapCache, plus the ActivePair private key so the test can
// hand-sign capability tokens against the same audience/issuer the
// middleware validates against. Mirrors newAutoExtendTestSetup's shape.
func newCapUsesTestConfig(t *testing.T) (*Config, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	cm, err := cache.NewCacheManager("", "cap-uses-test", nil)
	require.NoError(t, err)

	cfg := &Config{
		Issuer:           "test-iss",
		Audience:         "test-aud",
		CookieName:       "auth_token",
		ActivePair:       &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		MintTokenEnabled: true,
		MintCapCache:     cm.GetCache("cap", cache.CacheOptions{Uncycled: true}),
	}

	return cfg, priv
}

// mintCapabilityTestToken hand-signs a host-audience JWT carrying the
// CapUsesClaim marker and the given jti, mirroring mint_token.go's shape
// closely enough to exercise the middleware's decrement path.
func mintCapabilityTestToken(t *testing.T, priv *ecdsa.PrivateKey, jti string, marker bool) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "alice",
		"iss": "test-iss",
		"aud": []string{"test-aud"},
		"jti": jti,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if marker {
		claims[CapUsesClaim] = true
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

// serveCapUses drives a single request bearing token through
// WithAuthentication and reports whether next was invoked plus the
// response.
func serveCapUses(cfg *Config, token string) (*httptest.ResponseRecorder, bool) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	handler := cfg.WithAuthentication(nil)(next)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, nextCalled
}

// TestWithAuthentication_BoundedUseDecrement pins Task 12 (#280): the
// inbound middleware must atomically decrement the jti-keyed "cap" counter
// provisioned at mint time for every request bearing a CapUsesClaim-marked
// token, and fail closed (401, next NOT called) when the counter is
// missing or exhausted. Ordinary tokens (no marker) are never gated.
func TestWithAuthentication_BoundedUseDecrement(t *testing.T) {
	cfg, priv := newCapUsesTestConfig(t)
	ctx := context.Background()

	// Seed a budget of 1 for jti "J1".
	require.NoError(t, cfg.MintCapCache.Set(ctx, "uses:J1", "1", cache.WithTTL(time.Hour)))
	token := mintCapabilityTestToken(t, priv, "J1", true)

	// 1st request: counter 1 -> 0, allowed.
	rec1, nextCalled1 := serveCapUses(cfg, token)
	assert.True(t, nextCalled1, "first request must be allowed (counter starts at 1)")
	assert.Equal(t, http.StatusOK, rec1.Code)

	// 2nd request: counter now 0 (exhausted), rejected fail-closed.
	rec2, nextCalled2 := serveCapUses(cfg, token)
	assert.False(t, nextCalled2, "second request must be rejected once the counter is exhausted")
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)

	// A token with a different jti whose counter was NEVER seeded is
	// rejected fail-closed on a missing counter.
	missingToken := mintCapabilityTestToken(t, priv, "J-missing", true)
	rec3, nextCalled3 := serveCapUses(cfg, missingToken)
	assert.False(t, nextCalled3, "a token whose counter was never seeded must be rejected (fail-closed)")
	assert.Equal(t, http.StatusUnauthorized, rec3.Code)

	// An ordinary token (no CapUsesClaim marker) passes through untouched,
	// even though its jti has no counter seeded — proves normal
	// session/FAT JWTs are not decrement-gated.
	normalToken := mintCapabilityTestToken(t, priv, "J-normal", false)
	rec4, nextCalled4 := serveCapUses(cfg, normalToken)
	assert.True(t, nextCalled4, "a token without the CapUsesClaim marker must never be decrement-gated")
	assert.Equal(t, http.StatusOK, rec4.Code)
}

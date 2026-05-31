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
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type autoExtendStubIdentityProvider struct{}

func (autoExtendStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (autoExtendStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// newAutoExtendTestSetup builds a Config + Exchanger sharing the same
// signer/keypair/issuer/audience, plus the keypair signer for hand-rolling
// expired access tokens. Mirrors newRotationTestExchanger's shape but
// exposes the bits the middleware test needs.
func newAutoExtendTestSetup(t *testing.T) (*Config, *Exchanger, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := &Config{
		Issuer:            "test-iss",
		Audience:          "test-aud",
		CookieName:        "auth_token",
		AutoExtendSession: true,
		ActivePair:        &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Signer:            *signer,
		RefreshTokenTTL:   time.Hour,
		Clients: map[string]AuthClient{
			"app": {ClientID: "app"},
		},
	}

	cm, err := cache.NewCacheManager("", "auto-extend-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), *cfg, cm, autoExtendStubIdentityProvider{})
	require.NoError(t, err)

	return cfg, ex, priv
}

// mintExpiredAccessToken hand-rolls a JWT with iat in the past and exp
// already crossed. Validates cleanly except for the exp check — exactly
// the input the middleware sees when a user's auth_token cookie has aged
// past the JWT TTL.
func mintExpiredAccessToken(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice",
		"iss": "test-iss",
		"aud": []string{"test-aud"},
		"iat": now.Add(-2 * time.Hour).Unix(),
		"exp": now.Add(-time.Hour).Unix(), // expired 1h ago
	})
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

// findCookieByName returns ALL Set-Cookie entries with the given name
// from the response. Critical for the post-fix assertion: pre-fix the
// response carried TWO Set-Cookie headers for auth_token — one with the
// freshly-minted value, then one with Max-Age:-1 clearing it. Browsers
// (and net/http.Response.Cookies) apply Set-Cookie in order, so the
// clear wins. We need to verify the CLEAR is gone, not just that some
// new cookie was set.
func findCookieByName(t *testing.T, rec *httptest.ResponseRecorder, name string) []*http.Cookie {
	t.Helper()
	var matches []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			matches = append(matches, c)
		}
	}
	return matches
}

// TestWithAuthentication_AutoExtend_ExpiredTokenWithValidRefreshContinues
// pins the fix for kdex-tech/host-manager#100. Pre-fix the middleware
// re-parsed the OLD `tokenString` after successfully redeeming the
// refresh token. That re-parse still failed on exp, the outer
// error-handler ran (clear both cookies with Max-Age:-1, redirect to /),
// and the user was effectively logged out at every JWT TTL boundary.
//
// Post-fix the re-parse uses `ts.AccessToken` (the freshly-minted token),
// which validates cleanly, the outer error-handler is skipped, and the
// request proceeds to the next handler with the new cookies set.
func TestWithAuthentication_AutoExtend_ExpiredTokenWithValidRefreshContinues(t *testing.T) {
	cfg, ex, priv := newAutoExtendTestSetup(t)
	ctx := context.Background()

	// Seed a refresh-token entry the middleware can redeem. ClientID is
	// EMPTY because the auto-extend cookie flow calls
	// RedeemRefreshToken(..., "") with no clientID — cookie-bound
	// sessions aren't OAuth-client-scoped — and RedeemRefreshToken
	// rejects with "not issued to this client" when the seeded ClientID
	// disagrees with the redemption arg.
	refreshID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// Build the request: cookie-bound expired auth_token + valid
	// refresh-token cookie. authSource detection requires the cookie
	// (not a Bearer header) to enter the auto-extend branch.
	expiredToken := mintExpiredAccessToken(t, priv)
	req := httptest.NewRequest("GET", "/-/state/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: expiredToken})
	req.AddCookie(&http.Cookie{Name: cfg.CookieName + "_refresh", Value: refreshID})

	var nextCalled bool
	var authedSubject string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if ac, ok := GetAuthContext(r.Context()); ok {
			if sub, _ := ac["sub"].(string); sub != "" {
				authedSubject = sub
			}
		}
	})

	handler := cfg.WithAuthentication(ex)(next)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Post-fix: request proceeds normally with the rotated identity.
	assert.True(t, nextCalled,
		"middleware MUST pass to next handler after successful refresh (#100); "+
			"pre-fix this returned a 303 with cleared cookies before calling next")
	assert.NotEqual(t, http.StatusSeeOther, rec.Code,
		"middleware MUST NOT redirect on successful refresh (#100)")
	assert.Equal(t, "alice", authedSubject,
		"authContext seen by next handler must reflect the refreshed token's sub claim")

	// Post-fix: the response carries exactly ONE Set-Cookie for auth_token
	// (the new value) and ZERO Set-Cookies that clear it (Max-Age:-1).
	// Pre-fix it carried two: the new value AND a clear, in that order,
	// so the clear won by last-write-wins.
	authCookies := findCookieByName(t, rec, cfg.CookieName)
	require.Len(t, authCookies, 1,
		"expected exactly one Set-Cookie: auth_token=… on the response (the rotated token), got %d", len(authCookies))
	assert.NotEmpty(t, authCookies[0].Value,
		"rotated auth_token must have a non-empty value")
	assert.NotEqual(t, -1, authCookies[0].MaxAge,
		"rotated auth_token MUST NOT carry Max-Age:-1 (#100 pre-fix bug)")

	refreshCookies := findCookieByName(t, rec, cfg.CookieName+"_refresh")
	require.Len(t, refreshCookies, 1,
		"expected exactly one Set-Cookie: auth_token_refresh=… on the response, got %d", len(refreshCookies))
	assert.NotEmpty(t, refreshCookies[0].Value,
		"rotated refresh token must have a non-empty value")
	assert.NotEqual(t, -1, refreshCookies[0].MaxAge,
		"rotated refresh token MUST NOT carry Max-Age:-1 (#100 pre-fix bug)")

	// The rotated tokens must validate cleanly on a follow-up request —
	// proves the refresh actually produced a working session rather than
	// some garbage placeholder.
	verified, err := jwt.ParseWithClaims(
		authCookies[0].Value,
		&AuthContext{},
		func(token *jwt.Token) (any, error) {
			return cfg.ActivePair.Private.Public(), nil
		},
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
	)
	require.NoError(t, err, "rotated auth_token must validate against the host's keys")
	require.True(t, verified.Valid, "rotated auth_token must be Valid")
}

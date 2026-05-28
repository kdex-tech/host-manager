/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintTokenAud is a test helper that builds a signer pinned to the
// supplied audience and mints a token. We need a fresh signer per
// audience because sign.Signer.Project AUTHORITATIVELY overrides the
// `aud` claim with the signer's configured audience (this is by
// design — see the comment block above sign.Signer.Project).
func mintTokenAud(t *testing.T, kp *keys.KeyPair, audience string) string {
	t.Helper()
	cs := crypto.Signer(kp.Private.(crypto.Signer))
	signer, err := sign.NewSigner(audience, time.Hour, "test-iss", &cs, kp.KeyId, nil)
	require.NoError(t, err)
	tok, err := signer.Sign(jwt.MapClaims{
		"sub": "alice",
	})
	require.NoError(t, err)
	return tok
}

// TestWithAuthentication_RejectsFATAudience pins the fix for
// kdex-tech/host-manager#86. Pre-fix the middleware accepted any
// token whose `aud` was in {c.Audience} ∪ c.FunctionURLs — so a FAT
// minted for a function (aud=fn.Status.URL) was accepted at the
// HOST. A function that logged or proxied its inbound Authorization
// header leaked a token replayable across the entire host surface.
//
// Post-fix the middleware accepts only c.Audience. FATs are
// validated by the function backend; the host doesn't trust them.
func TestWithAuthentication_RejectsFATAudience(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	kp := &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs}

	c := &Config{
		Audience:     "host-aud",
		Issuer:       "test-iss",
		CookieName:   "auth_token",
		ActivePair:   kp,
		FunctionURLs: []string{"https://fn-a.cluster.local"},
	}

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})
	handler := c.WithAuthentication(nil)(next)

	t.Run("FAT (aud=fn-URL) is rejected at the host", func(t *testing.T) {
		nextCalled = false
		fat := mintTokenAud(t, kp, "https://fn-a.cluster.local")

		req := httptest.NewRequest("GET", "/-/anything", nil)
		req.Header.Set("Authorization", "Bearer "+fat)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.False(t, nextCalled,
			"middleware MUST NOT call next handler for a FAT (aud=fn-URL) at the host (#86)")
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"middleware must reject the FAT with 401")
	})

	t.Run("host-aud token is accepted", func(t *testing.T) {
		nextCalled = false
		tok := mintTokenAud(t, kp, "host-aud")

		req := httptest.NewRequest("GET", "/-/anything", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled,
			"middleware MUST accept a token minted for the host's own audience")
	})
}

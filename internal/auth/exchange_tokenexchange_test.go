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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenExchangeStubIdentityProvider satisfies InternalIdentityProvider for
// these tests: it resolves a single known subject ("alice") to a fixed
// roles/entitlements pair, which is what proves ExchangeSubjectToken
// RE-RESOLVES entitlements rather than copying them from the subject_token.
type tokenExchangeStubIdentityProvider struct {
	subject      string
	roles        []string
	entitlements []string
}

func (s tokenExchangeStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}

func (s tokenExchangeStubIdentityProvider) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	if subject != s.subject {
		return nil, nil, nil
	}
	return s.roles, s.entitlements, nil
}

// newTokenExchangeExchanger builds a minimal Exchanger configured with the
// given signing key, key id and issuer, wired to an identity provider that
// resolves "alice" -> ["functions:/v1/internal:read"]. Mirrors the fixture
// shape in exchange_resource_test.go's newTestExchangerWithDCR, trimmed to
// what ExchangeSubjectToken needs (no OIDC, no DCR, no cache manager).
// Named distinctly from exchange_test.go's package-level newTestExchanger
// (different signature; that one drives ConfigBuilder + a generated key
// pair this suite can't sign a matching subject_token against).
func newTokenExchangeExchanger(t *testing.T, cs *crypto.Signer, kid, issuer string) *Exchanger {
	t.Helper()

	cfg := Config{
		Issuer:   issuer,
		Audience: issuer, // a real host sets Audience (= issuer); the FAT gate needs it
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     kid,
			Private:   *cs,
		},
		TokenTTL: time.Hour,
	}

	ex, err := NewExchanger(context.Background(), cfg, nil, tokenExchangeStubIdentityProvider{
		subject:      "alice",
		roles:        []string{"internal-reader"},
		entitlements: []string{"functions:/v1/internal:read"},
	}, nil)
	require.NoError(t, err)
	return ex
}

// parseClaims parses a JWT signed by cs's public key with no audience filter
// (ExchangeSubjectToken mints for an arbitrary target audience the test
// wants to inspect directly, not validate against).
func parseClaims(t *testing.T, token string, cs *crypto.Signer) jwt.MapClaims {
	t.Helper()

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return (*cs).Public(), nil
	})
	require.NoError(t, err)
	require.True(t, tok.Valid)
	return claims
}

func TestExchangeSubjectToken_MintsForTargetAudienceWithReResolvedEntitlements(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	// A FAT the handler would hold: aud = function A, sub = alice, iss = host.
	fatSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Hour, "https://host.example", &cs, "kid-1", nil)
	require.NoError(t, err)
	fat, err := fatSigner.Sign(jwt.MapClaims{"sub": "alice", "entitlements": []string{"stale:from:fat"}})
	require.NoError(t, err)

	e := newTokenExchangeExchanger(t, &cs, "kid-1", "https://host.example") // resolver returns ents ["functions:/v1/internal:read"] for "alice"

	ts, err := e.ExchangeSubjectToken(fat, "https://fn-b.ns.svc.cluster.local")
	require.NoError(t, err)
	require.Equal(t, "alice", ts.Subject)

	claims := parseClaims(t, ts.AccessToken, &cs) // helper: jwt.Parse with the public key, no aud filter
	assert.Equal(t, []any{"https://fn-b.ns.svc.cluster.local"}, claims["aud"])
	assert.Equal(t, "https://host.example", claims["iss"])
	// entitlements were RE-RESOLVED from roles, not copied from the FAT
	assert.Contains(t, claims["entitlements"], "functions:/v1/internal:read")
	assert.NotContains(t, claims["entitlements"], "stale:from:fat")
	// act records the calling function (the FAT's audience)
	act, _ := claims["act"].(map[string]any)
	assert.Equal(t, "https://fn-a.ns.svc.cluster.local", act["sub"])
}

func TestExchangeSubjectToken_RejectsForgedOrExpiredOrSubjectless(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	e := newTokenExchangeExchanger(t, &cs, "kid-1", "https://host.example")

	t.Run("forged: signed by a different key", func(t *testing.T) {
		otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		otherCS := crypto.Signer(otherPriv)

		forgedSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Hour, "https://host.example", &otherCS, "kid-1", nil)
		require.NoError(t, err)
		forged, err := forgedSigner.Sign(jwt.MapClaims{"sub": "alice"})
		require.NoError(t, err)

		ts, err := e.ExchangeSubjectToken(forged, "https://fn-b.ns.svc.cluster.local")
		require.Error(t, err)
		assert.Empty(t, ts.AccessToken)
	})

	t.Run("expired", func(t *testing.T) {
		expiredSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Nanosecond, "https://host.example", &cs, "kid-1", nil)
		require.NoError(t, err)
		expired, err := expiredSigner.Sign(jwt.MapClaims{"sub": "alice"})
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)

		ts, err := e.ExchangeSubjectToken(expired, "https://fn-b.ns.svc.cluster.local")
		require.Error(t, err)
		assert.Empty(t, ts.AccessToken)
	})

	t.Run("no sub in subject_token", func(t *testing.T) {
		// sign.Signer.Project refuses to mint a subject-less token (see
		// ErrSubjectlessCredential), so build the JWT directly rather than
		// through the signer to produce one for ExchangeSubjectToken to reject.
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": "https://host.example",
			"aud": []string{"https://fn-a.ns.svc.cluster.local"},
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		token.Header["kid"] = "kid-1"
		signed, err := token.SignedString(cs)
		require.NoError(t, err)

		ts, err := e.ExchangeSubjectToken(signed, "https://fn-b.ns.svc.cluster.local")
		require.Error(t, err)
		assert.Empty(t, ts.AccessToken)
	})
}

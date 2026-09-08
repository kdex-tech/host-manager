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
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// texKeyID and texIssuer are the fixed key id / issuer newTestOAuth2 wires
// its Exchanger with, so mintTestFAT and parseClaims can build/verify tokens
// against the exact same key without threading them through every call.
const (
	texKeyID  = "kid-1"
	texIssuer = "https://host.example"
)

// newTestOAuth2 builds an *OAuth2 wired to a real *Exchanger (a generated
// ECDSA key, a stub identity provider resolving "alice", and one
// ExchangeTargets entry mapping "/v1/internal" -> "https://fn-b.ns.svc.cluster.local").
// Config.Clients is deliberately left nil: TestTokenHandler_TokenExchange_NoClientRequired
// (and every other test here) relies on that to prove the grant is clientless
// -- if the clientless branch in OAuth2TokenHandler were ever moved after the
// client-authentication block, GetClient("") would fail against this fixture
// and these tests would start failing with invalid_client.
func newTestOAuth2(t *testing.T) *OAuth2 {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	cfg := Config{
		Issuer: texIssuer,
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     texKeyID,
			Private:   cs,
		},
		TokenTTL: time.Hour,
	}

	ex, err := NewExchanger(context.Background(), cfg, nil, tokenExchangeStubIdentityProvider{
		subject:      "alice",
		roles:        []string{"internal-reader"},
		entitlements: []string{"functions:/v1/internal:read"},
	})
	require.NoError(t, err)

	return &OAuth2{
		AuthConfig:        &ex.config,
		AuthExchanger:     ex,
		ResourceAudiences: map[string]bool{},
		ExchangeTargets: map[string]string{
			"/v1/internal": "https://fn-b.ns.svc.cluster.local",
		},
		AccessTokenTTL: time.Hour,
	}
}

// testKey returns the ActivePair private key newTestOAuth2 wired up, so a
// test can verify a minted access token's signature with parseClaims (from
// exchange_tokenexchange_test.go).
func (o *OAuth2) testKey(t *testing.T) *crypto.Signer {
	t.Helper()
	priv := o.AuthExchanger.config.ActivePair.Private
	return &priv
}

// mintTestFAT signs a FAT the way a KDexFunction's own audience-bound token
// would look: sub is the caller, aud is actorAud (the calling function),
// iss/key match o's fixture exactly so ExchangeSubjectToken verifies it.
func mintTestFAT(t *testing.T, o *OAuth2, subject, actorAud string) string {
	t.Helper()
	priv := o.AuthExchanger.config.ActivePair.Private
	signer, err := sign.NewSigner(actorAud, time.Hour, texIssuer, &priv, texKeyID, nil)
	require.NoError(t, err)
	fat, err := signer.Sign(jwt.MapClaims{"sub": subject})
	require.NoError(t, err)
	return fat
}

func TestTokenHandler_TokenExchange_InternalTarget(t *testing.T) {
	o := newTestOAuth2(t)
	fat := mintTestFAT(t, o, "alice", "https://fn-a.ns.svc.cluster.local")

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"/v1/internal"},
	}

	rec := postToken(t, o, form)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"RFC 6749 5.1 requires no-store on the token endpoint's success response")

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", resp.IssuedTokenType,
		"RFC 8693 3 requires issued_token_type on a token-exchange response")

	claims := parseClaims(t, resp.AccessToken, o.testKey(t))
	assert.Equal(t, []any{"https://fn-b.ns.svc.cluster.local"}, claims["aud"])
	assert.Equal(t, "alice", claims["sub"])
	// entitlements were re-resolved for the exchange, not copied off the FAT.
	assert.Contains(t, claims["entitlements"], "functions:/v1/internal:read")
	act, _ := claims["act"].(map[string]any)
	assert.Equal(t, "https://fn-a.ns.svc.cluster.local", act["sub"])
}

func TestTokenHandler_TokenExchange_UnknownResourceIsInvalidTarget(t *testing.T) {
	o := newTestOAuth2(t)
	fat := mintTestFAT(t, o, "alice", "https://fn-a.ns.svc.cluster.local")

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"/v1/does-not-exist"},
	}

	rec := postToken(t, o, form)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body := decodeOAuthError(t, rec)
	assert.Equal(t, "invalid_target", body["error"])
}

// TestTokenHandler_TokenExchange_NoClientRequired is the same happy path as
// TestTokenHandler_TokenExchange_InternalTarget but pins the clientless
// requirement explicitly: no client_id/client_secret field is present in the
// form at all, and o's Config.Clients is nil (see newTestOAuth2), so a 200
// here can only happen if the grant is handled before client resolution.
func TestTokenHandler_TokenExchange_NoClientRequired(t *testing.T) {
	o := newTestOAuth2(t)
	fat := mintTestFAT(t, o, "alice", "https://fn-a.ns.svc.cluster.local")

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"/v1/internal"},
	}
	require.Empty(t, form.Get("client_id"))
	require.Empty(t, form.Get("client_secret"))

	rec := postToken(t, o, form)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

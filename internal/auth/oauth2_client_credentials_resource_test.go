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

	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ccrClientID/ccrClientSecret identify the one confidential client
// newClientCredentialsResourceOAuth2 registers.
const (
	ccrClientID     = "svc-caller"
	ccrClientSecret = "s3cret"
)

// newClientCredentialsResourceOAuth2 builds an *OAuth2 wired to a real
// *Exchanger with:
//   - one confidential client (ccrClientID), AllowedGrantTypes
//     ["client_credentials"], AllowedResources ["/db/v1", "/unregistered/v1"]
//   - ExchangeTargets mapping "/db/v1" -> "aud-db" and "/other/v1" -> "aud-other"
//
// so the four cases in this file (allowed+registered, not-allowed,
// allowed-but-unregistered, no-resource) can each be driven by picking a
// different `resource` value off the same fixture. Mirrors newTestOAuth2
// (oauth2_tokenexchange_test.go) for the OAuth2/postToken wiring, and
// newClientCredsExchanger (oauth2_tokenerror_test.go) for the
// client_credentials Config/Signer shape -- LoginClient (the no-resource
// path) signs with e.config.Signer, which must be a real *sign.Signer, not
// the zero value newTestOAuth2 leaves it at.
func newClientCredentialsResourceOAuth2(t *testing.T) *OAuth2 {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	hostSigner, err := sign.NewSigner(texIssuer, time.Hour, texIssuer, &cs, texKeyID, nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:     texIssuer,
		Audience:   texIssuer,
		Signer:     *hostSigner,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: texKeyID, Private: cs},
		TokenTTL:   time.Hour,
		Clients: map[string]AuthClient{
			ccrClientID: {
				ClientID:          ccrClientID,
				ClientSecret:      ccrClientSecret,
				Public:            false,
				AllowedGrantTypes: []string{"client_credentials"},
				AllowedResources:  []string{"/db/v1", "/unregistered/v1"},
			},
		},
	}

	ex, err := NewExchanger(context.Background(), cfg, nil, clientCredsStubIdentityProvider{}, nil)
	require.NoError(t, err)

	return &OAuth2{
		AuthConfig:        &ex.config,
		AuthExchanger:     ex,
		ResourceAudiences: map[string]bool{},
		ExchangeTargets: map[string]string{
			"/db/v1":    "aud-db",
			"/other/v1": "aud-other",
		},
		AccessTokenTTL: time.Hour,
	}
}

// client_credentials + a resource both registered as an ExchangeTarget and
// present in the client's AllowedResources -> 200, token aud=target.
func TestTokenHandler_ClientCredentialsResource_MintsTargetAud(t *testing.T) {
	o := newClientCredentialsResourceOAuth2(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ccrClientID},
		"client_secret": {ccrClientSecret},
		"resource":      {"/db/v1"},
	}

	rec := postToken(t, o, form)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Empty(t, resp.IssuedTokenType, "client_credentials is not a token-exchange response")

	claims := parseClaims(t, resp.AccessToken, o.testKey(t))
	assert.Equal(t, []any{"aud-db"}, claims["aud"])
	assert.Equal(t, ccrClientID, claims["sub"])
}

// resource IS a registered ExchangeTarget but is NOT in this client's
// AllowedResources -> 400 invalid_target, not a silent host-aud fallback.
func TestTokenHandler_ClientCredentialsResource_NotAllowed_InvalidTarget(t *testing.T) {
	o := newClientCredentialsResourceOAuth2(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ccrClientID},
		"client_secret": {ccrClientSecret},
		"resource":      {"/other/v1"},
	}

	rec := postToken(t, o, form)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body := decodeOAuthError(t, rec)
	assert.Equal(t, "invalid_target", body["error"])
}

// resource IS in the client's AllowedResources but is NOT a registered
// ExchangeTarget -> 400 invalid_target.
func TestTokenHandler_ClientCredentialsResource_UnknownTarget_InvalidTarget(t *testing.T) {
	o := newClientCredentialsResourceOAuth2(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ccrClientID},
		"client_secret": {ccrClientSecret},
		"resource":      {"/unregistered/v1"},
	}

	rec := postToken(t, o, form)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body := decodeOAuthError(t, rec)
	assert.Equal(t, "invalid_target", body["error"])
}

// client_credentials with no `resource` at all -> unchanged host-aud token
// (regression pin for the pre-existing behavior).
func TestTokenHandler_ClientCredentials_NoResource_HostAud(t *testing.T) {
	o := newClientCredentialsResourceOAuth2(t)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {ccrClientID},
		"client_secret": {ccrClientSecret},
	}

	rec := postToken(t, o, form)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	claims := parseClaims(t, resp.AccessToken, o.testKey(t))
	assert.Equal(t, []any{texIssuer}, claims["aud"])
	assert.Equal(t, ccrClientID, claims["sub"])
}

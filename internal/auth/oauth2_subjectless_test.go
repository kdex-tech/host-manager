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
	"net/http/httptest"
	"net/url"
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

// subjectlessOAuth2 builds an /-/oauth/authorize + /-/oauth/token pair with one
// registered client. The internal identity provider is subjectlessStubProvider
// (internal/auth/subjectless_credential_test.go), so the `password` grant
// exercises a credential source that vouches without naming anybody.
func subjectlessOAuth2(t *testing.T) *OAuth2 {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Audience:   "test-aud",
		Issuer:     "test-iss",
		CookieName: "kdex-auth",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Clients: map[string]AuthClient{
			"client-1": {
				ClientID:     "client-1",
				ClientSecret: "test-secret",
				RedirectURIs: []string{"http://localhost/cb"},
			},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "oauth2-subjectless-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, subjectlessStubProvider{})
	require.NoError(t, err)

	return &OAuth2{AuthConfig: &cfg, AuthExchanger: ex}
}

// /-/oauth/authorize gated on the PRESENCE of an auth context and accepted
// GetSubject()'s ("", nil) for a missing `sub`, so a session naming nobody
// minted an authorization code with Subject: "" -- redeemable for a full JWT
// and a rotating refresh token. Same class as the mint/validation refusals,
// same ruling: refuse it, and say so in operator terms.
//
// 500, not a redirect and not a 4xx: the session was already accepted by the
// middleware, so an empty subject here is a server-side fault and nothing the
// caller does can change it.
func TestAuthorizeHandlerRefusesASubjectlessSession(t *testing.T) {
	for name, ac := range map[string]AuthContext{
		"no sub claim": {"aud": "test-aud"},
		"empty sub":    {"sub": ""},
	} {
		t.Run(name, func(t *testing.T) {
			o := subjectlessOAuth2(t)

			u, _ := url.Parse("/-/oauth/authorize")
			q := u.Query()
			q.Set("client_id", "client-1")
			q.Set("response_type", "code")
			q.Set("redirect_uri", "http://localhost/cb")
			u.RawQuery = q.Encode()

			req := httptest.NewRequest("GET", u.String(), nil)
			req = req.WithContext(SetAuthContext(req.Context(), ac))
			w := httptest.NewRecorder()

			o.AuthorizeHandler(w, req)

			assert.Equal(t, http.StatusInternalServerError, w.Code,
				"a session that names nobody must not mint an authorization code")
			assert.Empty(t, w.Header().Get("Location"),
				"no redirect: neither the callback (with a code) nor the login form")
		})
	}
}

// The still-valid row, so the refusal above is attributable to the subject
// alone: a session that DOES name somebody gets its code.
func TestAuthorizeHandlerStillIssuesACodeForANamedSubject(t *testing.T) {
	o := subjectlessOAuth2(t)

	u, _ := url.Parse("/-/oauth/authorize")
	q := u.Query()
	q.Set("client_id", "client-1")
	q.Set("response_type", "code")
	q.Set("redirect_uri", "http://localhost/cb")
	u.RawQuery = q.Encode()

	req := httptest.NewRequest("GET", u.String(), nil)
	req = req.WithContext(SetAuthContext(req.Context(), AuthContext(jwt.MapClaims{"sub": "alice"})))
	w := httptest.NewRecorder()

	o.AuthorizeHandler(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc, err := w.Result().Location()
	require.NoError(t, err)
	assert.NotEmpty(t, loc.Query().Get("code"))
}

// The token endpoint is the sibling with the same shape. Every grant arm
// returns a TokenSet whose Subject is the identity the tokens were minted for,
// and ts.Subject is what writeResourcePATResponse hands to MintResourcePAT --
// so an empty one would mint a PASETO PAT with `sub: ""`, a bearer credential
// naming nobody that the function proxy would bridge into an auth context.
//
// Driven through the `password` grant against a credential source that vouches
// without naming: RFC 6749 5.2 JSON, 500 server_error, no tokens.
func TestTokenEndpointRefusesAGrantThatResolvesNoSubject(t *testing.T) {
	o := subjectlessOAuth2(t)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "client-1")
	form.Set("client_secret", "test-secret")
	form.Set("username", "nobody@example.test")
	form.Set("password", "pw")

	req := httptest.NewRequest("POST", "/-/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	o.OAuth2TokenHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, errCodeServerError, body["error"],
		"a credential source that vouches without naming is a server fault, not a client error")
	assert.NotContains(t, body, "access_token")
}

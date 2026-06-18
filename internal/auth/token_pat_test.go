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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestExchangerWithTokenManager builds an *Exchanger whose
// config.TokenManager is a real apitoken.TokenManager with a loaded
// devmode key, mirroring apitoken's own tests.
func newTestExchangerWithTokenManager(t *testing.T) *Exchanger {
	t.Helper()
	cm, err := cache.NewCacheManager("", "test-host", nil)
	if err != nil {
		t.Fatalf("NewCacheManager: %v", err)
	}
	tm, err := apitoken.NewTokenManager(
		"test-issuer",
		apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}),
	)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	return &Exchanger{config: Config{TokenManager: tm}}
}

func TestMintResourcePATSetsAudience(t *testing.T) {
	e := newTestExchangerWithTokenManager(t)
	resource := "https://dev.knowdrive.ai/api/v1/mcp"
	pat, err := e.MintResourcePAT(resource, "alice@example.com", "functions:/api/v1/mcp:read", time.Hour)
	if err != nil {
		t.Fatalf("MintResourcePAT: %v", err)
	}
	// Validate with the resource as expected audience → must pass
	data, err := e.config.TokenManager.ValidateToken(context.Background(), pat, resource)
	if err != nil {
		t.Fatalf("ValidateToken(resource): %v", err)
	}
	if data.Subject != "alice@example.com" {
		t.Fatalf("sub = %q", data.Subject)
	}
	// Validate with a DIFFERENT audience → must fail (confused-deputy guard)
	if _, err := e.config.TokenManager.ValidateToken(context.Background(), pat, "https://other.example/x"); err == nil {
		t.Fatal("expected audience mismatch to fail validation")
	}
}

// TestOAuth2TokenHandlerMintsPATForResource proves the authorization_code
// grant returns an audience-bound PASETO PAT as the access_token when the
// request targets an oauth2-protected resource (resource in ResourceAudiences),
// and falls back to the standard JWT otherwise.
func TestOAuth2TokenHandlerMintsPATForResource(t *testing.T) {
	keyPairs := keys.GenerateECDSAKeyPair()
	signer, _ := sign.NewSigner("aud", time.Hour, "iss", &keyPairs.ActiveKey().Private, keyPairs.ActiveKey().KeyId, nil)

	cm, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	tm, err := apitoken.NewTokenManager(
		"test-issuer",
		apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}),
	)
	require.NoError(t, err)

	cfg := Config{
		ActivePair: keyPairs.ActiveKey(),
		KeyPairs:   keyPairs,
		Clients: map[string]AuthClient{
			"valid-client": {
				ClientID:     "valid-client",
				ClientSecret: "valid-secret",
				RedirectURIs: []string{"http://localhost/cb"},
			},
		},
		Signer:       *signer,
		TokenTTL:     time.Hour,
		TokenManager: tm,
	}

	sp := &mockScopeProvider{
		resolveIdentity: func(subject string, password string) (jwt.MapClaims, error) {
			return nil, fmt.Errorf("mock auth failed")
		},
		resolveRolesAndEntitlements: func(subject string) ([]string, []string, error) {
			return []string{"role1"}, []string{"entitlement1"}, nil
		},
	}
	ex, _ := NewExchanger(context.Background(), cfg, nil, sp)

	resource := "https://dev.knowdrive.ai/api/v1/mcp"

	newCode := func() string {
		code, _ := ex.CreateAuthorizationCode(context.Background(), AuthorizationCodeClaims{
			Subject:     "alice@example.com",
			ClientID:    "valid-client",
			Scope:       "openid profile",
			RedirectURI: "http://localhost/cb",
			AuthMethod:  "local",
			Exp:         time.Now().Add(time.Minute).Unix(),
		})
		return code
	}

	oauth2 := &OAuth2{
		AuthExchanger:     ex,
		ResourceAudiences: map[string]bool{resource: true},
		AccessTokenTTL:    time.Hour,
	}

	post := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		oauth2.OAuth2TokenHandler(w, req)
		return w
	}

	t.Run("matching resource yields a PAT access_token", func(t *testing.T) {
		w := post(url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"valid-client"},
			"client_secret": {"valid-secret"},
			"code":          {newCode()},
			"redirect_uri":  {"http://localhost/cb"},
			"resource":      {resource},
		})
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		accessToken, _ := resp["access_token"].(string)
		require.NotEmpty(t, accessToken)
		// The access_token must be the audience-bound PAT, not a JWT — it
		// validates against the resource audience.
		data, err := tm.ValidateToken(context.Background(), accessToken, resource)
		require.NoError(t, err, "access_token should be a PAT bound to the resource audience")
		assert.Equal(t, "alice@example.com", data.Subject)
		assert.Equal(t, "Bearer", resp["token_type"])
		// A resource PAT carries no id_token.
		assert.Empty(t, resp["id_token"])
	})

	t.Run("no resource falls back to standard JWT", func(t *testing.T) {
		w := post(url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"valid-client"},
			"client_secret": {"valid-secret"},
			"code":          {newCode()},
			"redirect_uri":  {"http://localhost/cb"},
		})
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		accessToken, _ := resp["access_token"].(string)
		require.NotEmpty(t, accessToken)
		// Standard JWT path: the access_token is NOT a resource PAT.
		_, err := tm.ValidateToken(context.Background(), accessToken, resource)
		assert.Error(t, err, "without a resource the access_token must be the standard JWT, not a PAT")
	})

	t.Run("unknown resource falls back to standard JWT", func(t *testing.T) {
		w := post(url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"valid-client"},
			"client_secret": {"valid-secret"},
			"code":          {newCode()},
			"redirect_uri":  {"http://localhost/cb"},
			"resource":      {"https://not-protected.example/x"},
		})
		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		// Standard JWT issued (id_token present for openid scope).
		assert.NotEmpty(t, resp["id_token"])
	})
}

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
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resourceStubIdentityProvider satisfies InternalIdentityProvider for these tests.
type resourceStubIdentityProvider struct{}

func (resourceStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (resourceStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// newTestExchangerWithDCR builds an Exchanger that has an empty static Clients
// map but a DCR store containing a pre-registered client. It returns both the
// exchanger and the registered DCR client id.
func newTestExchangerWithDCR(t *testing.T) (*Exchanger, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "dcr-test", &ttl)
	require.NoError(t, err)

	store := dcr.NewStore(cm, "test-iss", time.Hour, 100)
	ctx := context.Background()

	// Pre-register the client we want to look up. Register generates a
	// random client_id, so we register first and capture the id.
	registered, err := store.Register(ctx, dcr.Client{
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scope:        "openid email",
		ClientName:   "Test DCR App",
	})
	require.NoError(t, err)

	cfg := Config{
		Issuer:   "test-iss",
		Audience: "test-aud",
		Signer:   *signer,
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     "test-kid",
			Private:   cs,
		},
		Clients:  map[string]AuthClient{}, // empty static map — forces DCR fallback
		DCRStore: store,
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	ex, err := NewExchanger(ctx, cfg, cm, resourceStubIdentityProvider{})
	require.NoError(t, err)

	return ex, registered.ClientID
}

// decryptAuthCode decrypts a JWE authorization code using the exchanger's
// block key and returns the embedded AuthorizationCodeClaims.
func decryptAuthCode(t *testing.T, ex *Exchanger, code string) AuthorizationCodeClaims {
	t.Helper()
	key := sha256.Sum256([]byte(ex.config.OIDC.BlockKey))
	obj, err := jose.ParseEncrypted(code,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	require.NoError(t, err)
	decrypted, err := obj.Decrypt(key[:])
	require.NoError(t, err)
	var claims AuthorizationCodeClaims
	require.NoError(t, json.Unmarshal(decrypted, &claims))
	return claims
}

// TestGetClientFallsBackToDCRStore verifies that GetClient returns a
// synthesized AuthClient when the clientID is absent from the static Clients
// map but present in the DCR store.
func TestGetClientFallsBackToDCRStore(t *testing.T) {
	ex, clientID := newTestExchangerWithDCR(t)

	c, ok := ex.GetClient(clientID)
	if !ok {
		t.Fatal("expected DCR client resolved via fallback")
	}
	if !c.Public {
		t.Fatalf("DCR client must be public: %+v", c)
	}
	if !c.RequirePKCE {
		t.Fatalf("DCR client must require PKCE: %+v", c)
	}
	assert.Equal(t, clientID, c.ClientID)
	assert.Contains(t, c.RedirectURIs, "https://example.com/cb")
	assert.Contains(t, c.AllowedGrantTypes, "authorization_code")
	assert.Contains(t, c.AllowedScopes, "openid")
	assert.Contains(t, c.AllowedScopes, "email")
	assert.Equal(t, "Test DCR App", c.Name)
}

// TestGetClientStaticMapTakesPrecedence verifies that a client present in the
// static map is returned without touching the DCR store (static wins).
func TestGetClientStaticMapTakesPrecedence(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	ex.config.Clients["static_client"] = AuthClient{
		ClientID:     "static_client",
		Public:       false,
		RequirePKCE:  false,
		RedirectURIs: []string{"https://static.example.com/cb"},
		Name:         "Static",
	}
	c, ok := ex.GetClient("static_client")
	require.True(t, ok)
	assert.False(t, c.Public, "static client must not be overridden by DCR synthesized defaults")
}

// TestAuthorizationCodeCarriesResource mints an authorization code with a
// Resource claim and verifies the claim round-trips through
// CreateAuthorizationCode (the JWE is decrypted and the raw claims inspected).
func TestAuthorizationCodeCarriesResource(t *testing.T) {
	// Reuse the replay-test exchanger which has a static "app" client registered.
	ex := newReplayTestExchanger(t)
	ctx := context.Background()

	const wantResource = "https://api.example.com"

	code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
		ClientID:    "app",
		RedirectURI: "https://app.example.com/cb",
		Subject:     "bob",
		Exp:         time.Now().Add(time.Minute).Unix(),
		Scope:       "openid",
		Resource:    wantResource,
	})
	require.NoError(t, err)
	require.NotEmpty(t, code)

	// Decrypt and unmarshal the raw claims to verify Resource round-trips.
	claims := decryptAuthCode(t, ex, code)
	assert.Equal(t, wantResource, claims.Resource,
		"Resource must round-trip through CreateAuthorizationCode")
}

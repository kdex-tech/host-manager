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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	ex, err := NewExchanger(ctx, cfg, cm, resourceStubIdentityProvider{}, nil)
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

// registerStoredDCRClient writes a DCR record straight into the exchanger's
// store with the given grants, bypassing /-/oauth/register's filter. It stands
// in for a record persisted before that filter existed (pre-v0.5.1): the store
// is Uncycled and refreshes its TTL on every use, so such a record outlives
// the release that stopped issuing it for as long as someone keeps using it.
func registerStoredDCRClient(t *testing.T, ex *Exchanger, grants []string) string {
	t.Helper()
	c, err := ex.config.DCRStore.Register(context.Background(), dcr.Client{
		RedirectURIs: []string{"https://example.com/cb"},
		GrantTypes:   grants,
	})
	require.NoError(t, err)
	return c.ClientID
}

// A stored DCR record is not trusted for its grants: GetClient re-applies the
// DCR grant policy on read, so a record holding `password` (or
// client_credentials) can no longer use them. GHSA-hm9g-w2cw-j7gg.
func TestGetClientDCRDropsGrantsADCRClientMayNotHold(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClient(t, ex, []string{"password", "refresh_token", "client_credentials"})

	c, ok := ex.GetClient(id)
	require.True(t, ok)
	assert.Equal(t, []string{"refresh_token"}, c.AllowedGrantTypes)
}

// An empty AllowedGrantTypes means "every grant" at the token endpoint, so a
// stored record with no grant_types must not reach it as empty. It gets the
// default DCR pair, as a registration that omitted grant_types does.
func TestGetClientDCRWithNoStoredGrantsGetsTheDefaultPair(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClient(t, ex, nil)

	c, ok := ex.GetClient(id)
	require.True(t, ok)
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, c.AllowedGrantTypes)
}

// A stored record whose grants are all ones a DCR client may not hold has no
// usable grant left. It is not a client, rather than one with an empty (and so
// unrestricted) grant list.
func TestGetClientDCRWithOnlyDisallowedGrantsIsNotAClient(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClient(t, ex, []string{"password"})

	_, ok := ex.GetClient(id)
	assert.False(t, ok)
}

// The end-to-end shape of GHSA-hm9g-w2cw-j7gg: a DCR client registered with
// `password` before registration filtered grants is refused the password
// grant at /-/oauth/token.
func TestTokenEndpointRefusesThePasswordGrantToAStoredDCRClient(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClient(t, ex, []string{"password", "refresh_token"})
	o := &OAuth2{AuthConfig: &ex.config, AuthExchanger: ex}

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", id)
	form.Set("username", "alice")
	form.Set("password", "pw")
	req := httptest.NewRequest("POST", "/-/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	o.OAuth2TokenHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, errCodeUnauthorizedClient, body["error"])
	assert.NotContains(t, body, "access_token")
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

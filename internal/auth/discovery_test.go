package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryHandler(t *testing.T) {
	handler := DiscoveryHandler("http://example.com", "")
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var config OpenIDConfiguration
	err := json.Unmarshal(w.Body.Bytes(), &config)
	assert.NoError(t, err)

	assert.Contains(t, config.GrantTypesSupported, "client_credentials")
	assert.Contains(t, config.GrantTypesSupported, "password")
	assert.Equal(t, "http://example.com", config.Issuer)
}

// TestDiscoveryAdvertisesRefreshTokenGrant pins that the authorization-server
// metadata advertises the refresh_token grant. The token endpoint
// (OAuth2TokenHandler) handles grant_type=refresh_token and DCR registers MCP
// clients with the refresh_token grant, so a spec-compliant client that reads
// grant_types_supported to decide whether to attempt a refresh must see it
// here — otherwise it silently falls back to full re-auth on every expiry.
func TestDiscoveryAdvertisesRefreshTokenGrant(t *testing.T) {
	handler := DiscoveryHandler("http://example.com", "")
	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	var config OpenIDConfiguration
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &config))

	assert.Contains(t, config.GrantTypesSupported, "authorization_code")
	assert.Contains(t, config.GrantTypesSupported, "refresh_token",
		"AS metadata must advertise refresh_token: the token endpoint and DCR both support it")
}

func TestDiscoveryAdvertisesRegistrationAndPKCE(t *testing.T) {
	h := DiscoveryHandler("https://dev.knowdrive.ai", "https://dev.knowdrive.ai/-/oauth/register")
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	var cfg OpenIDConfiguration
	if err := json.Unmarshal(rr.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.RegistrationEndpoint != "https://dev.knowdrive.ai/-/oauth/register" {
		t.Fatalf("registration_endpoint = %q", cfg.RegistrationEndpoint)
	}
	if len(cfg.CodeChallengeMethodsSupported) != 1 || cfg.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", cfg.CodeChallengeMethodsSupported)
	}
}

func TestDiscoveryOmitsRegistrationWhenDisabled(t *testing.T) {
	h := DiscoveryHandler("https://dev.knowdrive.ai", "")
	req := httptest.NewRequest("GET", "/x", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if strings.Contains(rr.Body.String(), "registration_endpoint") {
		t.Fatal("registration_endpoint must be omitted when DCR disabled")
	}
}

package host

import (
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
)

// The login page links to /-/oauth/login, which binds the login to the
// browser (#234), never straight to the provider: a provider URL baked into a
// cacheable page cannot carry per-login state. prompt and login_hint from an
// authorize redirect ride along to the provider (#233).
func TestLoginOIDCExtra(t *testing.T) {
	cfg := &auth.Config{}
	cfg.OIDC.ProviderURL = "https://idp.example"
	cfg.OIDC.Name = "Example"
	hh := &HostHandler{authConfig: cfg}

	r := httptest.NewRequest("GET", "/-/login?return=%2Fdocs&prompt=select_account&login_hint=a%40b.c", nil)
	got := hh.loginOIDCExtra(r, "/docs")

	assert.Equal(t, map[string]any{
		"authCodeURL": "/-/oauth/login?login_hint=a%40b.c&prompt=select_account&return=%2Fdocs",
		"name":        "Example",
		"provider":    "https://idp.example",
	}, got)
}

func TestLoginOIDCExtra_NilWithoutOIDC(t *testing.T) {
	hh := &HostHandler{authConfig: &auth.Config{}}

	assert.Nil(t, hh.loginOIDCExtra(httptest.NewRequest("GET", "/-/login", nil), "/"))
}

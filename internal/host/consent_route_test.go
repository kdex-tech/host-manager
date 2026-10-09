package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeHandler_RegistersTheConsentRoute(t *testing.T) {
	hh := &HostHandler{log: logr.Discard(), scheme: "https", authConfig: &auth.Config{ActivePair: &keys.KeyPair{}}}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.authorizeHandler(mux, paths)

	_, p := mux.Handler(httptest.NewRequest(http.MethodPost, auth.OAuthConsentPath, nil))
	assert.Equal(t, "POST "+auth.OAuthConsentPath, p)
	assert.Contains(t, paths, auth.OAuthConsentPath, "documented in /-/openapi")

	off := http.NewServeMux()
	(&HostHandler{log: logr.Discard()}).authorizeHandler(off, map[string]ko.PathInfo{})
	_, p = off.Handler(httptest.NewRequest(http.MethodPost, auth.OAuthConsentPath, nil))
	assert.Empty(t, p, "not registered when auth is off")
}

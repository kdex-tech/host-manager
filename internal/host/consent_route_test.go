package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// The consent POST refuses with 403 (not same-origin, no browser session, a
// stale or foreign request) and answers 503 when the consent store is down;
// /-/openapi says so, and every shared response it points at is declared.
func TestAuthorizeHandler_DocumentsTheConsentRefusals(t *testing.T) {
	hh := &HostHandler{log: logr.Discard(), scheme: "https", authConfig: &auth.Config{ActivePair: &keys.KeyPair{}}}
	paths := map[string]ko.PathInfo{}
	hh.authorizeHandler(http.NewServeMux(), paths)

	doc := (&ko.Builder{TypesToInclude: []ko.PathType{ko.SystemPathType}}).
		BuildOpenAPI("https://dev.example", "test-host", paths, ko.Filter{})
	item := doc.Paths.Find(auth.OAuthConsentPath)
	require.NotNil(t, item)
	require.NotNil(t, item.Post)

	forbidden := item.Post.Responses.Status(http.StatusForbidden)
	require.NotNil(t, forbidden)
	assert.Equal(t, ko.RespRefForbidden, forbidden.Ref)
	unavailable := item.Post.Responses.Status(http.StatusServiceUnavailable)
	require.NotNil(t, unavailable, "a store outage answers 503")

	for status, ref := range item.Post.Responses.Map() {
		if ref.Ref == "" {
			continue
		}
		name := strings.TrimPrefix(ref.Ref, "#/components/responses/")
		assert.Contains(t, doc.Components.Responses, name, "%s: %s is declared", status, ref.Ref)
	}
}

package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestIsSystemPath documents the prefix contract used by the host.go
// ServeHTTP short-circuit to keep system endpoints serving JSON/etc. even
// when the host is in HostStatusInitializing. See kdex-tech/host-manager#33.
func TestIsSystemPath(t *testing.T) {
	cases := map[string]bool{
		"/":                                 false,
		"/app":                              false,
		"/app/":                             false,
		"/invitations/foo":                  false,
		"/.well-known/jwks.json":            true,
		"/.well-known/openid-configuration": true,
		"/.well-known/oauth-authorization-server": true,
		"/-/login":                  true,
		"/-/logout":                 true,
		"/-/openapi":                true,
		"/-/navigation/main/en-CA/": true,
		"/-/translation/en":         true,
		"/-/theme/main.css":         true,
		"/favicon.ico":              true,
	}
	for p, want := range cases {
		t.Run(p, func(t *testing.T) {
			assert.Equal(t, want, isSystemPath(p))
		})
	}
}

// TestServeHTTP_InitializingPreservesSystemPaths is the regression test for
// kdex-tech/host-manager#33. While a host is still initializing (no
// reconciled Status yet), root and page paths must serve the announcement
// utility page, but system paths must keep their normal handlers so
// downstream consumers (KDexFunctions fetching JWKS, etc.) keep getting
// well-formed responses.
func TestServeHTTP_InitializingPreservesSystemPaths(t *testing.T) {
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "test-host", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	// Register an announcement utility page so the page-path fallback has
	// content to render.
	hh.AddOrUpdateUtilityPage(page.PageHandler{
		Name: "announcement",
		UtilityPage: &kdexv1alpha1.KDexUtilityPageSpec{
			Type: kdexv1alpha1.AnnouncementUtilityPageType,
		},
		MainTemplate: "<html><body>ANNOUNCEMENT_CONTENT</body></html>",
	})

	// Bring up just enough state to ensure the mux is built, but DO NOT set
	// hh.status — that keeps GetStatus() at HostStatusInitializing.
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "Test"},
		nil, nil, nil, nil, "", nil, nil,
		nil, nil, "http", nil, time.Now(),
	)
	assert.Equal(t, HostStatusInitializing, hh.GetStatus(),
		"test setup expects Initializing — adjust if status semantics change")

	t.Run("GET / serves announcement HTML during init", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ANNOUNCEMENT_CONTENT")
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	})

	t.Run("GET /-/openapi does NOT serve HTML during init", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/-/openapi", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		// The openapi handler emits application/json. Before the #33 fix
		// this returned the announcement HTML body, breaking any client
		// that tried to parse the OpenAPI doc.
		assert.NotContains(t, w.Body.String(), "ANNOUNCEMENT_CONTENT",
			"system path must not be intercepted by the Initializing short-circuit")
	})

	t.Run("GET /favicon.ico does NOT serve HTML during init", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/favicon.ico", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		assert.NotContains(t, w.Body.String(), "ANNOUNCEMENT_CONTENT")
	})
}

// TestLoginHandler_CatchAllClientRoute verifies the catch-all subtree route
// that lets the login page host client-side routing between views. It is
// registered only when auth is enabled, alongside the exact /-/login route.
func TestLoginHandler_CatchAllClientRoute(t *testing.T) {
	newMuxFor := func(hh *HostHandler) *http.ServeMux {
		mux := http.NewServeMux()
		hh.loginHandler(mux, map[string]ko.PathInfo{})
		return mux
	}
	pattern := func(mux *http.ServeMux, target string) string {
		_, p := mux.Handler(httptest.NewRequest("GET", target, nil))
		return p
	}

	authOn := &HostHandler{
		log:        logr.Discard(),
		authConfig: &auth.Config{ActivePair: &keys.KeyPair{}},
	}
	muxOn := newMuxFor(authOn)

	t.Run("exact /-/login still routes to the login handler", func(t *testing.T) {
		assert.Equal(t, "GET /-/login", pattern(muxOn, "/-/login"))
	})
	t.Run("app-router sub-path routes to the catch-all", func(t *testing.T) {
		assert.Equal(t, "GET /-/login/{path...}", pattern(muxOn, "/-/login/-/main/login-app/forgot"))
	})
	t.Run("any sub-path routes to the catch-all", func(t *testing.T) {
		assert.Equal(t, "GET /-/login/{path...}", pattern(muxOn, "/-/login/anything"))
	})
	t.Run("auth disabled registers neither route", func(t *testing.T) {
		muxOff := newMuxFor(&HostHandler{log: logr.Discard()})
		assert.Equal(t, "", pattern(muxOff, "/-/login"))
		assert.Equal(t, "", pattern(muxOff, "/-/login/anything"))
	})
}

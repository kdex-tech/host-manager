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
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestPatternRegistered_ProbeURL verifies that patternRegistered correctly
// detects whether a Go-1.22 mux pattern is already attached to the mux,
// including wildcard segments like {l10n} and {param...}.
func TestPatternRegistered_ProbeURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /{l10n}/{$}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /app/{$}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /invitations/{$}", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /{l10n}/app/{$}", func(http.ResponseWriter, *http.Request) {})

	cases := []struct {
		pattern  string
		expected bool
	}{
		{"GET /{$}", true},
		{"GET /{l10n}/{$}", true},
		{"GET /app/{$}", true},
		{"GET /invitations/{$}", true},
		{"GET /{l10n}/app/{$}", true},

		{"GET /workbench/{$}", false},
		{"GET /{l10n}/workbench/{$}", false},
		{"POST /{$}", false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern, func(t *testing.T) {
			assert.Equal(t, tc.expected, patternRegistered(mux, tc.pattern))
		})
	}
}

// TestAddHandlerAndRegister_DuplicateRouteSkipsCleanly is the regression test
// for kdex-tech/host-manager#32. Two RebuildMux passes with the same KDexPages
// must not surface a "skipping" error, and all page basePaths must remain
// routable on the resulting mux. Before the fix, the second pass would relive
// the same "GET /{$}" panic-recover pattern observed in production logs.
func TestAddHandlerAndRegister_DuplicateRouteSkipsCleanly(t *testing.T) {
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "test-host", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	hh.Pages.Set(page.PageHandler{
		Name:         "page-home",
		MainTemplate: "<html><body>home</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Home",
			Paths: kdexv1alpha1.Paths{BasePath: "/"},
		},
	})
	hh.Pages.Set(page.PageHandler{
		Name:         "page-app",
		MainTemplate: "<html><body>app</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "App",
			Paths: kdexv1alpha1.Paths{BasePath: "/app"},
		},
	})
	hh.Pages.Set(page.PageHandler{
		Name:         "page-invitations",
		MainTemplate: "<html><body>invitations</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Invitations",
			Paths: kdexv1alpha1.Paths{BasePath: "/invitations"},
		},
	})

	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Force two more RebuildMux passes — this is the scenario that surfaces
	// the bug. Before the fix the second-and-third passes would relive the
	// same "GET /{$}" panic-recover pattern observed in production logs.
	hh.RebuildMux()
	hh.RebuildMux()

	// Inspect the mux directly to confirm each page's basePath resolves to
	// the page-specific finalPath rather than a more-general fallback.
	want := map[string]string{
		"/":             "GET /{$}",
		"/app/":         "GET /app/{$}",
		"/invitations/": "GET /invitations/{$}",
	}
	for probe, expected := range want {
		req := httptest.NewRequest("GET", probe, nil)
		_, pat := hh.Mux.Handler(req)
		assert.Equal(t, expected, pat, "probe %s should resolve to %s", probe, expected)
	}
}

// TestPatternRegistered_ToleratesEmptyBasePath documents that a PageHandler
// with a nil Page pointer (BasePath() == "") is skipped before any
// registration is attempted — preventing a `toFinalPath("")` -> "/{$}" race
// from clobbering the legitimate root-page route.
func TestAddHandlerAndRegister_EmptyBasePathSkipped(t *testing.T) {
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "test-host", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	mux := http.NewServeMux()
	registeredPaths := map[string]interface{}{}
	_ = registeredPaths // unused; keeping the signature shape clear

	// Construct a pageRender with an empty basePath via a nil Page pointer.
	pr := pageRender{ph: page.PageHandler{Name: "broken"}}

	// We want to verify the early-return guard fires without touching mux.
	err := hh.addHandlerAndRegister(mux, pr, nil, &hh.Translations)
	require.NoError(t, err)

	// Probe: no patterns should be attached to mux.
	req := httptest.NewRequest("GET", "/", nil)
	_, pat := mux.Handler(req)
	assert.Empty(t, pat, "no pattern should be registered for a page with empty basePath")
}

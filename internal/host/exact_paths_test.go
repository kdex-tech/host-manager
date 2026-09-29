/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"net/http"
	"testing"

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Tests for #220: pages register at their exact basePath; {$} only for
// slash-terminated basePaths; the legacy slash form 301s to the bare path.

func TestExactPaths_HTMLPage_BareServesSlashRedirects(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")
	mux := hh.currentMux(t)

	rr := doRequest(t, mux, "GET", "/pricing")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Empty(t, rr.Header().Get("Location"))

	rr = doRequest(t, mux, "GET", "/pricing/?a=1&b=2")
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/pricing?a=1&b=2", rr.Header().Get("Location"))
}

func TestExactPaths_Languages(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")
	mux := hh.currentMux(t)

	rr := doRequest(t, mux, "GET", "/fr/pricing")
	require.Equal(t, http.StatusOK, rr.Code)

	rr = doRequest(t, mux, "GET", "/fr/pricing/?x=1")
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/fr/pricing?x=1", rr.Header().Get("Location"))

	rr = doRequest(t, mux, "GET", "/en/pricing")
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/pricing", rr.Header().Get("Location"))

	// One hop: straight to the bare canonical path.
	rr = doRequest(t, mux, "GET", "/en/pricing/")
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/pricing", rr.Header().Get("Location"))
}

func TestExactPaths_LocalizedFalse_OnlyBareSlashRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing", withLocalizedFalse())
	mux := hh.currentMux(t)

	rr := doRequest(t, mux, "GET", "/pricing/")
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/pricing", rr.Header().Get("Location"))

	assertNoPattern(t, mux, "GET /fr/pricing")
	assertNoPattern(t, mux, "GET /fr/pricing/{$}")
	assertNoPattern(t, mux, "GET /en/pricing")
	assertNoPattern(t, mux, "GET /en/pricing/{$}")
}

func TestExactPaths_RootPage(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "home", "/")
	mux := hh.currentMux(t)

	require.Equal(t, http.StatusOK, doRequest(t, mux, "GET", "/").Code)
	require.Equal(t, http.StatusNotFound, doRequest(t, mux, "GET", "/nope").Code)
	assertMatches(t, mux, "GET", "/", "GET /{$}")
	assertMatches(t, mux, "GET", "/fr/", "GET /fr/{$}")
	// slash-terminated basePath: no legacy redirect routes at all.
	assertNoPattern(t, mux, "GET //{$}")
}

func TestExactPaths_AuthoredTrailingSlashBasePath(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "docs", "/docs/")
	mux := hh.currentMux(t)

	assertMatches(t, mux, "GET", "/docs/", "GET /docs/{$}")
	require.Equal(t, http.StatusOK, doRequest(t, mux, "GET", "/docs/").Code)
	require.Equal(t, http.StatusNotFound, doRequest(t, mux, "GET", "/docs/x").Code)

	// GET /docs is answered by ServeMux's own redirect to /docs/ (a 307; the mux
	// adds it for a registered "/docs/" pattern); acceptable.
	rr := doRequest(t, mux, "GET", "/docs")
	require.Equal(t, http.StatusTemporaryRedirect, rr.Code)
	require.Equal(t, "/docs/", rr.Header().Get("Location"))
}

func TestExactPaths_TextPage_NoLegacyRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "User-agent: *"))
	mux := hh.currentMux(t)

	require.Equal(t, http.StatusOK, doRequest(t, mux, "GET", "/robots.txt").Code)
	require.Equal(t, http.StatusNotFound, doRequest(t, mux, "GET", "/robots.txt/").Code)
	assertNoPattern(t, mux, "GET /robots.txt/{$}")
}

func TestExactPaths_LegacySlashRouteOwnedByPage(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	mux := http.NewServeMux()
	routes := newRouteRegistry()

	a := htmlPageForTest("a", "/pricing")
	b := htmlPageForTest("b", "/pricing/")

	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: a}, hh.registeredPaths, &hh.Translations, routes))
	owner, ok := routes.claimedBy("GET /pricing/{$}")
	require.True(t, ok)
	require.Equal(t, "a", owner.name)

	// A second page authored at "/pricing/" wants the same pattern: refused.
	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: b}, hh.registeredPaths, &hh.Translations, routes))
	require.NotEmpty(t, routes.collisions)
	require.Equal(t, "GET /pricing/{$}", routes.collisions[0].Pattern)
	require.Equal(t, "a", routes.collisions[0].WinnerName)
	require.Equal(t, "b", routes.collisions[0].LoserName)
}

func TestExactPaths_OpenAPI_NoLegacyRedirectEntries(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")

	for path, info := range hh.registeredPaths {
		for p := range info.API.Paths {
			require.NotContains(t, p, "{$}", "path %s: %s", path, p)
			require.False(t, len(p) > 1 && p[len(p)-1] == '/', "legacy slash path documented: %s", p)
		}
	}
	require.NotEmpty(t, hh.registeredPaths)
	ids := collectOperationIDs(t, hh)
	seen := map[string]bool{}
	for _, id := range ids {
		require.False(t, seen[id], "duplicate %q", id)
		seen[id] = true
	}
}

func htmlPageForTest(name, basePath string) page.PageHandler {
	return page.PageHandler{
		Name:         name,
		MainTemplate: "<html><body>" + name + "</body></html>",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: name, Paths: kdexv1alpha1.Paths{BasePath: basePath}},
	}
}

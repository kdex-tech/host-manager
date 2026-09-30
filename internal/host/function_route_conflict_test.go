/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// stubHandler answers 200 with body, standing in for a function proxy.
func stubHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
}

// catchAllPageMux is the page half of the Fix A repro: a page whose
// patternPath /x/{path...} registered "GET /x/{path...}", claimed on routes
// exactly as addHandlerAndRegister claims it.
func catchAllPageMux(pattern string) (*http.ServeMux, *routeRegistry) {
	mux := http.NewServeMux()
	routes := newRouteRegistry()
	mux.Handle(pattern, stubHandler("page"))
	routes.claim(pattern, routeOwner{name: "catchall", basePath: "/x"})
	return mux, routes
}

// A function whose routes conflict with a page's (neither ServeMux pattern
// is more specific: any-method /x/v1 vs GET /x/{path...}) is refused per
// pattern and recorded naming both sides -- never a panic out of the rebuild.
func TestRegisterFunctionRoutes_ConflictWithPageIsRefusedAndRecorded(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux, routes := catchAllPageMux("GET /x/{path...}")

	require.NotPanics(t, func() {
		hh.registerFunctionRoutes(mux, functionHandler{name: "api", basePath: "/x/v1", handler: stubHandler("fn")}, routes)
	})

	want := func(pattern string) RouteCollision {
		return RouteCollision{
			Pattern:            pattern,
			ConflictingPattern: "GET /x/{path...}",
			WinnerName:         "catchall",
			WinnerBasePath:     "/x",
			LoserName:          "KDexFunction/api",
			LoserBasePath:      "/x/v1",
		}
	}
	require.Equal(t, []RouteCollision{want("/x/v1"), want("/x/v1/")}, routes.collisions)

	// Pages keep precedence: the page still serves the whole subtree.
	for _, p := range []string{"/x/v1", "/x/v1/items", "/x/other"} {
		rr := doRequest(t, mux, "GET", p)
		assert.Equal(t, "page", rr.Body.String(), p)
	}
}

// Only the conflicting pattern of a function is refused: GET /x/{a} conflicts
// with /x/v1 but not with /x/v1/, so the prefix route still registers.
func TestRegisterFunctionRoutes_OnlyConflictingPatternIsRefused(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux, routes := catchAllPageMux("GET /x/{a}")

	hh.registerFunctionRoutes(mux, functionHandler{name: "api", basePath: "/x/v1", handler: stubHandler("fn")}, routes)

	require.Len(t, routes.collisions, 1)
	assert.Equal(t, "/x/v1", routes.collisions[0].Pattern)
	assert.Equal(t, "GET /x/{a}", routes.collisions[0].ConflictingPattern)
	assertMatches(t, mux, "GET", "/x/v1/items", "/x/v1/")
	assert.Equal(t, "fn", doRequest(t, mux, "GET", "/x/v1/items").Body.String())
	owner, ok := routes.claimedBy("/x/v1/")
	require.True(t, ok)
	assert.Equal(t, routeOwner{name: "KDexFunction/api", basePath: "/x/v1"}, owner)
}

// A conflict with a route the registry does not track (a built-in system
// route) is still refused and recorded, with an unknown winner.
func TestRegisterFunctionRoutes_ConflictWithUntrackedRoute(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := http.NewServeMux()
	mux.Handle("GET /x/{path...}", stubHandler("system"))
	routes := newRouteRegistry()

	require.NotPanics(t, func() {
		hh.registerFunctionRoutes(mux, functionHandler{name: "api", basePath: "/x/v1", handler: stubHandler("fn")}, routes)
	})
	require.Len(t, routes.collisions, 2)
	for _, c := range routes.collisions {
		assert.Empty(t, c.WinnerName)
		assert.Empty(t, c.ConflictingPattern)
		assert.Equal(t, "KDexFunction/api", c.LoserName)
	}
}

// Two functions on the same basePath: the second's identical patterns are
// refused (ServeMux panics on a duplicate too) and name the first function.
func TestRegisterFunctionRoutes_DuplicateFunctionBasePath(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := http.NewServeMux()
	routes := newRouteRegistry()

	hh.registerFunctionRoutes(mux, functionHandler{name: "a", basePath: "/api", handler: stubHandler("a")}, routes)
	require.NotPanics(t, func() {
		hh.registerFunctionRoutes(mux, functionHandler{name: "b", basePath: "/api", handler: stubHandler("b")}, routes)
	})

	require.Len(t, routes.collisions, 2)
	assert.Equal(t, RouteCollision{
		Pattern: "/api", ConflictingPattern: "/api",
		WinnerName: "KDexFunction/a", WinnerBasePath: "/api",
		LoserName: "KDexFunction/b", LoserBasePath: "/api",
	}, routes.collisions[0])
	assert.Equal(t, "a", doRequest(t, mux, "GET", "/api/x").Body.String())
}

// readyFunction is a Ready, non-internal KDexFunction proxied to upstream.
func readyFunction(name, basePath, upstream string) kdexv1alpha1.KDexFunction {
	return kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1ObjectMeta(name),
		Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: basePath}},
		Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady, URL: upstream},
	}
}

// The Fix A repro end to end: before the guard, the function loop in
// rebuildMuxSnapshot panicked on every rebuild, so RebuildMux never swapped
// in a new mux. Now the rebuild completes, the page still serves, a second
// non-conflicting function registers and serves in the same rebuild, and the
// refusal reaches hh.RouteCollisions() naming the function.
func TestRebuildMux_FunctionConflictWithPageDoesNotPanic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	t.Cleanup(upstream.Close)

	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.host.Routing.Domains = []string{"example.com"}
	hh.scheme = "https"
	hh.authConfig = challengeFixtureAuthConfig(t)

	catchAll := textPageForTest(t, "catchall", "/x", "txt", "page")
	catchAll.Page.PatternPath = "/x/{path...}"
	hh.Pages.Set(catchAll)
	hh.functions = []kdexv1alpha1.KDexFunction{
		readyFunction("api", "/x/v1", upstream.URL),
		readyFunction("other", "/y", upstream.URL),
	}

	require.NotPanics(t, hh.RebuildMux)

	mux := hh.Mux
	assert.Equal(t, "page", doRequest(t, mux, "GET", "/x/v1/items").Body.String())
	assert.Equal(t, "upstream", doRequest(t, mux, "GET", "/y/z").Body.String())

	collisions := hh.RouteCollisions()
	require.Len(t, collisions, 2, "%+v", collisions)
	for _, c := range collisions {
		assert.Equal(t, "KDexFunction/api", c.LoserName)
		assert.Equal(t, "catchall", c.WinnerName)
		assert.Equal(t, "GET /x/{path...}", c.ConflictingPattern)
	}
}

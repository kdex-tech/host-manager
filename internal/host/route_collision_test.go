/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestRouteRegistry_ClaimAndCollisionRecording is a direct unit test of the
// routeRegistry collision-collection API added by the route-collision fix,
// independent of addHandlerAndRegister/HTTP machinery entirely.
func TestRouteRegistry_ClaimAndCollisionRecording(t *testing.T) {
	rr := newRouteRegistry()

	// Fresh pattern: unclaimed.
	_, ok := rr.claimedBy("GET /fr/{$}")
	require.False(t, ok)

	home := routeOwner{name: "home", basePath: "/"}
	rr.claim("GET /fr/{$}", home)

	// Now claimed by home.
	owner, ok := rr.claimedBy("GET /fr/{$}")
	require.True(t, ok)
	require.Equal(t, home, owner)
	require.Empty(t, rr.collisions, "claiming an unowned pattern must not record a collision")

	// A different page wants the same pattern: the caller (mirroring
	// addHandlerAndRegister's registerIfNew) detects the existing owner
	// differs and records a collision instead of re-claiming.
	frPage := routeOwner{name: "fr-page", basePath: "/fr"}
	rr.recordCollision("GET /fr/{$}", home, frPage)

	require.Len(t, rr.collisions, 1)
	require.Equal(t, RouteCollision{
		Pattern:        "GET /fr/{$}",
		WinnerName:     "home",
		WinnerBasePath: "/",
		LoserName:      "fr-page",
		LoserBasePath:  "/fr",
	}, rr.collisions[0])

	// The pattern is still owned by the winner -- recordCollision does not
	// reassign ownership.
	owner, ok = rr.claimedBy("GET /fr/{$}")
	require.True(t, ok)
	require.Equal(t, home, owner)
}

// homeAndFrPages returns two independently-authored PageHandlers that
// reproduce the exact collision class from the bug report: with "en"
// (default) + "fr" supported, the home page (basePath "/") registers its
// French route as "GET /fr/{$}", and a page at basePath "/fr" wants that
// exact pattern for its own bare (default-language) route.
func homeAndFrPages() (page.PageHandler, page.PageHandler) {
	home := page.PageHandler{
		Name:         "home",
		MainTemplate: "<html><body>home</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Home",
			Paths: kdexv1alpha1.Paths{BasePath: "/"},
		},
	}
	frPage := page.PageHandler{
		Name:         "fr-page",
		MainTemplate: "<html><body>fr-page</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "FrPage",
			Paths: kdexv1alpha1.Paths{BasePath: "/fr"},
		},
	}
	return home, frPage
}

// TestAddHandlerAndRegister_CrossPageCollision_HomeFirst is the RED/GREEN pin
// for the route-collision fix's detection half: registering home (basePath
// "/") before the page at basePath "/fr" (both localized under en+fr) must
// NOT silently let the second registration's "GET /fr/{$}" clobber or get
// silently absorbed by the first's identical pattern -- it must be recorded
// as a genuine cross-page collision, refused (mux keeps exactly one live
// registration for the pattern, home's), and logged at Error (see the
// registerIfNew branch in handlers.go; not independently assertable here,
// asserted via the RouteCollision record instead per the task brief).
func TestAddHandlerAndRegister_CrossPageCollision_HomeFirst(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	home, frPage := homeAndFrPages()

	mux := http.NewServeMux()
	routes := newRouteRegistry()

	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: home}, hh.registeredPaths, &hh.Translations, routes))
	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: frPage}, hh.registeredPaths, &hh.Translations, routes))

	require.Len(t, routes.collisions, 1, "expected exactly one collision, got %+v", routes.collisions)
	require.Equal(t, RouteCollision{
		Pattern:        "GET /fr/{$}",
		WinnerName:     "home",
		WinnerBasePath: "/",
		LoserName:      "fr-page",
		LoserBasePath:  "/fr",
	}, routes.collisions[0])

	// The pattern is still live -- exactly one registration, not silently
	// dropped -- and owned by the winner.
	assertMatches(t, mux, "GET", "/fr/", "GET /fr/{$}")
	owner, ok := routes.claimedBy("GET /fr/{$}")
	require.True(t, ok)
	require.Equal(t, "home", owner.name)
}

// TestAddHandlerAndRegister_CrossPageCollision_FrPageFirst mirrors the above
// with registration order reversed, proving collision detection is symmetric
// -- whichever page registers first wins and the other is refused, rather
// than the detection logic silently favoring one page by identity.
func TestAddHandlerAndRegister_CrossPageCollision_FrPageFirst(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	home, frPage := homeAndFrPages()

	mux := http.NewServeMux()
	routes := newRouteRegistry()

	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: frPage}, hh.registeredPaths, &hh.Translations, routes))
	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: home}, hh.registeredPaths, &hh.Translations, routes))

	require.Len(t, routes.collisions, 1, "expected exactly one collision, got %+v", routes.collisions)
	collision := routes.collisions[0]
	require.Equal(t, "GET /fr/{$}", collision.Pattern)
	require.Equal(t, "fr-page", collision.WinnerName)
	require.Equal(t, "home", collision.LoserName)
}

// TestRouteCollision_DeterministicAcrossRebuilds is the RED/GREEN pin for the
// fix's determinism requirement: hh.Pages is a map (PageStore.List() ranges
// it), so before the basePath-sort in rebuildMuxSnapshot, repeated
// RebuildMux() calls could flip which of the two colliding pages won,
// because Go randomizes map iteration order per range. This drives the full
// SetHost -> Pages.Set -> RebuildMux pipeline (mirroring
// TestAddHandlerAndRegister_DuplicateRouteSkipsCleanly) many times and
// requires the SAME winner every time.
func TestRouteCollision_DeterministicAcrossRebuilds(t *testing.T) {
	log := logr.Discard()
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	home, frPage := homeAndFrPages()
	hh.Pages.Set(home)
	hh.Pages.Set(frPage)

	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Add "fr" support the same way KDexInternalTranslationReconciler would,
	// triggering another RebuildMux.
	hh.AddOrUpdateTranslation("tr-fr", &kdexv1alpha1.KDexTranslationSpec{
		Translations: []kdexv1alpha1.Translation{
			{Lang: "fr", KeysAndValues: map[string]string{"_": "_"}},
		},
	})

	var firstWinner, firstLoser string
	for i := range 20 {
		hh.RebuildMux()

		collisions := hh.RouteCollisions()
		require.Len(t, collisions, 1, "pass %d: expected exactly one collision, got %+v", i, collisions)
		require.Equal(t, "GET /fr/{$}", collisions[0].Pattern)

		if i == 0 {
			firstWinner, firstLoser = collisions[0].WinnerName, collisions[0].LoserName
			require.Contains(t, []string{"home", "fr-page"}, firstWinner)
			continue
		}

		require.Equal(t, firstWinner, collisions[0].WinnerName, "pass %d: winner flipped -- registration order is not deterministic", i)
		require.Equal(t, firstLoser, collisions[0].LoserName, "pass %d: loser flipped -- registration order is not deterministic", i)
	}

	// Sanity: the deterministic winner is basePath-sorted-first, i.e. home
	// ("/" sorts before "/fr").
	require.Equal(t, "home", firstWinner)
	require.Equal(t, "fr-page", firstLoser)
}

// TestRouteCollision_NoCollision_MultiPageMultiLanguage_Regression is the
// regression guard from the task brief: a multi-page, multi-language host
// with NO colliding basePaths must behave exactly as before the fix -- every
// route registers, and hh.RouteCollisions() stays empty (no spurious
// Degraded signal).
func TestRouteCollision_NoCollision_MultiPageMultiLanguage_Regression(t *testing.T) {
	log := logr.Discard()
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	hh.Pages.Set(page.PageHandler{
		Name:         "page-home",
		MainTemplate: "<html><body>home</body></html>",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "Home", Paths: kdexv1alpha1.Paths{BasePath: "/"}},
	})
	hh.Pages.Set(page.PageHandler{
		Name:         "page-app",
		MainTemplate: "<html><body>app</body></html>",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "App", Paths: kdexv1alpha1.Paths{BasePath: "/app"}},
	})
	hh.Pages.Set(page.PageHandler{
		Name:         "page-invitations",
		MainTemplate: "<html><body>invitations</body></html>",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "Invitations", Paths: kdexv1alpha1.Paths{BasePath: "/invitations"}},
	})

	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)
	hh.AddOrUpdateTranslation("tr-fr", &kdexv1alpha1.KDexTranslationSpec{
		Translations: []kdexv1alpha1.Translation{
			{Lang: "fr", KeysAndValues: map[string]string{"_": "_"}},
		},
	})

	for i := range 5 {
		hh.RebuildMux()
		require.Empty(t, hh.RouteCollisions(), "pass %d: no-collision host must never report a collision", i)
	}

	mux := hh.Mux
	want := map[string]string{
		"/":                "GET /{$}",
		"/app/":            "GET /app/{$}",
		"/invitations/":    "GET /invitations/{$}",
		"/fr/":             "GET /fr/{$}",
		"/fr/app/":         "GET /fr/app/{$}",
		"/fr/invitations/": "GET /fr/invitations/{$}",
	}
	for probe, expected := range want {
		assertMatches(t, mux, "GET", probe, expected)
	}
}

// TestRouteCollision_SingleLanguageHost_NeverCollides is the RED/GREEN pin
// for the task brief's single-language guard: a host with only the default
// language has no prefixed routes at all, so a page at basePath "/fr" is
// just an ordinary page -- there is no wildcard-vs-literal collision class
// possible, and it must register and serve normally with zero collisions.
func TestRouteCollision_SingleLanguageHost_NeverCollides(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	home, frPage := homeAndFrPages()

	mux := http.NewServeMux()
	routes := newRouteRegistry()

	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: home}, hh.registeredPaths, &hh.Translations, routes))
	require.NoError(t, hh.addHandlerAndRegister(mux, pageRender{ph: frPage}, hh.registeredPaths, &hh.Translations, routes))

	require.Empty(t, routes.collisions)
	assertMatches(t, mux, "GET", "/", "GET /{$}")
	assertMatches(t, mux, "GET", "/fr/", "GET /fr/{$}")
}

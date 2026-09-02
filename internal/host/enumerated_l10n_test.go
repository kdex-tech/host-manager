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
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// newTestHostHandler builds a minimal HostHandler with the given default
// language and the full set of supported languages (including the default),
// wired up with real Translations so hh.Translations.Languages() reflects
// them. It does not go through SetHost/RebuildMux — callers exercise
// registration directly via registerPageForTest.
func newTestHostHandler(t *testing.T, defaultLang string, langs []string) *HostHandler {
	t.Helper()

	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.defaultLanguage = defaultLang

	translationResources := map[string]kdexv1alpha1.KDexTranslationSpec{}
	for _, lang := range langs {
		if lang == defaultLang {
			continue
		}
		translationResources["tr-"+lang] = kdexv1alpha1.KDexTranslationSpec{
			Translations: []kdexv1alpha1.Translation{
				{Lang: lang, KeysAndValues: map[string]string{"_": "_"}},
			},
		}
	}

	translations, err := NewTranslations(defaultLang, translationResources)
	require.NoError(t, err)
	hh.Translations = *translations

	return hh
}

// registerPageForTest builds a minimal page.PageHandler for name/basePath and
// runs it through addHandlerAndRegister against a fresh mux, stashing the
// result on hh.Mux for currentMux to return.
func (hh *HostHandler) registerPageForTest(t *testing.T, name string, basePath string) {
	t.Helper()

	ph := page.PageHandler{
		Name:         name,
		MainTemplate: "<html><body>" + name + "</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: name,
			Paths: kdexv1alpha1.Paths{BasePath: basePath},
		},
	}

	mux := http.NewServeMux()
	registeredPaths := map[string]ko.PathInfo{}
	err := hh.addHandlerAndRegister(mux, pageRender{ph: ph}, registeredPaths, &hh.Translations)
	require.NoError(t, err)

	hh.Mux = mux
}

// currentMux returns the mux most recently built by registerPageForTest.
func (hh *HostHandler) currentMux(t *testing.T) *http.ServeMux {
	t.Helper()
	require.NotNil(t, hh.Mux, "no mux registered yet; call registerPageForTest first")
	return hh.Mux
}

// assertMatches asserts that method+path resolves on mux to exactly pattern.
func assertMatches(t *testing.T, mux *http.ServeMux, method string, path string, pattern string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	_, pat := mux.Handler(req)
	assert.Equal(t, pattern, pat, "expected %s %s to match %q", method, path, pattern)
}

// assertNoPattern asserts that pattern is not registered on mux at all.
func assertNoPattern(t *testing.T, mux *http.ServeMux, pattern string) {
	t.Helper()
	assert.False(t, patternRegistered(mux, pattern), "expected %q to NOT be registered", pattern)
}

// assertNotMatched asserts that method+path resolves to no registered
// pattern on mux (i.e. it falls through to the mux's not-found handling).
func assertNotMatched(t *testing.T, mux *http.ServeMux, method string, path string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	_, pat := mux.Handler(req)
	assert.Empty(t, pat, "expected %s %s to not match any registered pattern, got %q", method, path, pat)
}

// TestEnumeratedPrefixes_RegisterPerLanguage is the RED/GREEN pin for task
// 2.1: a KDexPage must register one literal prefix per supported
// non-default language plus a bare default route -- never the /{l10n}
// wildcard, which matches ANY first path segment (the root-namespace bug
// this task removes).
func TestEnumeratedPrefixes_RegisterPerLanguage(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")
	mux := hh.currentMux(t)

	assertMatches(t, mux, "GET", "/pricing/", "GET /pricing/{$}")       // bare = default
	assertMatches(t, mux, "GET", "/fr/pricing/", "GET /fr/pricing/{$}") // non-default prefix
	assertNoPattern(t, mux, "GET /{l10n}/pricing/{$}")                  // wildcard gone
	// unknown root falls through — no page/wildcard swallows it
	assertNotMatched(t, mux, "GET", "/robots.txt")
}

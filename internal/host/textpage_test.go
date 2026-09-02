/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"testing"

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// textPageForTest builds a minimal page.PageHandler for a text-mime KDexPage
// -- MimeType + Body set, no archetype/header/footer/navigation content --
// the shape L10nRenderText renders.
func textPageForTest(t *testing.T, name string, basePath string, mime string, body string) page.PageHandler {
	t.Helper()

	return page.PageHandler{
		Name: name,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label:    name,
			Paths:    kdexv1alpha1.Paths{BasePath: basePath},
			MimeType: mime,
			Body:     body,
		},
	}
}

// TestContentTypeFor is the RED/GREEN pin for task 3.1 step 1: contentTypeFor
// must map each spec.mimeType enum value to its Content-Type per the task
// brief's table.
func TestContentTypeFor(t *testing.T) {
	cases := map[string]string{
		"txt":      "text/plain; charset=utf-8",
		"json":     "application/json",
		"yaml":     "application/yaml",
		"markdown": "text/markdown; charset=utf-8",
		"xml":      "application/xml",
	}
	for mime, want := range cases {
		require.Equal(t, want, contentTypeFor(mime), mime)
	}
}

// TestL10nRenderText_TranslatesAndOmitsChrome is the RED/GREEN pin for task
// 3.1 step 5: L10nRenderText must render ph.Page.Body through the SAME
// [[ ]]-delimited template + l10n translation FuncMap that L10nRender uses
// (render.Renderer.RenderOne, via render.go's `funcs["l10n"]` -- NOT the
// brief's illustrative `t`), but produce ONLY the body -- no
// archetype/header/footer/navigation chrome wrapped around it.
func TestL10nRenderText_TranslatesAndOmitsChrome(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})

	// newTestHostHandler only seeds non-default-language translations
	// (see its doc comment), so build our own catalog with an "en" value
	// for "tagline" and swap it onto hh.Translations.
	translations, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"tr-en": {
			Translations: []kdexv1alpha1.Translation{
				{Lang: "en", KeysAndValues: map[string]string{"tagline": "the knowledge engine"}},
			},
		},
	})
	require.NoError(t, err)
	hh.Translations = *translations

	ph := textPageForTest(t, "llms", "/llms.txt", "txt",
		`KnowDrive — [[ l10n "tagline" ]]`) // body uses the real l10n function name + [[ ]] delims

	out, err := hh.L10nRenderText(ph, language.Make("en"), &hh.Translations)
	require.NoError(t, err)
	require.Equal(t, "KnowDrive — the knowledge engine", out)
	require.NotContains(t, out, "<html", "text render must not wrap in archetype HTML")
}

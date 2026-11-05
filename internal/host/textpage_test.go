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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/render"
)

// withText sets MimeType and Body on the spec built by registerPageForTest,
// exercising a text-mime KDexPage (task 3.2) the same way withLocalizedFalse
// exercises Localized. Missing from enumerated_l10n_test.go's helper set
// until now -- added here since it is textpage-specific.
func withText(mime string, body string) pageSpecOption {
	return func(spec *kdexv1alpha1.KDexPageSpec) {
		spec.MimeType = mime
		spec.Body = body
	}
}

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
	}, nil)
	require.NoError(t, err)
	hh.Translations = *translations

	ph := textPageForTest(t, "llms", "/llms.txt", "txt",
		`KnowDrive — [[ l10n "tagline" ]]`) // body uses the real l10n function name + [[ ]] delims

	out, err := hh.L10nRenderText(ph, language.Make("en"), &hh.Translations)
	require.NoError(t, err)
	require.Equal(t, "KnowDrive — the knowledge engine", out)
	require.NotContains(t, out, "<html", "text render must not wrap in archetype HTML")
}

// TestL10nRenderText_DoesNotEscapeHTMLSpecialChars is the RED/GREEN pin for
// fix I2: L10nRenderText must render ph.Page.Body through
// render.Renderer.RenderOneText (text/template), NOT RenderOne
// (html/template), so an interpolated [[ l10n "key" ]] value containing
// HTML-special characters (&, <, >, ") is served VERBATIM in text/plain,
// json, and markdown output instead of HTML-entity-escaped.
func TestL10nRenderText_DoesNotEscapeHTMLSpecialChars(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})

	translations, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"tr-en": {
			Translations: []kdexv1alpha1.Translation{
				{Lang: "en", KeysAndValues: map[string]string{"org": `R&D <core> "x"`}},
			},
		},
	}, nil)
	require.NoError(t, err)
	hh.Translations = *translations

	ph := textPageForTest(t, "llms", "/llms.txt", "txt",
		`org: [[ l10n "org" ]]`)

	out, err := hh.L10nRenderText(ph, language.Make("en"), &hh.Translations)
	require.NoError(t, err)
	require.Equal(t, `org: R&D <core> "x"`, out)
	require.NotContains(t, out, "&amp;")
	require.NotContains(t, out, "&lt;")
	require.NotContains(t, out, "&gt;")
	require.NotContains(t, out, "&#34;")
}

// TestTextPage_ExactPathNoRedirect is the RED/GREEN pin for task 3.2: a
// text-mime KDexPage must register at its EXACT basePath -- no
// toFinalPath trailing-slash + {$} anchor -- so GET /robots.txt serves
// directly instead of 307-redirecting to /robots.txt/.
func TestTextPage_ExactPathNoRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "ok"), withLocalizedFalse())
	rr := doRequest(t, hh.currentMux(t), "GET", "/robots.txt")
	require.Equal(t, http.StatusOK, rr.Code) // NOT 307
	require.Empty(t, rr.Header().Get("Location"))
}

// TestTextPage_ServesBodyWithContentType is the deferred end-to-end pin from
// task 3.1: with exact-path registration (task 3.2) landed, GET /robots.txt
// serves the rendered body with the mapped Content-Type.
func TestTextPage_ServesBodyWithContentType(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "ok"), withLocalizedFalse())
	rr := doRequest(t, hh.currentMux(t), "GET", "/robots.txt")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
	require.Equal(t, "ok", rr.Body.String())
}

// TestTextPage_NoSniffHeader is the RED/GREEN pin for Fix 2 (security R1):
// serveText serves un-escaped operator-authored content at canonical URLs
// (e.g. /llms.txt) but, unlike serveRendered's HTML pages which browsers
// treat as opaque, a text-mime response is a MIME-sniffing target -- so it
// must carry X-Content-Type-Options: nosniff to stop a browser from
// second-guessing the declared Content-Type.
func TestTextPage_NoSniffHeader(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "ok"), withLocalizedFalse())
	rr := doRequest(t, hh.currentMux(t), "GET", "/robots.txt")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
}

// sitemapBody is the sitemap template documented in kdex-main-site's Page
// Operating Modes page (Text mode), verbatim: a recursive walk of .PageMap
// via define/template that drops entries tagged nav-surrogate or
// no-navigation. Keep the two in step.
const sitemapBody = `[[- define "urls" ]][[ range $p := . ]]
  [[- $skip := false ]][[ range $t := $p.Tags ]][[ if or (eq $t.Name "nav-surrogate") (eq $t.Name "no-navigation") ]][[ $skip = true ]][[ end ]][[ end ]]
  [[- if not $skip ]]<url><loc>https://example.com[[ $p.Href ]]</loc></url>[[ end ]]
  [[- if $p.Children ]][[ template "urls" $p.Children ]][[ end ]]
[[- end ]][[ end -]]
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">[[ template "urls" .PageMap ]]</urlset>
`

// A text page's .PageMap is the host's page tree built under the ANONYMOUS
// scope, whoever asks: a sitemap lists what an anonymous crawler can reach,
// and the text-page cache key (page + language) stays correct for every
// caller. The entitled caller asks first, so a per-caller tree would be the
// one cached and then served to the anonymous caller. See #283.
func TestTextPage_PageMapIsAnonymousScopedTree(t *testing.T) {
	// Anonymous callers may read pages, as on a real public host; /admin
	// additionally requires the "admin" entitlement.
	checker := auth.NewAuthorizationChecker([]string{"pages::read"}, logr.Discard())

	admin := newPage("admin", "Admin", "/admin")
	adminReqs := checker.ParseRequirements([]kdexv1alpha1.SecurityRequirement{{"bearer": {"admin"}}})
	admin.ParsedRequirements = &adminReqs

	docs := newPage("docs", "Docs", "/docs")
	intro := newPage("intro", "Intro", "/docs/intro")
	intro.Page.ParentPageRef = &corev1.LocalObjectReference{Name: "docs"}
	tools := newPage("tools", "Tools", "/tools")
	tools.Page.Tags = []kdexv1alpha1.Tag{{Name: "nav-surrogate"}}

	sitemap := newPage("sitemap", "Sitemap", "/sitemap.xml")
	sitemap.Page.MimeType = "xml"
	sitemap.Page.Body = sitemapBody
	sitemap.Page.Tags = []kdexv1alpha1.Tag{{Name: "no-navigation"}}

	// The real checker fails closed on a zero-value ParsedRequirements, so
	// the open pages carry a parsed empty set, as RebuildMux gives them.
	open := checker.ParseRequirements(nil)
	for _, p := range []*page.PageHandler{&docs, &intro, &tools, &sitemap} {
		p.ParsedRequirements = &open
	}

	hh := gatedHostFixture(admin, docs, intro, tools, sitemap)
	hh.authChecker = checker

	entitled := func() *http.Request {
		req := httptest.NewRequest("GET", "/sitemap.xml", nil)
		return req.WithContext(auth.SetAuthContext(req.Context(),
			auth.AuthContext{"sub": "alice", "entitlements": []any{"pages::read", "admin"}}))
	}

	// Control: the entitled caller really can reach /admin, so its absence
	// below is the scope at work, not a fixture that hides it from everyone.
	root := &render.PageEntry{}
	hh.BuildMenuEntries(entitled().Context(), root, ptr.To(language.Make("en")), true, nil)
	require.NotNil(t, root.Children)
	require.Contains(t, *root.Children, "Admin")

	serve := func(req *http.Request) string {
		w := httptest.NewRecorder()
		hh.pageHandlerFunc(sitemap, &hh.Translations, language.Make(hh.defaultLanguage))(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		return w.Body.String()
	}

	first := serve(entitled())
	second := serve(httptest.NewRequest("GET", "/sitemap.xml", nil))

	for _, body := range []string{first, second} {
		require.True(t, strings.HasPrefix(body, "<?xml "), "the XML declaration must come first: %q", body)
		require.Contains(t, body, "<loc>https://example.com/docs</loc>")
		require.Contains(t, body, "<loc>https://example.com/docs/intro</loc>", "the template walks Children")
		require.NotContains(t, body, "sitemap.xml", "the template filters by tag")
		require.NotContains(t, body, "/admin", "the tree is the anonymous scope's")
		require.NotContains(t, body, "/tools", "the template filters by tag")
	}
	require.Equal(t, first, second)
}

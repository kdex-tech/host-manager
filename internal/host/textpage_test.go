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
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
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
// via define/template that lists only HTML pages (no text files, no rewrite
// aliases) and escapes each href for XML. The doc points back here; keep the
// two in step.
const sitemapBody = `[[- define "urls" ]][[ range $p := . ]]
  [[- if eq $p.Type "html" ]]<url><loc>https://example.com[[ $p.Href | html ]]</loc></url>[[ end ]]
  [[- if $p.Children ]][[ template "urls" $p.Children ]][[ end ]]
[[- end ]][[ end -]]
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">[[ template "urls" .PageMap ]]</urlset>
`

// sitemapFixture is a host with auth on, a real checker, and a sitemap text
// page over a small tree: /docs with child /docs/intro, /tools, a rewrite
// alias of /docs/intro, and /admin, which requires the "admin" entitlement. Anonymous
// callers may read pages, as on a real public host. The checker, not
// gatedHostFixture's authConfig.AnonymousEntitlements, decides the anonymous
// set. RebuildMux parses each page's spec.security, as in production.
func sitemapFixture(t *testing.T, extra ...page.PageHandler) *HostHandler {
	t.Helper()

	admin := newPage("admin", "Admin", "/admin")
	admin.Page.Security = &[]kdexv1alpha1.SecurityRequirement{{"bearer": {"admin"}}}
	docs := newPage("docs", "Docs", "/docs")
	intro := newPage("intro", "Intro", "/docs/intro")
	intro.Page.ParentPageRef = &corev1.LocalObjectReference{Name: "docs"}
	tools := aliasPH("tools", "/tools", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("intro"), Canonical: true})
	sitemap := textPageForTest(t, "sitemap", "/sitemap.xml", "xml", sitemapBody)
	sitemap.Page.Localized = ptr.To(false)

	hh := gatedHostFixture(append([]page.PageHandler{admin, docs, intro, tools, sitemap}, extra...)...)
	hh.authChecker = auth.NewAuthorizationChecker([]string{"pages::read"}, logr.Discard())
	hh.RebuildMux()
	return hh
}

// serveSitemap serves req through the sitemap page's handler, as registered
// now, and returns the body.
func serveSitemap(t *testing.T, hh *HostHandler, req *http.Request, lang string) string {
	t.Helper()
	sitemap, ok := hh.Pages.Get("sitemap")
	require.True(t, ok)
	w := httptest.NewRecorder()
	hh.pageHandlerFunc(sitemap, &hh.Translations, language.Make(lang))(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}

func entitledSitemapReq() *http.Request {
	return callerCtx(httptest.NewRequest("GET", "/sitemap.xml", nil), "alice", []any{"pages::read", "admin"})
}

// A text page's .PageMap is the host's page tree built under the ANONYMOUS
// scope, whoever asks: a sitemap lists what an anonymous crawler can reach,
// and the text-page cache key stays correct for every caller. The entitled
// caller asks first, so a per-caller tree would be the one cached and then
// served to the anonymous caller. See #283.
func TestTextPage_PageMapIsAnonymousScopedTree(t *testing.T) {
	hh := sitemapFixture(t)

	// Control: the entitled caller really can reach /admin, so its absence
	// below is the scope at work, not a fixture that hides it from everyone.
	require.Contains(t, hh.pageMap(entitledSitemapReq().Context(), language.Make("en")), "Admin")

	first := serveSitemap(t, hh, entitledSitemapReq(), "en")
	second := serveSitemap(t, hh, httptest.NewRequest("GET", "/sitemap.xml", nil), "en")

	for _, body := range []string{first, second} {
		require.True(t, strings.HasPrefix(body, "<?xml "), "the XML declaration must come first: %q", body)
		require.Contains(t, body, "<loc>https://example.com/docs</loc>")
		require.Contains(t, body, "<loc>https://example.com/docs/intro</loc>", "the template walks Children")
		require.NotContains(t, body, "sitemap.xml", "the template lists only HTML pages, not text files")
		require.NotContains(t, body, "/admin", "the tree is the anonymous scope's")
		require.NotContains(t, body, "/tools", "the template lists only HTML pages, not aliases")
	}
	require.Equal(t, first, second)
}

// The cached sitemap moves with the page set, not only with its own page:
// the host checksum the caches cycle on does not change when another
// KDexPage is added or gated. See #283.
func TestTextPage_PageMapCacheFollowsOtherPages(t *testing.T) {
	hh := sitemapFixture(t)
	anon := func() *http.Request { return httptest.NewRequest("GET", "/sitemap.xml", nil) }

	require.NotContains(t, serveSitemap(t, hh, anon(), "en"), "/pricing")

	hh.Pages.Set(newPage("pricing", "Pricing", "/pricing"))
	require.Contains(t, serveSitemap(t, hh, anon(), "en"), "<loc>https://example.com/pricing</loc>",
		"a page added after the first render must appear")

	gated := newPage("pricing", "Pricing", "/pricing")
	gated.Page.Security = &[]kdexv1alpha1.SecurityRequirement{{"bearer": {"admin"}}}
	hh.Pages.Set(gated)
	require.NotContains(t, serveSitemap(t, hh, anon(), "en"), "/pricing",
		"a page gated after the first render must drop out")
}

// A page whose requirements are not parsed is in no tree: nothing yet says
// who may see it. RebuildMux parses before it publishes the index, so this
// guards a checker installed after the last rebuild. See #283.
func TestBuildMenuEntries_UnparsedRequirementsAreHidden(t *testing.T) {
	hh := sitemapFixture(t)
	unparsed := newPage("fresh", "Fresh", "/fresh")
	unparsed.ParsedRequirements = nil
	hh.mu.Lock()
	hh.tree = newPageIndex(append(slices.Clone(hh.tree.pages), unparsed))
	hh.mu.Unlock()

	tree := hh.pageMap(context.Background(), language.Make("en"))
	require.Contains(t, tree, "Docs", "parsed pages still list")
	require.NotContains(t, tree, "Fresh")
}

// On a non-default language, a page with localized: false keeps its bare
// href: it registers only the bare route, so /fr/... would be a 404. See
// #283.
func TestBuildMenuEntries_UnlocalizedPageKeepsBareHref(t *testing.T) {
	hh := sitemapFixture(t)
	tree := hh.pageMap(context.Background(), language.Make("fr"))

	docs, ok := tree["Docs"].(render.PageEntry)
	require.True(t, ok)
	require.Equal(t, "/fr/docs", docs.Href)
	sitemap, ok := tree["sitemap"].(render.PageEntry)
	require.True(t, ok)
	require.Equal(t, "/sitemap.xml", sitemap.Href, "the fixture's sitemap sets localized: false")
}

// Every tree entry carries its page's mode, and an alias carries its target,
// with the Href the alias serves. An alias of a page the tree hides keeps
// its target's identity but not its path. See #284.
func TestBuildMenuEntries_EntriesCarryPageMode(t *testing.T) {
	billingRef := kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "billing"}
	bare := aliasPH("bare-alias", "/bare", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs")})
	bare.Page.Localized = ptr.To(false)
	hh := sitemapFixture(t,
		aliasPH("docs-alias", "/d", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs"), Canonical: true}),
		aliasPH("intro-alias", "/i", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs"), Path: "intro"}),
		aliasPH("old-alias", "/old", "/old/{rest...}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs"), Path: "{rest}"}),
		aliasPH("admin-alias", "/a", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("admin")}),
		aliasPH("billing-alias", "/b", "", kdexv1alpha1.RewriteSpec{TargetRef: billingRef}),
		bare,
	)
	hh.mu.Lock()
	hh.functions = []kdexv1alpha1.KDexFunction{{
		ObjectMeta: metav1ObjectMeta("billing"),
		Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/billing"}},
		Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady},
	}}
	hh.mu.Unlock()

	entry := func(tree map[string]any, label string) render.PageEntry {
		t.Helper()
		e, ok := tree[label].(render.PageEntry)
		require.True(t, ok, label)
		return e
	}

	tree := hh.pageMap(context.Background(), language.Make("en"))

	docs := entry(tree, "Docs")
	require.Equal(t, render.PageTypeHTML, docs.Type)
	require.Empty(t, docs.MimeType)
	require.Nil(t, docs.Rewrite)
	require.Equal(t, render.PageTypeHTML, entry(*docs.Children, "Intro").Type, "nested entries carry it too")

	sitemap := entry(tree, "sitemap")
	require.Equal(t, render.PageTypeText, sitemap.Type)
	require.Equal(t, "xml", sitemap.MimeType)
	require.Nil(t, sitemap.Rewrite)

	require.Equal(t, render.PageTypeRewrite, entry(tree, "docs-alias").Type)
	require.Equal(t, &render.PageRewrite{Canonical: true, Href: "/docs", Kind: "KDexPage", Name: "docs"},
		entry(tree, "docs-alias").Rewrite)
	require.Equal(t, "/docs/intro", entry(tree, "intro-alias").Rewrite.Href, "rewrite.path joins the target's basePath")
	require.Equal(t, "/docs", entry(tree, "old-alias").Rewrite.Href,
		"an empty wildcard's trailing slash is the legacy redirect the runtime follows")
	require.Equal(t, &render.PageRewrite{Kind: "KDexPage", Name: "admin"}, entry(tree, "admin-alias").Rewrite,
		"the anonymous tree does not list a hidden target's path")
	require.Equal(t, "/api/billing", entry(tree, "billing-alias").Rewrite.Href)

	fr := hh.pageMap(context.Background(), language.Make("fr"))
	require.Equal(t, "/fr/docs", entry(fr, "docs-alias").Rewrite.Href, "a localized page target keeps the language")
	require.Equal(t, "/api/billing", entry(fr, "billing-alias").Rewrite.Href, "functions are not localized")
	require.Equal(t, "/bare", entry(fr, "bare-alias").Href)
	require.Equal(t, "/docs", entry(fr, "bare-alias").Rewrite.Href,
		"a localized: false alias serves the default language")

	entitled := hh.pageMap(entitledSitemapReq().Context(), language.Make("en"))
	require.Equal(t, "/admin", entry(entitled, "admin-alias").Rewrite.Href)
}

// A parentPageRef with an empty name names no page, so the page is in no
// tree, as before the bucketed build.
func TestBuildMenuEntries_EmptyParentNameIsInNoTree(t *testing.T) {
	stray := newPage("stray", "Stray", "/stray")
	stray.Page.ParentPageRef = &corev1.LocalObjectReference{}
	hh := sitemapFixture(t, stray)
	require.NotContains(t, hh.pageMap(context.Background(), language.Make("en")), "Stray")
}

// A text page is never a landing page for a denied caller, even when it
// wins the weight-then-basePath order. See #283.
func TestFirstAuthorizedPage_SkipsTextPages(t *testing.T) {
	robots := textPageForTest(t, "robots", "/a-robots.txt", "txt", "User-agent: *")
	hh := sitemapFixture(t, robots)
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	require.Equal(t, "/docs", hh.firstAuthorizedPage(hh.treeEntitlements(context.Background())))
}

// The digest moves with what a tree reads and with nothing else: a content
// edit leaves every cached tree valid, a host-level gate does not. See #283.
func TestComputePageSetDigest_TracksTreeInputsOnly(t *testing.T) {
	hh := sitemapFixture(t)
	digest := func() string {
		hh.mu.RLock()
		defer hh.mu.RUnlock()
		return hh.pageSetDigest
	}
	before := digest()

	docs, _ := hh.Pages.Get("docs")
	edited := docs
	spec := *docs.Page
	spec.Body = "edited"
	edited.Page = &spec
	hh.Pages.Set(edited)
	require.Equal(t, before, digest(), "a body edit changes no tree")

	hh.mu.Lock()
	hh.host.Security = &[]kdexv1alpha1.SecurityRequirement{{"bearer": {"member"}}}
	hh.mu.Unlock()
	hh.RebuildMux()
	require.NotEqual(t, before, digest(), "a host-level gate changes what the tree shows")
}

// Siblings that share a label share one tree key. The page whose name sorts
// first keeps it, on every build. See #286.
func TestBuildMenuEntries_LabelCollisionIsDeterministic(t *testing.T) {
	hh := sitemapFixture(t,
		newPage("zeta", "Shared", "/zeta"),
		newPage("alpha", "Shared", "/alpha"),
	)
	for range 20 {
		got, ok := hh.pageMap(context.Background(), language.Make("en"))["Shared"].(render.PageEntry)
		require.True(t, ok)
		require.Equal(t, "alpha", got.Name)
	}
}

// Concurrent cache misses on one page share one render. The checker holds
// the first tree build until every caller has passed the page gate, so
// without coalescing each caller would build its own tree. See #285.
func TestTextPage_ConcurrentMissesShareOneRender(t *testing.T) {
	hh := sitemapFixture(t)

	const callers = 8
	var builds, gates atomic.Int32
	release := make(chan struct{})
	hh.mu.Lock()
	hh.authChecker = &pageMockAuthChecker{
		getEntitlementsFn: func(ctx context.Context) entitlements.ParsedEntitlements {
			// The gate asks with the request's context (t.Context() below),
			// the anonymous tree build with context.Background().
			if ctx == context.Background() {
				builds.Add(1)
				<-release
			} else {
				gates.Add(1)
			}
			return entitlements.ParsedEntitlements{}
		},
	}
	hh.mu.Unlock()

	var wg sync.WaitGroup
	bodies := make([]string, callers)
	for i := range callers {
		wg.Go(func() {
			bodies[i] = serveSitemap(t, hh, httptest.NewRequestWithContext(t.Context(), "GET", "/sitemap.xml", nil), "en")
		})
	}
	require.Eventually(t, func() bool { return gates.Load() == callers && builds.Load() >= 1 },
		5*time.Second, time.Millisecond, "every caller passed the gate while the first render is held")
	time.Sleep(20 * time.Millisecond) // the last callers go from the gate into the render
	close(release)
	wg.Wait()

	require.Equal(t, int32(1), builds.Load(), "one render for all concurrent misses")
	for _, b := range bodies {
		require.Equal(t, bodies[0], b)
	}
}

// A stale navigation fragment is re-rendered in the background for the
// caller it belongs to: its tree and Identity, not the anonymous ones.
// Rendering it with context.Background() stored the anonymous menu under a
// signed-in caller's key.
func TestNavigation_StaleMigrationKeepsTheCallersTree(t *testing.T) {
	home := newPage("home", "Home", "/home")
	home.Navigations = map[string]string{"main": `[[ range $k, $v := .PageMap ]][[ $v.Label ]];[[ end ]]`}
	hh := sitemapFixture(t, home)

	alice := func() *http.Request {
		return callerCtx(httptest.NewRequest("GET", "/-/navigation/main/en/home", nil), "alice", []any{"pages::read", "admin"})
	}
	get := func() string {
		w := httptest.NewRecorder()
		hh.Mux.ServeHTTP(w, alice())
		require.Equal(t, http.StatusOK, w.Code)
		return w.Body.String()
	}
	require.Contains(t, get(), "Admin;", "alice's tree lists the page she may see")

	// A host generation moves on: alice's entry is now stale.
	require.NoError(t, hh.cacheManager.Cycle("next-generation", false))
	require.Contains(t, get(), "Admin;", "the stale entry is served while it migrates")

	hh.mu.RLock()
	aliceHash, _ := hh.getUserHash(alice())
	key := navCacheKey("main", "/home", hh.treeSeed(home.Checksum()), language.Make("en"), aliceHash)
	hh.mu.RUnlock()
	navCache := hh.cacheManager.GetCache(navCacheClass, cache.CacheOptions{})
	require.Eventually(t, func() bool {
		_, _, current, _ := navCache.Get(context.Background(), key)
		return current
	}, 5*time.Second, 5*time.Millisecond, "the migration stores a current entry")
	migrated, _, _, err := navCache.Get(context.Background(), key)
	require.NoError(t, err)
	require.Contains(t, migrated, "Admin;", "the migrated fragment is still alice's")
}

// A signed-in caller whose auth context cannot be hashed (a claimMapping can
// leave a value json.Marshal rejects) is never filed under the shared "anon"
// key: their fragment is rendered for them alone and cached under nothing.
func TestNavigation_UnhashableCallerIsNeverCachedAsAnon(t *testing.T) {
	home := newPage("home", "Home", "/home")
	home.Navigations = map[string]string{"main": `[[ range $k, $v := .PageMap ]][[ $v.Label ]];[[ end ]]`}
	hh := sitemapFixture(t, home)

	req := httptest.NewRequest("GET", "/-/navigation/main/en/home", nil)
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "entitlements": []any{"pages::read", "admin"}, "bad": math.NaN(),
	}))
	_, ok := hh.getUserHash(req)
	require.False(t, ok, "NaN does not marshal")

	w := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Admin;", "the caller still gets their own tree")

	hh.mu.RLock()
	anonKey := navCacheKey("main", "/home", hh.treeSeed(home.Checksum()), language.Make("en"), "anon")
	hh.mu.RUnlock()
	_, found, _, err := hh.cacheManager.GetCache(navCacheClass, cache.CacheOptions{}).Get(context.Background(), anonKey)
	require.NoError(t, err)
	require.False(t, found, "nothing is stored under the anonymous key")
}

// When two pages claim one basePath, the one whose name sorts first is served
// and is the one the tree describes, on every rebuild.
func TestRebuildMux_DuplicateBasePathIsDeterministic(t *testing.T) {
	hh := sitemapFixture(t, newPage("aaa-dup", "Dup", "/docs"))
	for range 10 {
		hh.RebuildMux()
		hh.mu.RLock()
		served := hh.tree.byBasePath["/docs"].Name
		_, docsListed := hh.tree.byName["docs"]
		hh.mu.RUnlock()
		require.Equal(t, "aaa-dup", served)
		require.False(t, docsListed, "the dropped page is in no tree")
	}
}

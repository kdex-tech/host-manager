package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func aliasPH(name, basePath, pattern string, rw kdexv1alpha1.RewriteSpec) page.PageHandler {
	return page.PageHandler{
		Name: name,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label:   name,
			Paths:   kdexv1alpha1.Paths{BasePath: basePath, PatternPath: pattern},
			Rewrite: &rw,
		},
	}
}

func pageRef(name string) kdexv1alpha1.KDexObjectReference {
	return kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: name}
}

// registerRendersForTest registers every render onto ONE shared mux (unlike
// registerPageForTest's fresh mux per call), resolving rewrite targets the
// way rebuildMuxSnapshot does.
func (hh *HostHandler) registerRendersForTest(t *testing.T, fns []kdexv1alpha1.KDexFunction, phs ...page.PageHandler) *http.ServeMux {
	t.Helper()
	byName := map[string]page.PageHandler{}
	for _, ph := range phs {
		byName[ph.Name] = ph
	}
	mux := http.NewServeMux()
	routes := newRouteRegistry()
	for _, ph := range phs {
		pr := pageRender{ph: ph}
		if ph.Page.Rewrite != nil {
			pr.rewrite, pr.rewriteFound = resolveRewriteTarget(ph.Page.Rewrite.TargetRef, byName, fns)
		}
		require.NoError(t, hh.addHandlerAndRegister(mux, pr, hh.registeredPaths, &hh.Translations, routes))
	}
	hh.Mux = mux
	return mux
}

func TestResolveRewriteTarget(t *testing.T) {
	html := page.PageHandler{Name: "docs", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/docs/v3"}}}
	text := page.PageHandler{Name: "robots", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/robots.txt"}, MimeType: "txt"}}
	f := false
	unloc := page.PageHandler{Name: "unloc", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/u"}, Localized: &f}}
	hop := aliasPH("hop", "/hop", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs")})
	pages := map[string]page.PageHandler{"docs": html, "robots": text, "unloc": unloc, "hop": hop}
	fns := []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
		{ObjectMeta: metav1ObjectMeta("cold"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/cold"}}},
		{ObjectMeta: metav1ObjectMeta("inner"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/inner"}, Internal: true}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}

	got, ok := resolveRewriteTarget(pageRef("docs"), pages, fns)
	require.True(t, ok)
	assert.Equal(t, rewriteTarget{basePath: "/docs/v3", exact: "/docs/v3/", localized: true}, got, "HTML target's registered form has the trailing slash")

	got, ok = resolveRewriteTarget(pageRef("robots"), pages, fns)
	require.True(t, ok)
	assert.Equal(t, "/robots.txt", got.exact, "text target registers at its exact basePath")

	got, ok = resolveRewriteTarget(pageRef("unloc"), pages, fns)
	require.True(t, ok)
	assert.False(t, got.localized)

	_, ok = resolveRewriteTarget(pageRef("hop"), pages, fns)
	assert.False(t, ok, "a rewrite-mode target is never resolvable (one hop; Review Focus #2)")
	_, ok = resolveRewriteTarget(pageRef("gone"), pages, fns)
	assert.False(t, ok)

	got, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"}, pages, fns)
	require.True(t, ok)
	assert.Equal(t, rewriteTarget{basePath: "/api/downloads", exact: "/api/downloads"}, got)
	_, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "cold"}, pages, fns)
	assert.False(t, ok, "a function that is not Ready is not routable")
	_, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "inner"}, pages, fns)
	assert.False(t, ok, "an internal function is never on the host mux")
}

func TestRewrite_ServesTextPageTargetWithoutRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	rr := doRequest(t, mux, "GET", "/bots/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "hello", rr.Body.String())
	assert.Empty(t, rr.Header().Get("Location"))
	assert.Empty(t, rr.Header().Get("Link"), "canonical is opt-in")
}

func TestRewrite_HTMLTargetDispatchesToRegisteredForm(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := page.PageHandler{Name: "docs", MainTemplate: "<html></html>", Page: &kdexv1alpha1.KDexPageSpec{Label: "docs", Paths: kdexv1alpha1.Paths{BasePath: "/docs/v3"}}}
	mux := hh.registerRendersForTest(t, nil, target)
	tgt, ok := resolveRewriteTarget(pageRef("docs"), map[string]page.PageHandler{"docs": target}, nil)
	require.True(t, ok)
	// The empty-path dispatch lands on the page's own {$} route, not on a
	// slash-redirect that would expose the target URL.
	assertMatches(t, mux, "GET", tgt.exact, "GET /docs/v3/{$}")
}

func TestRewrite_SubstitutesParamsAndKeepsRawQuery(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerRendersForTest(t, []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}, aliasPH("get", "/get", "/get/{id}", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"},
		Path:      "{id}",
	}))
	// Stand-in for the function proxy route rebuildMuxSnapshot registers.
	mux.HandleFunc("/api/downloads/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path + "?" + r.URL.RawQuery))
	})

	rr := doRequest(t, mux, "GET", "/get/42?q=a%26b&x=1")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "/api/downloads/42?q=a%26b&x=1", rr.Body.String(), "Review Focus #4")
}

func TestRewrite_RefusesEncodedTraversal(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("u", "/u", "/u/{rest...}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots"), Path: "{rest}"})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	// End to end: ServeMux matches on the ESCAPED path, so %2F is not a
	// separator to it and nothing is cleaned; {rest...} receives the decoded
	// "a/../../secret" and the handler's safety check refuses it with 400.
	rr := doRequest(t, mux, "GET", "/u/a%2F..%2F..%2Fsecret")
	assert.Equal(t, http.StatusBadRequest, rr.Code, "Review Focus #1")
	assert.NotEqual(t, "hello", rr.Body.String(), "Review Focus #1: traversal must never reach the target")

	// The handler's own guard, for values the mux does not clean (defence in
	// depth -- e.g. a future pattern or a non-ServeMux caller).
	pr := pageRender{ph: alias}
	pr.rewrite, pr.rewriteFound = resolveRewriteTarget(pageRef("robots"),
		map[string]page.PageHandler{"robots": target}, nil)
	req := httptest.NewRequest("GET", "/u/x", nil)
	req.SetPathValue("rest", "../secret")
	w := httptest.NewRecorder()
	hh.rewriteHandlerFunc(pr, language.Make("en"), mux)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "Review Focus #1")
}

func TestRewrite_LocalizedPageTargetKeepsLanguagePrefix(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "about", "/about.txt", "txt", "about")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("a", "/a", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("about")}))

	// /fr/a/ must dispatch to /fr/about.txt (registered for the localized
	// text target), not to the bare /about.txt.
	rr := doRequest(t, mux, "GET", "/fr/a/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "about", rr.Body.String())
	assert.Equal(t, "fr", rr.Header().Get("Content-Language"), "served by the /fr route, not the bare default-language one")
	assertMatches(t, mux, "GET", "/fr/about.txt", "GET /fr/about.txt")
}

func TestRewrite_CanonicalLinkHeader(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.host.Routing.Domains = []string{"example.com"}
	hh.scheme = "https"
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots"), Canonical: true}))

	rr := doRequest(t, mux, "GET", "/bots/")
	assert.Equal(t, `<https://example.com/robots.txt>; rel="canonical"`, rr.Header().Get("Link"))
}

func TestRewrite_MissingTargetIs404(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerRendersForTest(t, nil,
		aliasPH("orphan", "/orphan", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("gone")}))
	assertMatches(t, mux, "GET", "/orphan/", "GET /orphan/{$}")
	rr := doRequest(t, mux, "GET", "/orphan/")
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRewrite_SecondHopIs508(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	req := httptest.NewRequest("GET", "/bots/", nil)
	req = req.WithContext(context.WithValue(req.Context(), rewriteMarkerKey{}, true))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusLoopDetected, rr.Code)
}

func TestRewrite_AliasGateAndTargetGateBothApply(t *testing.T) {
	target := newPage("keys", "Keys", "/keys.txt") // newPage sets ParsedRequirements, which arms the gate
	target.Page.MimeType, target.Page.Body = "txt", "secret"
	alias := aliasPH("k", "/k", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("keys")})
	alias.ParsedRequirements = &entitlements.ParsedRequirements{}

	// gatedHostFixture's auth wiring on top of newTestHostHandler, whose
	// Translations are populated -- addHandlerAndRegister registers one
	// route set per language, so an empty language list registers nothing.
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.authConfig = &auth.Config{AnonymousEntitlements: []string{"public"}, ActivePair: &keys.KeyPair{}}
	hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}

	// Alias public, target gated: the TARGET's gate must still deny (Review Focus #3).
	hh.authChecker = denyPath("/keys.txt")
	mux := hh.registerRendersForTest(t, nil, target, alias)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, anonReq("GET", "/k/", "application/json"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Alias gated: denied before any dispatch.
	hh.authChecker = denyPath("/k")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, anonReq("GET", "/k/", "application/json"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRewrite_NoDeadlockUnderConcurrentWriter(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")}))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // a SetHost-shaped writer hammering hh.mu
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				hh.mu.Lock()
				hh.mu.Unlock() //nolint:staticcheck // deliberate empty critical section
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		for range 2000 {
			doRequest(t, mux, "GET", "/bots/")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("rewrite dispatch deadlocked against a concurrent writer (Review Focus #5)")
	}
	close(stop)
	wg.Wait()
}

func metav1ObjectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }

func TestRewrite_DispatchesIntoRegisteredSnapshotNotLiveMux(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")}))
	hh.Mux = http.NewServeMux() // a reconcile swapped in a different snapshot

	rr := doRequest(t, mux, "GET", "/bots/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "hello", rr.Body.String())
}

func TestRewrite_OpenAPIDescribesAlias(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")}))

	found := 0
	for _, info := range hh.registeredPaths {
		for p, item := range info.API.Paths {
			if item.Get == nil || !strings.HasPrefix(item.Get.OperationID, "bots") {
				continue
			}
			found++
			assert.Contains(t, item.Get.Summary, "Alias of KDexPage/robots", p)
			resp := item.Get.Responses.Status(http.StatusOK)
			require.NotNil(t, resp, p)
			assert.Nil(t, resp.Value.Content, "%s: an alias must not claim text/html", p)
		}
	}
	assert.GreaterOrEqual(t, found, 2, "bare + /fr routes documented")
	ids := collectOperationIDs(t, hh)
	assert.Len(t, ids, len(uniqueStrings(ids)), "operationIds stay unique")
}

func uniqueStrings(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		m[s] = struct{}{}
	}
	return m
}

// rootTargetWithSystemRoutes registers a root HTML target plus stand-ins for
// the /-/ and /.well-known/ system routes rebuildMuxSnapshot registers.
func rootTargetWithSystemRoutes(t *testing.T, hh *HostHandler, alias page.PageHandler) *http.ServeMux {
	t.Helper()
	root := page.PageHandler{Name: "root", MainTemplate: "<html></html>", Page: &kdexv1alpha1.KDexPageSpec{Label: "root", Paths: kdexv1alpha1.Paths{BasePath: "/"}}}
	mux := hh.registerRendersForTest(t, nil, root, alias)
	mux.HandleFunc("GET /-/userinfo", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("userinfo")) })
	mux.HandleFunc("GET /.well-known/x", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("well-known")) })
	return mux
}

// A single-segment wildcard value holding a decoded %2F must not span
// segments into a system route (final review I1, verified repro).
func TestRewrite_SingleSegmentValueCannotReachSystemRoutes(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := rootTargetWithSystemRoutes(t, hh,
		aliasPH("m", "/m", "/m/{id}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("root"), Path: "{id}"}))

	for _, p := range []string{"/m/-%2Fuserinfo", "/m/.well-known%2Fx"} {
		rr := doRequest(t, mux, "GET", p)
		assert.Equal(t, http.StatusNotFound, rr.Code, p)
		assert.NotContains(t, rr.Body.String(), "userinfo", p)
		assert.NotContains(t, rr.Body.String(), "well-known", p)
	}
}

// Even a multi-segment wildcard, which may legitimately span segments, never
// dispatches to a system path: those are never rewrite targets (spec §Out
// of scope; final review I1).
func TestRewrite_MultiSegmentValueCannotReachSystemRoutes(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := rootTargetWithSystemRoutes(t, hh,
		aliasPH("m", "/m", "/m/{rest...}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("root"), Path: "{rest}"}))

	for _, p := range []string{"/m/-/userinfo", "/m/.well-known/x", "/m/-%2Fuserinfo"} {
		rr := doRequest(t, mux, "GET", p)
		assert.Equal(t, http.StatusNotFound, rr.Code, p)
		assert.NotContains(t, rr.Body.String(), "userinfo", p)
		assert.NotContains(t, rr.Body.String(), "well-known", p)
	}
}

// The canonical target is percent-encoded into the Link header, so a
// request value cannot close the <...> and inject a second link (final
// review I2, verified repro).
func TestRewrite_CanonicalLinkHeaderIsEscaped(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.host.Routing.Domains = []string{"example.com"}
	hh.scheme = "https"
	mux := hh.registerRendersForTest(t, []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}, aliasPH("u", "/u", "/u/{rest...}", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"},
		Path:      "{rest}",
		Canonical: true,
	}))
	mux.HandleFunc("/api/downloads/", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	rr := doRequest(t, mux, "GET", `/u/x%3E;%20rel=%22nofollow%22,%20%3Chttps:evil.example`)
	link := rr.Header().Get("Link")
	require.Len(t, rr.Header().Values("Link"), 1)
	assert.Equal(t, 1, strings.Count(link, "<"), link)
	assert.Equal(t, 1, strings.Count(link, ">"), link)
	assert.Equal(t, 1, strings.Count(link, `rel="`), link)
	assert.Equal(t, 1, strings.Count(link, `rel="canonical"`), link)
	assert.True(t, strings.HasSuffix(link, `>; rel="canonical"`), link)
	uri := link[strings.Index(link, "<")+1 : strings.Index(link, ">")]
	assert.Contains(t, uri, "%3E", link)
	assert.NotContains(t, uri, `"`, link)
	assert.NotContains(t, uri, " ", link)
	assert.True(t, strings.HasPrefix(uri, "https://example.com/api/downloads/x"), link)
}

// {rest...} copied verbatim from patternPath into rewrite.path substitutes
// like {rest} (final review I3).
func TestRewrite_MultiSegmentSpellingInPathSubstitutes(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerRendersForTest(t, []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}, aliasPH("d", "/d", "/d/{rest...}", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"},
		Path:      "{rest...}",
	}))
	mux.HandleFunc("/api/downloads/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.URL.Path)) })

	rr := doRequest(t, mux, "GET", "/d/a/b")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "/api/downloads/a/b", rr.Body.String())
}

// A slashless request whose target would trailing-slash redirect is sent to
// the ALIAS's slash form, never to the target URL (final review I4 / R5).
func TestRewrite_TrailingSlashRedirectStaysOnAlias(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "docs-v3", "/docs/v3", "txt", "v3 page")
	target.Page.PatternPath = "/docs/v3/{page}/"
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("latest", "/docs/latest", "/docs/latest/{rest...}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs-v3"), Path: "{rest}"}))

	// Precondition: the target itself answers the slashless path with a
	// trailing-slash redirect.
	direct := doRequest(t, mux, "GET", "/docs/v3/guide")
	require.Equal(t, "/docs/v3/guide/", direct.Header().Get("Location"))

	rr := doRequest(t, mux, "GET", "/docs/latest/guide?x=1")
	assert.Equal(t, direct.Code, rr.Code, "same status ServeMux uses")
	assert.Equal(t, "/docs/latest/guide/?x=1", rr.Header().Get("Location"))
	assert.NotContains(t, rr.Header().Get("Location"), "/docs/v3")

	rr = doRequest(t, mux, "GET", "/docs/latest/guide/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "v3 page", rr.Body.String())
}

// The bare alias route of a page whose required placeholder is absent is a
// missing segment: 404, not 400 (final review M1).
func TestRewrite_EmptyRequiredPlaceholderIs404(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "profile", "/profile", "txt", "profile")
	target.Page.PatternPath = "/profile/{user}/"
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("u", "/u", "/u/{user}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("profile"), Path: "{user}/"}))

	rr := doRequest(t, mux, "GET", "/u/")
	assert.Equal(t, http.StatusNotFound, rr.Code)
	rr = doRequest(t, mux, "GET", "/u/bob")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "profile", rr.Body.String())
}

package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// digestTemplate renders every host-wide input a page reads: the meta
// (host assets, the default-language path prefix), the head (importmap),
// the brand, the organization, the language list and a translation.
const digestTemplate = `<html><head>[[ .Meta ]][[ .HeadScript ]]</head><body>` +
	`brand=[[ .BrandName ]] org=[[ .Organization ]] langs=[[ range .Languages ]][[ . ]],[[ end ]] hi=[[ l10n "hi" ]]` +
	`</body></html>`

func digestSpec() *kdexv1alpha1.KDexHostSpec {
	return &kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex", Organization: "KDex Tech"}
}

func applyDigestHost(hh *HostHandler, spec *kdexv1alpha1.KDexHostSpec, reconcileTime time.Time) {
	hh.SetHost(context.Background(), spec,
		&kdexv1alpha1.KDexObjectStatus{Attributes: map[string]string{"packages.importmap": importmapBuild1}},
		nil, nil, nil, importmapBuild1, nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, reconcileTime)
	hh.authChecker = &mockAuthChecker{}
}

func digestTranslation(lang, hi string) *kdexv1alpha1.KDexTranslationSpec {
	return &kdexv1alpha1.KDexTranslationSpec{Translations: []kdexv1alpha1.Translation{
		{Lang: lang, KeysAndValues: map[string]string{"hi": hi}},
	}}
}

func newDigestHost(t *testing.T) *HostHandler {
	t.Helper()
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.AddOrUpdateTranslation("base", digestTranslation("en", "Hello"))
	hh.Pages.Set(page.PageHandler{
		Name:         "page-b",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "page-b", Paths: kdexv1alpha1.Paths{BasePath: "/b"}},
		MainTemplate: digestTemplate,
		Navigations: map[string]string{
			"main": `nav brand=[[ .BrandName ]] org=[[ .Organization ]] langs=[[ range .Languages ]][[ . ]],[[ end ]] hi=[[ l10n "hi" ]]`,
		},
		Status: &kdexv1alpha1.KDexObjectStatus{ObservedGeneration: 1},
	})
	hh.Pages.Set(page.PageHandler{
		Name: "page-t",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label:    "page-t",
			Paths:    kdexv1alpha1.Paths{BasePath: "/t"},
			MimeType: "text/plain",
			Body:     `brand=[[ .BrandName ]] org=[[ .Organization ]] langs=[[ range .Languages ]][[ . ]],[[ end ]] hi=[[ l10n "hi" ]]`,
		},
		Status: &kdexv1alpha1.KDexObjectStatus{ObservedGeneration: 1},
	})
	return hh
}

// Each host-wide input a page renders from must move the page's cache key
// and ETag. An edit to one cycles the caches but keeps the page's own key,
// so without it the previous render is served as a stale hit under the new
// ETag, and a client revalidating its old copy is told it is current
// (#302's mechanism, for every input and not only the importmap).
func TestHostWideRenderInputsInvalidatePages(t *testing.T) {
	cases := []struct {
		name string
		// path is where the page is served before and after the change.
		before, after string
		change        func(hh *HostHandler, reconcileTime time.Time)
		want          string
	}{
		{
			name: "host assets", before: "/b", after: "/b",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.Assets = kdexv1alpha1.Assets{{LinkHref: "/-/theme/v2.css", Attributes: map[string]string{"rel": "stylesheet"}}}
				applyDigestHost(hh, spec, rt)
			},
			want: "/-/theme/v2.css",
		},
		{
			name: "brand name", before: "/b", after: "/b",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.BrandName = "Acme"
				applyDigestHost(hh, spec, rt)
			},
			want: "brand=Acme",
		},
		{
			name: "organization", before: "/b", after: "/b",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.Organization = "Acme Corp"
				applyDigestHost(hh, spec, rt)
			},
			want: "org=Acme Corp",
		},
		{
			// The French page moves from /fr/b to the bare /b; its meta
			// path prefix (MetaToString) goes with it.
			name: "default language", before: "/fr/b", after: "/b",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.DefaultLang = "fr"
				applyDigestHost(hh, spec, rt)
			},
			want: `data-page-basepath="/b"`,
		},
		{
			name: "language list", before: "/b", after: "/b",
			change: func(hh *HostHandler, _ time.Time) {
				hh.AddOrUpdateTranslation("german", digestTranslation("de", "Hallo"))
			},
			want: "de,",
		},
		{
			name: "translation value", before: "/b", after: "/b",
			change: func(hh *HostHandler, _ time.Time) {
				hh.AddOrUpdateTranslation("base", digestTranslation("en", "Howdy"))
			},
			want: "hi=Howdy",
		},
		{
			name: "text page brand name", before: "/t", after: "/t",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.BrandName = "Acme"
				applyDigestHost(hh, spec, rt)
			},
			want: "brand=Acme",
		},
		{
			name: "text page language list", before: "/t", after: "/t",
			change: func(hh *HostHandler, _ time.Time) {
				hh.AddOrUpdateTranslation("german", digestTranslation("de", "Hallo"))
			},
			want: "de,",
		},
		{
			// A navigation fragment renders the same text inputs.
			name: "navigation brand name", before: "/-/navigation/main/en/b", after: "/-/navigation/main/en/b",
			change: func(hh *HostHandler, rt time.Time) {
				spec := digestSpec()
				spec.BrandName = "Acme"
				applyDigestHost(hh, spec, rt)
			},
			want: "brand=Acme",
		},
		{
			name: "navigation translation value", before: "/-/navigation/main/en/b", after: "/-/navigation/main/en/b",
			change: func(hh *HostHandler, _ time.Time) {
				hh.AddOrUpdateTranslation("base", digestTranslation("en", "Howdy"))
			},
			want: "hi=Howdy",
		},
		{
			// The translation endpoint serves the strings themselves; a
			// translation edit moves no Last-Modified, so the digest is the
			// only thing that can tell the old body from the new.
			name: "translation endpoint value", before: "/-/translation/en", after: "/-/translation/en",
			change: func(hh *HostHandler, _ time.Time) {
				hh.AddOrUpdateTranslation("base", digestTranslation("en", "Howdy"))
			},
			want: "Howdy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hh := newDigestHost(t)
			hh.AddOrUpdateTranslation("french", digestTranslation("fr", "Bonjour"))
			// One reconcile time for every apply: the second-granular
			// Last-Modified must not be what tells the renders apart.
			reconcileTime := time.Now()
			applyDigestHost(hh, digestSpec(), reconcileTime)

			before := getPage(hh, tc.before, "")
			require.Equal(t, http.StatusOK, before.Code)
			require.NotContains(t, before.Body.String(), tc.want)
			etagBefore := before.Header().Get("ETag")
			require.NotEmpty(t, etagBefore)

			tc.change(hh, reconcileTime)

			fresh := getPage(hh, tc.after, "")
			require.Equal(t, http.StatusOK, fresh.Code)
			assert.Contains(t, fresh.Body.String(), tc.want, "the first request after the change serves a fresh render")

			revalidated := getPage(hh, tc.after, etagBefore)
			require.Equal(t, http.StatusOK, revalidated.Code, "the ETag from before the change is not current")
			assert.Contains(t, revalidated.Body.String(), tc.want)
			assert.NotEqual(t, etagBefore, revalidated.Header().Get("ETag"))
		})
	}
}

// A page-only change (another page's generation moves) leaves the host
// render digest alone, so it re-renders only that page.
func TestHostRenderDigestIgnoresPageChanges(t *testing.T) {
	hh := newDigestHost(t)
	applyDigestHost(hh, digestSpec(), time.Now())
	hh.mu.RLock()
	html, text := hh.renderDigest, hh.textDigest
	hh.mu.RUnlock()
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)

	hh.Pages.Set(page.PageHandler{
		Name:         "page-c",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "page-c", Paths: kdexv1alpha1.Paths{BasePath: "/c"}},
		MainTemplate: digestTemplate,
		Status:       &kdexv1alpha1.KDexObjectStatus{ObservedGeneration: 7},
	})
	hh.RebuildMux()

	hh.mu.RLock()
	defer hh.mu.RUnlock()
	assert.Equal(t, html, hh.renderDigest)
	assert.Equal(t, text, hh.textDigest)
}

// The utility background re-render must not store a render under a key
// that no longer describes the host: a SetHost that lands between the
// stale hit and the goroutine taking the lock moves the importmap, and the
// goroutine would otherwise write the new importmap's render under the
// previous key (#302).
func TestUtilityBackgroundRenderSkipsMovedKey(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.utilityPages[kdexv1alpha1.AnnouncementUtilityPageType] = page.PageHandler{
		Name:         "announcement",
		MainTemplate: promotionTemplate,
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "announcement", Paths: kdexv1alpha1.Paths{BasePath: "/-/announcement"}},
	}
	reconcileTime := time.Now()
	setPromotionHost(hh, importmapBuild1, reconcileTime)

	// Stage a stale hit under the build-1 key.
	uc := cacheManager.GetCache(utilityCacheClass, cache.CacheOptions{})
	hh.mu.RLock()
	oldKey := hh.renderCacheKeyLocked(hh.utilityPages[kdexv1alpha1.AnnouncementUtilityPageType], language.English)
	hh.mu.RUnlock()
	require.NoError(t, cacheManager.Cycle("stage-a", false))
	require.NoError(t, uc.Set(context.Background(), oldKey, "stale build-1 render"))
	require.NoError(t, cacheManager.Cycle("stage-b", false))

	// Hold the background re-render before it takes the lock.
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)
	hh.migrationStarted = func() {
		started.Done()
		<-release
	}

	hh.mu.RLock()
	served := hh.renderUtilityPage(kdexv1alpha1.AnnouncementUtilityPageType, language.English, nil, &hh.Translations)
	hh.mu.RUnlock()
	require.Equal(t, "stale build-1 render", served)
	started.Wait()

	// Promote while the re-render waits, then let it run.
	setPromotionHost(hh, importmapBuild2, reconcileTime)
	close(release)
	require.Eventually(t, func() bool {
		idle := true
		hh.pageMigrations.Range(func(any, any) bool { idle = false; return false })
		return idle
	}, 5*time.Second, time.Millisecond)

	rendered, ok, _, err := uc.Get(context.Background(), oldKey)
	require.NoError(t, err)
	if ok {
		assert.NotContains(t, rendered, "sha384-BUILD2", "the new importmap's render is not stored under the previous key")
	}
}

// The login page and the not-ready announcement render the importmap and
// the host's brand, so a client holding either from before a promotion
// must not get a 304, even when the reconcile time is unchanged (#302).
func TestLoginAndAnnouncementETagsMoveWithPromotion(t *testing.T) {
	utility := func(name string, typ kdexv1alpha1.KDexUtilityPageType) page.PageHandler {
		return page.PageHandler{
			Name:         name,
			MainTemplate: promotionTemplate,
			Page:         &kdexv1alpha1.KDexPageSpec{Label: name, Paths: kdexv1alpha1.Paths{BasePath: "/-/" + name}},
			UtilityPage:  &kdexv1alpha1.KDexUtilityPageSpec{Type: typ},
		}
	}
	// LoginGet is called directly: the mux registers /-/login only once
	// auth is configured, and that is not what this test is about.
	login := func(hh *HostHandler, ifNoneMatch string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/-/login", nil)
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		w := httptest.NewRecorder()
		hh.LoginGet(w, req)
		return w
	}
	viaMux := func(path string) func(*HostHandler, string) *httptest.ResponseRecorder {
		return func(hh *HostHandler, ifNoneMatch string) *httptest.ResponseRecorder {
			return getPage(hh, path, ifNoneMatch)
		}
	}
	cases := []struct {
		name  string
		get   func(hh *HostHandler, ifNoneMatch string) *httptest.ResponseRecorder
		setup func(hh *HostHandler)
	}{
		{name: "login", get: login, setup: func(hh *HostHandler) {
			hh.Pages.Set(promotionPage("page-a", "/a", "@x/app-x", 1))
			hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = utility("login", kdexv1alpha1.LoginUtilityPageType)
		}},
		{name: "announcement", get: viaMux("/"), setup: func(hh *HostHandler) {
			hh.utilityPages[kdexv1alpha1.AnnouncementUtilityPageType] = utility("announcement", kdexv1alpha1.AnnouncementUtilityPageType)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cacheManager, err := cache.NewCacheManager("", "test-host", nil)
			require.NoError(t, err)
			hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
			tc.setup(hh)
			reconcileTime := time.Now()
			setPromotionHost(hh, importmapBuild1, reconcileTime)
			hh.authChecker = &mockAuthChecker{}

			before := tc.get(hh, "")
			require.Equal(t, http.StatusOK, before.Code)
			require.Contains(t, before.Body.String(), "sha384-BUILD1")
			etagBefore := before.Header().Get("ETag")
			require.NotEmpty(t, etagBefore)

			// Unchanged host: the client's copy is current.
			require.Equal(t, http.StatusNotModified, tc.get(hh, etagBefore).Code)

			setPromotionHost(hh, importmapBuild2, reconcileTime)
			hh.authChecker = &mockAuthChecker{}

			revalidated := tc.get(hh, etagBefore)
			require.Equal(t, http.StatusOK, revalidated.Code, "the pre-promotion ETag is not current")
			assert.Contains(t, revalidated.Body.String(), "sha384-BUILD2")
			assert.NotEqual(t, etagBefore, revalidated.Header().Get("ETag"))
		})
	}
}

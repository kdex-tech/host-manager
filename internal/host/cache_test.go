package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHostHandler_PageCaching(t *testing.T) {
	// Setup
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	// Mock Page
	ph := page.PageHandler{
		Name: "test-page",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Test Page",
			Paths: kdexv1alpha1.Paths{
				BasePath: "/test",
			},
		},
		MainTemplate: "<html><body>[[ .Title ]]</body></html>",
	}
	hh.Pages.Set(ph)

	// Initialize Host (this sets reconcileTime and rebuilds mux)
	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		BrandName:   "KDex",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	// Mock authChecker to allow all access
	hh.authChecker = &mockAuthChecker{}

	// 1. Initial Request
	req := httptest.NewRequest("GET", "/test/", nil)
	w := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	etag := w.Header().Get("ETag")
	lastModified := w.Header().Get("Last-Modified")
	assert.NotEmpty(t, etag)
	assert.NotEmpty(t, lastModified)
	body1 := w.Body.String()
	assert.Contains(t, body1, "Test Page")

	// Verify it's in cache
	cacheVal, found, isCurrent, err := cacheManager.GetCache("page", cache.CacheOptions{}).Get(context.Background(), ph.CacheKey(language.English))
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, isCurrent)
	assert.Equal(t, body1, cacheVal)

	// 2. Test 304 logic

	// 3. Conditional Request (If-None-Match)
	req3 := httptest.NewRequest("GET", "/test/", nil)
	req3.Header.Set("If-None-Match", etag)
	w3 := httptest.NewRecorder()
	hh.ServeHTTP(w3, req3)
	assert.Equal(t, http.StatusNotModified, w3.Code)

	// 4. Conditional Request (If-Modified-Since)
	req4 := httptest.NewRequest("GET", "/test/", nil)
	req4.Header.Set("If-Modified-Since", lastModified)
	w4 := httptest.NewRecorder()
	hh.ServeHTTP(w4, req4)
	assert.Equal(t, http.StatusNotModified, w4.Code)
}

func TestHostHandler_NavigationCaching(t *testing.T) {
	// Setup
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	// Mock Page with Navigation
	ph := page.PageHandler{
		Name: "test-page",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Test Page",
			Paths: kdexv1alpha1.Paths{
				BasePath: "/test",
			},
		},
		Navigations: map[string]string{
			"main": "<ul><li>[[ .Title ]]</li></ul>",
		},
	}
	hh.Pages.Set(ph)

	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		BrandName:   "KDex",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	// 1. Initial Request
	req := httptest.NewRequest("GET", "/-/navigation/main/en/test", nil)
	w := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body1 := w.Body.String()
	assert.Contains(t, body1, "Test Page")

	// Verify it's in cache
	// Key format: nav:main:/test:en:anon (since no auth)
	cacheKey := fmt.Sprintf("%s:%s:%s:%s:%s", "main", ph.Page.Paths.BasePath, ph.Checksum(), language.English.String(), "anon")
	cacheVal, found, isCurrent, err := cacheManager.GetCache("nav", cache.CacheOptions{}).Get(context.Background(), cacheKey)
	require.NoError(t, err)
	assert.True(t, found)
	assert.True(t, isCurrent)
	assert.Equal(t, body1, cacheVal)

	// 2. Test RBAC/Identity Separation
	// Mock a request with an Authorization header
	req2 := httptest.NewRequest("GET", "/-/navigation/main/en/test", nil)
	req2.Header.Set("Authorization", "Bearer user-token")

	// Make NavigationGet public for this test or mock auth requirements
	// In the code, NavigationGet uses authenticated requirement by default in my change.
	// But applyCachingHeaders checks hh.authConfig.IsAuthEnabled().

	w2 := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)

	// Verify different cache key is used
	userHash := hh.getUserHash(req2)
	assert.NotEqual(t, "anon", userHash)
	// cacheKey2 := fmt.Sprintf("main:/test:en:%s", userHash)
	cacheKey2 := fmt.Sprintf("%s:%s:%s:%s:%s", "main", ph.Page.Paths.BasePath, ph.Checksum(), language.English.String(), userHash)

	_, found2, _, err2 := cacheManager.GetCache("nav", cache.CacheOptions{}).Get(context.Background(), cacheKey2)
	assert.NoError(t, err2)
	assert.True(t, found2)
}

type mockAuthChecker struct{}

func (m *mockAuthChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return true, nil
}

func (m *mockAuthChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (m *mockAuthChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (m *mockAuthChecker) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return true, nil
}

func TestApplyCachingHeaders_ETagVariesByLanguage(t *testing.T) {
	// Regression for kdex-tech/host-manager#43: applyCachingHeaders built
	// the ETag from lastModified + identity only — not the language. Two
	// responses to the same URL with different Accept-Language values
	// shared an ETag despite serving different content, breaking Vary-
	// aware revalidation at intermediaries that normalize Accept-Language
	// (some CDNs do) and confusing any client that treats the ETag as a
	// content-identity claim. Fix: applyCachingHeadersWithLang folds the
	// resolved language tag into the ETag input.
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)
	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		BrandName:   "KDex",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	lastModified := hh.reconcileTime

	wEn := httptest.NewRecorder()
	rEn := httptest.NewRequest("GET", "/", nil)
	hh.applyCachingHeadersWithLang(wEn, rEn, nil, lastModified, "en-CA")
	etagEn := wEn.Header().Get("ETag")

	wFr := httptest.NewRecorder()
	rFr := httptest.NewRequest("GET", "/", nil)
	hh.applyCachingHeadersWithLang(wFr, rFr, nil, lastModified, "fr-CA")
	etagFr := wFr.Header().Get("ETag")

	assert.NotEmpty(t, etagEn)
	assert.NotEmpty(t, etagFr)
	assert.NotEqual(t, etagEn, etagFr,
		"ETag must differ between en-CA and fr-CA responses for the same URL — pre-fix they were identical")
	assert.Contains(t, etagEn, "en-CA", "ETag should encode the resolved language")
	assert.Contains(t, etagFr, "fr-CA", "ETag should encode the resolved language")

	// If-None-Match with the en ETag must NOT 304 a fr request (the
	// observable symptom of the bug — wrong-variant cache hits).
	wCross := httptest.NewRecorder()
	rCross := httptest.NewRequest("GET", "/", nil)
	rCross.Header.Set("If-None-Match", etagEn)
	completed := hh.applyCachingHeadersWithLang(wCross, rCross, nil, lastModified, "fr-CA")
	assert.False(t, completed, "fr-CA request must not be answered as 304 against an en-CA ETag")
	assert.NotEqual(t, http.StatusNotModified, wCross.Code)

	// Sanity: same-language If-None-Match still 304s.
	wSame := httptest.NewRecorder()
	rSame := httptest.NewRequest("GET", "/", nil)
	rSame.Header.Set("If-None-Match", etagEn)
	completed = hh.applyCachingHeadersWithLang(wSame, rSame, nil, lastModified, "en-CA")
	assert.True(t, completed, "en-CA request with matching en-CA ETag must 304")
	assert.Equal(t, http.StatusNotModified, wSame.Code)

	// Backwards-compat shim (no language) still works for endpoints
	// genuinely independent of Accept-Language (favicon, raw OpenAPI).
	wPlain := httptest.NewRecorder()
	rPlain := httptest.NewRequest("GET", "/-/openapi", nil)
	hh.applyCachingHeaders(wPlain, rPlain, lastModified)
	etagPlain := wPlain.Header().Get("ETag")
	assert.NotEmpty(t, etagPlain)
	assert.NotContains(t, etagPlain, "en-CA")
	assert.NotContains(t, etagPlain, "fr-CA")
}

func TestApplyCachingHeaders_ETagVariesByPageSeed(t *testing.T) {
	// kdex-tech/host-manager#44: applyCachingHeadersWithSeed folds a
	// per-response seed (page.Checksum() — sha256 over
	// ObservedGeneration + sorted Status.Attributes) into the ETag input
	// so each KDexPage's ETag invalidates only when ITS observed state
	// moves rather than on every host reconcile (which bumps
	// hh.reconcileTime cluster-wide for every CR apply).
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)
	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		BrandName:   "KDex",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	lastModified := hh.reconcileTime
	const lang = "en-CA"

	wA := httptest.NewRecorder()
	rA := httptest.NewRequest("GET", "/page-a", nil)
	hh.applyCachingHeadersWithSeed(wA, rA, nil, lastModified, lang, "checksum-a")
	etagA := wA.Header().Get("ETag")

	wB := httptest.NewRecorder()
	rB := httptest.NewRequest("GET", "/page-b", nil)
	hh.applyCachingHeadersWithSeed(wB, rB, nil, lastModified, lang, "checksum-b")
	etagB := wB.Header().Get("ETag")

	wEmpty := httptest.NewRecorder()
	rEmpty := httptest.NewRequest("GET", "/empty-seed", nil)
	hh.applyCachingHeadersWithSeed(wEmpty, rEmpty, nil, lastModified, lang, "")
	etagEmpty := wEmpty.Header().Get("ETag")

	assert.NotEqual(t, etagA, etagB,
		"two pages with different Checksum() seeds must produce distinct ETags — pre-fix every page shared the cluster-wide reconcileTime")
	assert.Contains(t, etagA, "checksum-a", "ETag should encode the per-response seed")
	assert.Contains(t, etagB, "checksum-b", "ETag should encode the per-response seed")
	assert.NotEqual(t, etagA, etagEmpty,
		"empty-seed ETag must differ from non-empty-seed ETag at the same lastModified+lang")

	// If-None-Match with one page's ETag must NOT 304 a different page
	// with a different seed — that's the observable symptom of the bug
	// (one page's edit busting another page's cache, OR worse, two pages
	// of different content sharing the same cached representation).
	wCross := httptest.NewRecorder()
	rCross := httptest.NewRequest("GET", "/page-b", nil)
	rCross.Header.Set("If-None-Match", etagA)
	completed := hh.applyCachingHeadersWithSeed(wCross, rCross, nil, lastModified, lang, "checksum-b")
	assert.False(t, completed, "different-seed request must not be answered as 304 against another page's ETag")
	assert.NotEqual(t, http.StatusNotModified, wCross.Code)

	// Sanity: same seed + same lang + same lastModified still 304s.
	wSame := httptest.NewRecorder()
	rSame := httptest.NewRequest("GET", "/page-a", nil)
	rSame.Header.Set("If-None-Match", etagA)
	completed = hh.applyCachingHeadersWithSeed(wSame, rSame, nil, lastModified, lang, "checksum-a")
	assert.True(t, completed, "same-seed request with matching ETag must 304")
	assert.Equal(t, http.StatusNotModified, wSame.Code)
}

func TestSetHost_DoesNotEvictUncycledCache(t *testing.T) {
	// Regression for kdex-tech/host-manager#42: SetHost used to invoke
	// cacheManager.Cycle(checksum, true) with force=true, which silently
	// evicted Uncycled caches despite the flag. Refresh tokens live in
	// the "refresh-tokens" cache with Uncycled: true precisely so they
	// survive routine config-change reconciles — pre-fix, every CR apply
	// (KDexPage, KDexFunction, etc.) wiped every active refresh token,
	// surfacing as "refresh token not found or expired" right when a
	// user's JWT was about to expire.
	//
	// Fix: SetHost calls Cycle(..., false). Cycled caches still rotate
	// with a prevPrefix transition window; Uncycled caches are preserved.
	ctx := context.Background()
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)

	// Simulate the refresh-tokens cache shape: Uncycled: true.
	uncycled := cacheManager.GetCache("refresh-tokens", cache.CacheOptions{Uncycled: true})
	require.NoError(t, uncycled.Set(ctx, "rt-id", "rt-payload"))
	val, found, _, err := uncycled.Get(ctx, "rt-id")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "rt-payload", val)

	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)
	hh.SetHost(ctx, &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		BrandName:   "KDex",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	// Post-SetHost: refresh-tokens cache content must still be reachable.
	val, found, _, err = uncycled.Get(ctx, "rt-id")
	require.NoError(t, err)
	assert.True(t, found, "Uncycled cache must survive SetHost — refresh tokens were being evicted on every config-change reconcile")
	assert.Equal(t, "rt-payload", val)

	// Sanity: a second SetHost (the routine reconcile case) also preserves.
	hh.SetHost(ctx, &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "fr",
		BrandName:   "KDex2",
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now())

	val, found, _, err = uncycled.Get(ctx, "rt-id")
	require.NoError(t, err)
	assert.True(t, found, "Uncycled cache must survive repeated SetHost calls")
	assert.Equal(t, "rt-payload", val)
}

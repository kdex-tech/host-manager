package host

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/entitlements"
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
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http")

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
	}, nil, nil, nil, nil, "", nil, nil, &auth.Exchanger{}, &auth.Config{}, "http")

	// 1. Initial Request
	req := httptest.NewRequest("GET", "/-/navigation/main/en/test", nil)
	w := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body1 := w.Body.String()
	assert.Contains(t, body1, "Test Page")

	// Verify it's in cache
	// Key format: nav:main:/test:en:anon (since no auth)
	cacheKey := fmt.Sprintf("%s:%s:%s:%s", "main", ph.Checksum(), language.English.String(), "anon")
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
	cacheKey2 := fmt.Sprintf("%s:%s:%s:%s", "main", ph.Checksum(), language.English.String(), userHash)

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

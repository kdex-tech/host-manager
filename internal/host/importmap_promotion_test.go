package host

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// The importmap of two packages builds: the shared module's integrity moves
// with the build, as it does when a packages image promotes.
const (
	importmapBuild1 = `{"imports":{"@x/shared":"/-/p/shared.js"},"integrity":{"/-/p/shared.js":"sha384-BUILD1"}}`
	importmapBuild2 = `{"imports":{"@x/shared":"/-/p/shared.js"},"integrity":{"/-/p/shared.js":"sha384-BUILD2"}}`
)

const promotionTemplate = "<html><head>[[ .HeadScript ]]</head><body>[[ .Title ]]</body></html>"

func promotionPage(name, basePath, app string, generation int64) page.PageHandler {
	return page.PageHandler{
		Name: name,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: name,
			Paths: kdexv1alpha1.Paths{BasePath: basePath},
		},
		MainTemplate: promotionTemplate,
		PackageReferences: []kdexv1alpha1.PackageReference{
			{Name: app, Version: "1.0.0"},
			{Name: "@x/shared", Version: "1.0.0"},
		},
		Status: &kdexv1alpha1.KDexObjectStatus{ObservedGeneration: generation},
	}
}

// setPromotionHost applies the host as the internal host reconciler does:
// the importmap is passed in and also lands on status.attributes, so the
// cache generation moves with it.
func setPromotionHost(hh *HostHandler, importmap string, reconcileTime time.Time) {
	hh.SetHost(context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex"},
		&kdexv1alpha1.KDexObjectStatus{Attributes: map[string]string{"packages.importmap": importmap}},
		nil, nil, nil, importmap, nil, nil, &auth.Exchanger{}, &auth.Config{}, "http", nil, reconcileTime)
}

func getPage(hh *HostHandler, path, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	w := httptest.NewRecorder()
	hh.Mux.ServeHTTP(w, req)
	return w
}

// A packages promotion changes the host's importmap. A page whose own apps
// did not change (B) must serve the new importmap on the very first request
// after the promotion, never the previous build's integrity: the packages
// backend already serves the new build, so the browser refuses the old SRI
// and the page renders blank (#302).
func TestPagesServeCurrentImportmapAfterPromotion(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)

	hh.Pages.Set(promotionPage("page-a", "/a", "@x/app-x", 1))
	hh.Pages.Set(promotionPage("page-b", "/b", "@x/app-y", 1))
	// One reconcile time for both host applies: the second-granular
	// Last-Modified must not be what tells the two builds apart.
	reconcileTime := time.Now()
	setPromotionHost(hh, importmapBuild1, reconcileTime)
	hh.authChecker = &mockAuthChecker{}

	for _, path := range []string{"/a", "/b"} {
		w := getPage(hh, path, "")
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "sha384-BUILD1")
	}
	before := getPage(hh, "/b", "")
	etagBefore := before.Header().Get("ETag")
	require.NotEmpty(t, etagBefore)

	// Promote: app X changes (page A's own state moves), app Y does not.
	hh.Pages.Set(promotionPage("page-a", "/a", "@x/app-x", 2))
	setPromotionHost(hh, importmapBuild2, reconcileTime)
	hh.authChecker = &mockAuthChecker{}

	for _, path := range []string{"/a", "/b"} {
		w := getPage(hh, path, "")
		require.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "sha384-BUILD2", "%s serves the promoted importmap", path)
		assert.NotContains(t, w.Body.String(), "sha384-BUILD1", "%s never serves the previous build's integrity", path)
	}

	// A client holding page B from before the promotion must not be told
	// its copy is current.
	revalidated := getPage(hh, "/b", etagBefore)
	require.Equal(t, http.StatusOK, revalidated.Code, "the pre-promotion ETag is not current")
	assert.Contains(t, revalidated.Body.String(), "sha384-BUILD2")
	assert.NotEqual(t, etagBefore, revalidated.Header().Get("ETag"))
}

// Utility pages render the same head and are cached the same way, so a
// promotion must reach them too (#302).
func TestUtilityPagesServeCurrentImportmapAfterPromotion(t *testing.T) {
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

	render := func() string {
		hh.mu.RLock()
		defer hh.mu.RUnlock()
		return hh.renderUtilityPage(kdexv1alpha1.AnnouncementUtilityPageType, language.English, nil, &hh.Translations)
	}
	require.Contains(t, render(), "sha384-BUILD1")

	setPromotionHost(hh, importmapBuild2, reconcileTime)
	after := render()
	assert.Contains(t, after, "sha384-BUILD2")
	assert.NotContains(t, after, "sha384-BUILD1")
}

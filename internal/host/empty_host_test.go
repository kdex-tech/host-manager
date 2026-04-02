package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	G "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHostHandler_EmptyHostBehavior(t *testing.T) {
	g := G.NewGomegaWithT(t)
	ctx := context.Background()
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	spec := &kdexv1alpha1.KDexHostSpec{
		BrandName: "Test Brand",
	}
	status := &kdexv1alpha1.KDexObjectStatus{
		Conditions: []metav1.Condition{
			{
				Type:   string(kdexv1alpha1.ConditionTypeReady),
				Status: metav1.ConditionTrue,
			},
		},
	}

	// Set host with empty DefaultLang and no pages/functions
	hh.SetHost(ctx, spec, status, nil, nil, nil, "", nil, nil, nil, nil, "http", nil, time.Now())

	t.Run("GET / on empty host returns 404 instead of 400 when no utility page exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		
		// Should be 404 because no announcement page is registered.
		// If it were 400, it would mean GetLang failed due to empty default language.
		g.Expect(w.Code).To(G.Equal(http.StatusNotFound))
	})

	t.Run("GET / on empty host returns Announcement page when registered", func(t *testing.T) {
		hh.AddOrUpdateUtilityPage(page.PageHandler{
			Name: "announcement",
			UtilityPage: &kdexv1alpha1.KDexUtilityPageSpec{
				Type: kdexv1alpha1.AnnouncementUtilityPageType,
			},
			MainTemplate: "<html><body>ANNOUNCEMENT_CONTENT</body></html>",
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		
		g.Expect(w.Code).To(G.Equal(http.StatusOK))
		g.Expect(w.Body.String()).To(G.ContainSubstring("ANNOUNCEMENT_CONTENT"))
	})

	t.Run("GET /a/b/c on empty host returns 404 instead of 400", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/a/b/c", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		
		// Unmatched paths should be 404.
		g.Expect(w.Code).To(G.Equal(http.StatusNotFound))
	})

	t.Run("DesignMiddleware returns 404 when sniffer fails on unmatched path", func(t *testing.T) {
		sn := &sniffer.RequestSniffer{
			BasePathRegex: *regexp.MustCompile(`^/v1/`), // Only /v1/ paths allowed by sniffer
		}
		// Re-initialize with sniffer
		hh.SetHost(ctx, spec, status, nil, nil, nil, "", nil, nil, nil, nil, "http", sn, time.Now())

		req := httptest.NewRequest("GET", "/a/b/c/d", nil)
		w := httptest.NewRecorder()
		hh.ServeHTTP(w, req)
		
		// Should be 404 because /a/b/c/d didn't match any route AND sniffer failed (path doesn't start with /v1/).
		// Before the fix, this would return 400.
		g.Expect(w.Code).To(G.Equal(http.StatusNotFound))
	})
}

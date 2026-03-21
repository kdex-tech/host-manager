package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/entitlements"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	G "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

type pageMockAuthChecker struct {
	verifyFn          func(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error)
	getEntitlementsFn func(context.Context) entitlements.ParsedEntitlements
}

func (m *pageMockAuthChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}
func (m *pageMockAuthChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return true, nil
}
func (m *pageMockAuthChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	if m.getEntitlementsFn != nil {
		return m.getEntitlementsFn(ctx)
	}
	return entitlements.ParsedEntitlements{}
}
func (m *pageMockAuthChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}
func (m *pageMockAuthChecker) VerifyResourceParsedEntitlements(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(kind, name, ent, req, extra...)
	}
	return true, nil
}

func TestPageHandlerFunc_Redirection(t *testing.T) {
	cacheManager, _ := cache.NewCacheManager("", "", nil)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.host = &kdexv1alpha1.KDexHostSpec{}

	// Enable auth
	hh.authConfig = &auth.Config{
		AnonymousEntitlements: []string{"public"},
		ActivePair:            &keys.KeyPair{},
	}

	// Setup pages
	page1 := page.PageHandler{
		Name: "page1",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Page 1",
			Paths: kdexv1alpha1.Paths{BasePath: "/page1"},
			NavigationHints: &kdexv1alpha1.NavigationHints{
				Weight: resource.MustParse("10"),
			},
		},
		ParsedRequirements: &entitlements.ParsedRequirements{},
	}
	page2 := page.PageHandler{
		Name: "page2",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Page 2",
			Paths: kdexv1alpha1.Paths{BasePath: "/page2"},
			NavigationHints: &kdexv1alpha1.NavigationHints{
				Weight: resource.MustParse("20"),
			},
		},
		ParsedRequirements: &entitlements.ParsedRequirements{},
	}
	hh.Pages.Set(page1)
	hh.Pages.Set(page2)

	// Mock AuthChecker
	mock := &pageMockAuthChecker{
		verifyFn: func(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
			if name == "/page1" {
				return false, nil // Unauthorized for page1
			}
			return true, nil // Authorized for page2
		},
	}
	hh.authChecker = mock

	handler := hh.pageHandlerFunc(page1, &hh.Translations)

	t.Run("Redirect to first authorized page when unauthenticated", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		req := httptest.NewRequest("GET", "/page1", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
		g.Expect(w.Header().Get("Location")).To(G.Equal("/page2"))
	})

	t.Run("Redirect to first authorized page when authenticated", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		req := httptest.NewRequest("GET", "/page1", nil)
		// Simulate authenticated user
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "user1"}))
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
		g.Expect(w.Header().Get("Location")).To(G.Equal("/page2"))
	})

	t.Run("Redirect to login when unauthenticated and no authorized pages", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}
		// Ensure no pages are authorized
		mock.verifyFn = func(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
			return false, nil
		}

		req := httptest.NewRequest("GET", "/page1", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
		g.Expect(w.Header().Get("Location")).To(G.Equal("/-/login?return=%2Fpage1"))
	})

	t.Run("Return 404 when no authorized pages and no login page", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)
		mock.verifyFn = func(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
			return false, nil // Unauthorized for everything
		}

		req := httptest.NewRequest("GET", "/page1", nil)
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "user1"}))
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusNotFound))
	})
}

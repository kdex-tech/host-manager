package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	G "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
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
func (m *pageMockAuthChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}
func (m *pageMockAuthChecker) VerifyResourceParsedEntitlements(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(kind, name, ent, req, extra...)
	}
	return true, nil
}

// newPage is a page whose gate the mock checker can decide on by basePath.
func newPage(name, label, basePath string) page.PageHandler {
	return page.PageHandler{
		Name: name,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: label,
			Paths: kdexv1alpha1.Paths{BasePath: basePath},
		},
		ParsedRequirements: &entitlements.ParsedRequirements{},
	}
}

// gatedHostFixture builds a host with auth enabled and a login utility page
// registered, serving the given pages. Callers set hh.authChecker to decide
// which of them the gate lets through.
func gatedHostFixture(pages ...page.PageHandler) *HostHandler {
	cacheManager, _ := cache.NewCacheManager("", "", nil)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.host = &kdexv1alpha1.KDexHostSpec{}
	hh.authConfig = &auth.Config{
		AnonymousEntitlements: []string{"public"},
		ActivePair:            &keys.KeyPair{},
	}
	for _, p := range pages {
		hh.Pages.Set(p)
	}
	hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}
	return hh
}

func denyPath(basePath string) *pageMockAuthChecker {
	return &pageMockAuthChecker{
		verifyFn: func(_ string, name string, _ entitlements.ParsedEntitlements, _ entitlements.ParsedRequirements, _ ...string) (bool, error) {
			return name != basePath, nil
		},
	}
}

// An anonymous caller who fails a page's gate must be sent to the login page,
// not to whatever else they happen to be allowed to see. Any host with a
// non-empty anonymousEntitlements list has authorized pages for every caller,
// so a cascade that tries "first authorized page" first can never reach the
// login branch in production. See kdex-tech/host-manager#184.
func TestPageHandlerFunc_UnauthenticatedPrefersLoginOverAuthorizedPage(t *testing.T) {
	g := G.NewGomegaWithT(t)

	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	req := httptest.NewRequest("GET", "/developer-keys", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	hh.pageHandlerFunc(gated, &hh.Translations)(w, req)

	g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
	g.Expect(w.Header().Get("Location")).To(G.Equal("/-/login?return=%2Fdeveloper-keys"))
}

// The return trip must carry the whole request target, not just its path.
// Returning a user to /search after they asked for /search?q=foo silently
// drops what they came for. SafeReturnPath already round-trips a query
// string (see TestSafeReturnPath), so the value is safe to hand back.
func TestPageHandlerFunc_LoginReturnPreservesQueryString(t *testing.T) {
	g := G.NewGomegaWithT(t)

	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated)
	hh.authChecker = denyPath("/developer-keys")

	req := httptest.NewRequest("GET", "/developer-keys?tab=tokens&page=2", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()

	hh.pageHandlerFunc(gated, &hh.Translations)(w, req)

	g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
	g.Expect(w.Header().Get("Location")).To(
		G.Equal("/-/login?return=%2Fdeveloper-keys%3Ftab%3Dtokens%26page%3D2"))
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
				Weight: ptr.To(resource.MustParse("10")),
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
				Weight: ptr.To(resource.MustParse("20")),
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

	// No login utility page is registered until the third subtest below.
	// Per the denial contract, an anonymous caller never discovers -- their
	// fix is logging in, not being sent elsewhere -- so with nothing to send
	// them to, they get the contract's 401. Where a login page IS configured
	// the login redirect wins instead -- see
	// TestPageHandlerFunc_UnauthenticatedPrefersLoginOverAuthorizedPage.
	t.Run("401 rather than discovery when unauthenticated", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		req := httptest.NewRequest("GET", "/page1", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusUnauthorized))
		g.Expect(w.Header().Get("WWW-Authenticate")).NotTo(G.BeEmpty())
		g.Expect(w.Header().Get("Location")).To(G.BeEmpty())
	})

	// The contract's discovery rendering: an authenticated caller who fails
	// page1's gate is sent to the first page it can reach, carrying
	// ?denied=<path> so the destination can say what was denied. The
	// redirect only fires for a caller that can render HTML (hence the
	// explicit Accept header) and is marked no-store so a cached denial
	// can't outlive the grant that fixes it.
	t.Run("Redirect to first authorized page when authenticated", func(t *testing.T) {
		hh.SetPageDenialMode(PageDenialDiscover)
		g := G.NewGomegaWithT(t)
		req := httptest.NewRequest("GET", "/page1", nil)
		req.Header.Set("Accept", "text/html")
		// Simulate authenticated user
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "user1"}))
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
		g.Expect(w.Header().Get("Location")).To(G.Equal("/page2?denied=%2Fpage1"))
		g.Expect(w.Header().Get("Cache-Control")).To(G.Equal("no-store"))
	})

	t.Run("Redirect to login when unauthenticated and no authorized pages", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}
		// Ensure no pages are authorized
		mock.verifyFn = func(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
			return false, nil
		}

		req := httptest.NewRequest("GET", "/page1", nil)
		req.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusSeeOther))
		g.Expect(w.Header().Get("Location")).To(G.Equal("/-/login?return=%2Fpage1"))
	})

	// The retired posture: an authenticated caller denied on every page, with
	// no login page to fall back to, no longer gets the anti-enumeration
	// 404 -- the denial contract replaced it with 403 (NoIdentity, the
	// discovery fallback's floor). NoIdentity carries no challenge: naming a
	// scope would imply a scope would fix it.
	t.Run("403 rather than 404 when no authorized pages and no login page", func(t *testing.T) {
		g := G.NewGomegaWithT(t)
		delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)
		mock.verifyFn = func(kind string, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error) {
			return false, nil // Unauthorized for everything
		}

		req := httptest.NewRequest("GET", "/page1", nil)
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "user1"}))
		w := httptest.NewRecorder()

		handler(w, req)

		g.Expect(w.Code).To(G.Equal(http.StatusForbidden))
		g.Expect(w.Header().Get("WWW-Authenticate")).To(G.BeEmpty())
	})
}

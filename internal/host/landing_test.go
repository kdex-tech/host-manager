package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// denyPaths denies every listed basePath and allows the rest — a superset of
// denyPath (which denies exactly one). Used to model a caller who can reach
// some landing candidates but not others.
func denyPaths(basePaths ...string) *pageMockAuthChecker {
	denied := map[string]bool{}
	for _, p := range basePaths {
		denied[p] = true
	}
	return &pageMockAuthChecker{
		verifyFn: func(_ string, name string, _ entitlements.ParsedEntitlements, _ entitlements.ParsedRequirements, _ ...string) (bool, error) {
			return !denied[name], nil
		},
	}
}

// List order wins over navigation/alpha order: /home is listed first and is
// accessible, so it wins even though /dashboard sorts first alphabetically
// (which is what firstAuthorizedPage would have picked).
func TestDiscoverLanding_ListOrderBeatsNavOrder(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated,
		newPage("home", "Home", "/home"),
		newPage("dash", "Dash", "/dashboard"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home", "/dashboard"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/home?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /home (list order beats alpha-first /dashboard)", got)
	}
}

// The first list entry the caller cannot reach is skipped; the next accessible
// entry wins.
func TestDiscoverLanding_SkipsInaccessibleEntry(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated,
		newPage("home", "Home", "/home"),
		newPage("dash", "Dash", "/dashboard"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home", "/dashboard"}}
	hh.authChecker = denyPaths("/developer-keys", "/home")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/dashboard?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /dashboard (first accessible after skipping /home)", got)
	}
}

// An entry naming no existing page is skipped; with nothing left in the list
// the host falls back to firstAuthorizedPage.
func TestDiscoverLanding_UnknownEntryFallsBackToFirstAuthorized(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/nope"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want firstAuthorizedPage fallback /pricing", got)
	}
}

// Unset list ⇒ behavior identical to today (firstAuthorizedPage).
func TestDiscoverLanding_UnsetListUsesFirstAuthorized(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	// hh.host.Auth is nil (gatedHostFixture leaves it unset).
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want unchanged /pricing", got)
	}
}

// Scope boundary: in Forbid mode the list is never consulted; the caller gets
// a 403, same as today.
func TestDiscoverLanding_ForbidModeIgnoresList(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("home", "Home", "/home"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialForbid)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (forbid mode never consults the list)", w.Code)
	}
}

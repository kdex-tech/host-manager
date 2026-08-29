package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// authedReq returns a request carrying an auth context -- a caller who
// presented a credential. Anonymity is what separates 401 from 403, and
// anonymous entitlements live inside the checker rather than the context,
// so the presence of the context is the whole test.
func authedReq(method, target, accept string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", accept)
	return req.WithContext(
		auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "alice"}))
}

func anonReq(method, target, accept string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", accept)
	return req
}

// An anonymous API client asking for a gated page gets the contract's 401,
// not a 303 to a login form it cannot render.
func TestPageGateAnonymousNonHTMLGets401(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q; an API client must not be sent to a login form", loc)
	}
}

// A browser asking for the same page still gets the login redirect: that is
// the HTML rendering of Unauthenticated, and #184 put it here deliberately.
func TestPageGateAnonymousHTMLStillRedirectsToLogin(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/-/login?return=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want the login redirect with a return trip", got)
	}
}

// An anonymous caller on a host with NO login page has nothing to redirect
// to, so the contract's 401 is the answer even for a browser.
func TestPageGateAnonymousNoLoginPageGets401(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when there is no login page to send them to", w.Code)
	}
}

// An authenticated, under-entitled caller gets 403 -- no redirect, no 404.
// Task 6 makes the HTML rendering of this switchable; the non-HTML answer
// stays 403 in every mode.
func TestPageGateAuthenticatedUnderEntitledGets403(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("NoIdentity carries no challenge: naming a scope would imply a scope would fix it")
	}
}

// discover mode: a browser is sent to a page it can reach, and told which
// page it was denied.
func TestPageGateDiscoverModeRedirectsHTMLWithDeniedMarker(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /pricing?denied=%%2Fdeveloper-keys", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store: a cached denial outlives the grant that fixes it", got)
	}
}

// The knob is about the HTML rendering only.
func TestPageGateDiscoverModeStill403sNonHTML(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the knob never changes what an API client sees", w.Code)
	}
}

// One hop, maximum. firstAuthorizedPage can return a page that itself denies
// -- the navigation walk and the page render are separate checks -- so a
// request already carrying denied= renders the 403 rather than looping.
func TestPageGateDiscoverModeDoesNotLoop(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(
		w, authedReq("GET", "/developer-keys?denied=%2Fsomething", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 on a request already carrying denied=", w.Code)
	}
}

// Nothing to discover -> the 403 page, which is the floor both modes stand on.
func TestPageGateDiscoverModeFallsBackTo403(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated) // the only page is the denied one
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when no accessible page exists", w.Code)
	}
}

// forbid mode: the truthful 403 in the browser too, and no redirect at all.
func TestPageGateForbidModeReturns403ToHTML(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialForbid)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect in forbid mode", loc)
	}
}

// Discovery is only ever a rendering of FORBIDDEN. An anonymous caller is
// UNAUTHENTICATED -- the fix is logging in, not being sent elsewhere.
func TestPageGateDiscoverModeNeverDiscoversForAnonymous(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)
	delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: anonymous never discovers", w.Code)
	}
}

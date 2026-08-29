package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A present-but-subject-less AuthContext is REACHABLE from a real credential
// path, which is why these gate-level tests exist rather than a note saying it
// cannot happen. See TestSubjectlessTokenIsReachableFromLocalLogin
// (internal/auth/subjectless_credential_test.go): a credential lookup that
// resolves a subject without a `sub` claim -- a Secret keyed only by `email`,
// or an http-lookup backend answering `{"ok":true,"claims":{}}` -- mints a
// host-audience JWT whose `sub` is the empty string, because
// jwt.MapClaims.GetSubject returns ("", nil) for a MISSING key and
// sign.Signer.Project copies that straight into the token. WithAuthentication
// then validates it (only iss and aud are required) and injects it.
//
// Both shapes the wire can produce are covered: the claim absent, and the claim
// present but empty.
var subjectlessContexts = map[string]auth.AuthContext{
	"no sub claim": {"aud": "https://example.test"},
	"empty sub":    {"sub": ""},
}

// subjectlessReq is a caller who DID present a credential whose validated
// claims name nobody.
func subjectlessReq(method, target, accept string, ac auth.AuthContext) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", accept)
	return req.WithContext(auth.SetAuthContext(req.Context(), ac))
}

// denial.Classify calls a subject-less caller Unauthenticated, and that
// decision was pinned only at the decision. This pins it at the PAGE gate, in
// both Accept shapes.
//
// The HTML row is the one that had a third answer nobody named: page.go
// branches on `outcome == denial.Unauthenticated` BEFORE the 401, so a
// subject-less caller accepting HTML on a host with a login page used to get a
// 303 to /-/login -- neither the 401 nor the discovery redirect. That arm can
// LOOP (the login form is where the subject-less credential comes from), so it
// is now bounded: the login redirect is for a caller who presented NO
// credential.
func TestPageGateSubjectlessCallerGets401InBothAcceptShapes(t *testing.T) {
	for name, ac := range subjectlessContexts {
		for _, accept := range []string{"application/json", "text/html"} {
			t.Run(name+"/"+accept, func(t *testing.T) {
				gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
				hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
				hh.authChecker = denyPath("/developer-keys")

				w := httptest.NewRecorder()
				hh.pageHandlerFunc(gated, &hh.Translations)(
					w, subjectlessReq("GET", "/developer-keys", accept, ac))

				if w.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", w.Code)
				}
				if w.Header().Get("WWW-Authenticate") == "" {
					t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Fatalf("Location = %q; a caller whose credential names nobody has "+
						"already been to the login form -- sending it back is the loop", loc)
				}
			})
		}
	}
}

// The bound removes only the LOGIN redirect for a subject-less caller. A
// genuinely anonymous browser -- no credential at all, nothing to loop on --
// still gets the login page, which is #184's ordering and the HTML rendering of
// Unauthenticated.
func TestPageGateAnonymousStillRedirectsAfterTheSubjectlessBound(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303: the bound must not cost the anonymous caller its login page", w.Code)
	}
}

// Discovery is a rendering of FORBIDDEN only. A subject-less caller classifies
// as Unauthenticated, so it must not be sent wandering to some page it happens
// to be allowed to see either -- the 401 is the answer in both knob modes.
func TestPageGateSubjectlessNeverDiscovers(t *testing.T) {
	for _, mode := range []PageDenialMode{PageDenialDiscover, PageDenialForbid} {
		t.Run(string(mode), func(t *testing.T) {
			gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
			hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
			hh.authChecker = denyPath("/developer-keys")
			hh.SetPageDenialMode(mode)
			delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)

			w := httptest.NewRecorder()
			hh.pageHandlerFunc(gated, &hh.Translations)(
				w, subjectlessReq("GET", "/developer-keys", "text/html", auth.AuthContext{"sub": ""}))

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Fatalf("Location = %q, want no redirect", loc)
			}
		})
	}
}

// The FUNCTION PROXY gate, same caller. It negotiates nothing -- unwrap owns
// presentation -- so the answer is identical in both Accept shapes, and that
// invariant is worth asserting rather than assuming.
func TestProxyGateSubjectlessCallerGets401Challenge(t *testing.T) {
	for name, ac := range subjectlessContexts {
		for _, accept := range []string{"*/*", "text/html"} {
			t.Run(name+"/"+accept, func(t *testing.T) {
				h := newOAuth2ProtectedHandler(t, "dev.knowdrive.ai", "/api/v1/mcp")

				req := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader("{}"))
				req.Host = "dev.knowdrive.ai"
				req.Header.Set("Accept", accept)
				req = req.WithContext(auth.SetAuthContext(req.Context(), ac))

				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)

				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401: a credential that names nobody cannot "+
						"clear an identity gate keyed on who the caller is, so 403 would be "+
						"a denial no credential could ever fix", rr.Code)
				}
				want := `resource_metadata="https://dev.knowdrive.ai/.well-known/oauth-protected-resource/api/v1/mcp"`
				if got := rr.Header().Get("WWW-Authenticate"); !strings.Contains(got, want) {
					t.Fatalf("WWW-Authenticate = %q, want it to carry %s", got, want)
				}
			})
		}
	}
}

// The non-oauth2 half of the same row: a bearer-only function answers 401 with
// a realm challenge, not the 403 the pre-fix Classify produced.
func TestProxyGateSubjectlessCallerGets401RealmOnBearerOnlyFunction(t *testing.T) {
	h := newBearerOnlyHandler(t, "dev.knowdrive.ai", "/v1/admin")

	req := httptest.NewRequest(http.MethodGet, "/v1/admin", nil)
	req.Host = "dev.knowdrive.ai"
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": ""}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	got := rr.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer realm="`) {
		t.Fatalf("challenge = %q, want a Bearer realm challenge", got)
	}
	if strings.Contains(got, "error=") {
		t.Fatalf("challenge = %q; RFC 6750 3.1 omits error= when the caller is treated as "+
			"having presented no usable credential", got)
	}
}

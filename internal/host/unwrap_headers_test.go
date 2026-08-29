package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth/denial"
	"github.com/kdex-tech/host-manager/internal/page"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A handler that denies the way the denial contract requires: through the
// host's own gate helper, which records the challenge as host-authored.
// unwrap must not destroy that challenge on its way to rendering the HTML
// error page.
func denyingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeDenial(w, r, denial.Opts{
			Outcome: denial.Unauthenticated,
			Issuer:  "https://example.test",
		})
		w.Header().Set("Content-Length", "999") // a proxy-set header surviving past the denial
	})
}

// backendChallengeHandler impersonates a KDexFunction backend whose response
// ReverseProxy copied through: it writes WWW-Authenticate straight onto the
// header map, with no host provenance behind it.
func backendChallengeHandler(challenge string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", challenge)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func TestUnwrapPreservesChallengeForHTMLClients(t *testing.T) {
	// A real handler, not &HostHandler{}: unwrap's HTML branch renders through
	// serveError, which locks hh.mu and reads hh.Translations.
	hh := gatedHostFixture()

	// gatedHostFixture only registers a login utility page. Without an
	// ErrorUtilityPageType handler, serveError's renderUtilityPage call
	// returns "" and it falls back to calling net/http's http.Error itself
	// (internal/host/host.go) -- which deletes Content-Length as its own
	// first action, independent of unwrap's delete loop. That would make
	// the Content-Length assertion below pass even if unwrap's own wipe
	// were removed. Registering a real error page routes serveError
	// through its direct w.Header().Set/WriteHeader/Write path instead, so
	// the assertion actually exercises unwrap's delete loop.
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name:         "err",
		MainTemplate: "<html><body>{{ .Title }}</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/gated", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	denyingHandler().ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://example.test"` {
		t.Fatalf("WWW-Authenticate = %q; a 401 without a challenge violates RFC 7235", got)
	}
	if got := rr.Header().Get("Content-Length"); got == "999" {
		t.Fatal("stale Content-Length survived; unwrap must still drop it")
	}
}

func TestUnwrapPreservesChallengeForNonHTMLClients(t *testing.T) {
	hh := gatedHostFixture()

	req := httptest.NewRequest(http.MethodGet, "/gated", nil)
	req.Header.Set("Accept", "*/*")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	denyingHandler().ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://example.test"` {
		t.Fatalf("WWW-Authenticate = %q, want the challenge preserved", got)
	}
}

// The exemption that lets a challenge through unwrap is reasoned entirely
// about host-authored challenges. Written as an unconditional read-back of
// the header map it would also forward a PROXIED BACKEND's challenge --
// errorResponseWriter shares its header map with ReverseProxy's copied
// upstream headers -- and a backend answering
// `401 WWW-Authenticate: Basic realm="Sign in"` would then make the browser
// render a native credential prompt on the HOST's origin. That is a phishing
// primitive the unconditional header wipe used to suppress.
func TestUnwrapDropsBackendChallengeForHTMLClients(t *testing.T) {
	hh := gatedHostFixture()
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name:         "err",
		MainTemplate: "<html><body>{{ .Title }}</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backend", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	backendChallengeHandler(`Basic realm="Sign in"`).ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q; a backend's challenge must not reach a browser "+
			"on the host's origin", got)
	}
}

// The other half of the same rule: a host-authored Bearer challenge on the
// SAME response shape still reaches the client. Without this the fix would be
// indistinguishable from deleting the exemption.
func TestUnwrapKeepsHostAuthoredChallengeForHTMLClients(t *testing.T) {
	hh := gatedHostFixture()
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name:         "err",
		MainTemplate: "<html><body>{{ .Title }}</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backend", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	// The backend answers first (as it would through ReverseProxy); the host
	// gate then denies through the contract. Only the host's value survives.
	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Sign in"`)
		writeDenial(w, r, denial.Opts{
			Outcome: denial.Unauthenticated,
			Issuer:  "https://example.test",
		})
	}).ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://example.test"` {
		t.Fatalf("WWW-Authenticate = %q, want the host-authored Bearer challenge", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store to survive the wipe too", got)
	}
}

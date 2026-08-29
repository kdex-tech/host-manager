package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/page"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A handler that denies the way the denial contract requires: a status and a
// challenge. unwrap must not destroy the challenge on its way to rendering
// the HTML error page.
func denyingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://example.test"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		w.Header().Set("Content-Length", "999") // a proxy-set header surviving past the denial
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

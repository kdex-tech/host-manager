package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A handler that denies the way the denial contract requires: a status and a
// challenge. unwrap must not destroy the challenge on its way to rendering
// the HTML error page.
func denyingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://example.test"`)
		w.Header().Set("Content-Length", "999") // the stale header unwrap exists to drop
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func TestUnwrapPreservesChallengeForHTMLClients(t *testing.T) {
	// A real handler, not &HostHandler{}: unwrap's HTML branch renders through
	// serveError, which locks hh.mu and reads hh.Translations.
	hh := gatedHostFixture()

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

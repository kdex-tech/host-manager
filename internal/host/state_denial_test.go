package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// /-/state/ is the purest Unauthenticated row in the repo: no credential was
// presented at all. It answered a bare 401, which violates RFC 7235 and the
// contract's own "every 401 carries a challenge" constraint. Mirrors
// TestApitokenRevokeAnonymousGets401WithChallenge.
func TestStateAnonymousGets401WithChallenge(t *testing.T) {
	hh := &HostHandler{
		scheme: "https",
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"dev.knowdrive.ai"}},
		},
	}

	mux := http.NewServeMux()
	hh.stateHandler(mux, map[string]ko.PathInfo{})

	req := httptest.NewRequest(http.MethodGet, "/-/state/", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req) // no auth context

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an anonymous caller", rr.Code)
	}
	got := rr.Header().Get("WWW-Authenticate")
	if got == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
	if !strings.HasPrefix(got, `Bearer realm="https://dev.knowdrive.ai"`) {
		t.Fatalf("challenge = %q, want a Bearer realm challenge naming the issuer", got)
	}
	if strings.Contains(got, "error=") {
		t.Fatalf("challenge = %q; RFC 6750 3.1 omits error= when no credentials were sent", got)
	}
}

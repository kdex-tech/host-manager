package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
)

// newTestHostHandlerWithDCR creates a minimal HostHandler with DCR enabled,
// mirroring newTestHostHandlerWithDomain from oauth2_resources_test.go.
func newTestHostHandlerWithDCR(t *testing.T, domain string, schemes []string) *HostHandler {
	t.Helper()
	ttl := time.Hour
	cm, err := cache.NewCacheManager("", domain, &ttl)
	if err != nil {
		t.Fatalf("NewCacheManager: %v", err)
	}
	hh := newTestHostHandlerWithDomain(t, domain)
	hh.authConfig = &auth.Config{
		DCR: auth.DCRConfig{
			Enabled:                true,
			ClientTTL:              ttl,
			MaxClients:             100,
			AllowedRedirectSchemes: schemes,
		},
		DCRStore: dcr.NewStore(cm, domain, ttl, 100),
	}
	return hh
}

// postRegister builds a fresh mux via hh.registerHandler, issues a POST to
// /-/oauth/register with application/json body, and returns the recorder.
func postRegister(t *testing.T, hh *HostHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	hh.registerHandler(mux, nil)
	req := httptest.NewRequest("POST", "/-/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestRegisterRejectsNonHTTPSRedirect(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	rr := postRegister(t, hh, `{"redirect_uris":["http://evil.example/cb"]}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

func TestRegisterAcceptsLoopbackAndForcesPublicPKCE(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	rr := postRegister(t, hh, `{"redirect_uris":["http://127.0.0.1:33418/cb"],"client_name":"Claude"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"client_id"`) || !strings.Contains(body, `"token_endpoint_auth_method":"none"`) {
		t.Fatalf("missing client_id / public auth method: %s", body)
	}
}

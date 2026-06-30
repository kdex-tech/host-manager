package host

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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

// loopbackBody is a valid registration payload used by limiter tests.
const loopbackBody = `{"redirect_uris":["http://127.0.0.1:33418/cb"],"client_name":"Claude"}`

// postRegisterFrom is like postRegister but lets the caller set RemoteAddr
// / X-Forwarded-For so per-IP behaviour can be exercised.
func postRegisterFrom(t *testing.T, hh *HostHandler, body, remoteAddr, xff string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	hh.registerHandler(mux, nil)
	req := httptest.NewRequest("POST", "/-/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestRegisterHappyPathUnderLimit ensures the limiter does not break the
// 201 happy path for a single registration. A fresh HostHandler (and thus
// a fresh limiter) is used so prior tests cannot drain the bucket.
func TestRegisterHappyPathUnderLimit(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	rr := postRegister(t, hh, loopbackBody)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
}

// TestRegisterGlobalRateLimitReturns429 verifies the authoritative,
// non-spoofable global limiter returns 429 + Retry-After once exceeded,
// even as the apparent client IP rotates (so per-IP rotation can't evade
// it).
func TestRegisterGlobalRateLimitReturns429(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	// Force the limiter to exist now and shrink the global burst so the
	// test is fast and deterministic. Per-IP limiter is left generous and
	// each request uses a unique IP, so the global limiter is the only gate.
	hh.registerLimiter = newRegisterLimiter(0)
	hh.registerLimiterOnce.Do(func() {}) // mark done so registerHandler won't reinit

	const burst = globalRegisterBurst
	var got429 bool
	for i := 0; i < burst+5; i++ {
		ip := "203.0.113." + strconv.Itoa(i+1) // unique per request
		rr := postRegisterFrom(t, hh, loopbackBody, ip+":4444", "")
		if rr.Code == http.StatusTooManyRequests {
			got429 = true
			if ra := rr.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("429 response missing Retry-After header")
			}
			if !strings.Contains(rr.Body.String(), `"error"`) {
				t.Fatalf("429 body not RFC7591-shaped: %s", rr.Body.String())
			}
			break
		}
	}
	if !got429 {
		t.Fatalf("expected a 429 after exceeding global burst of %d", burst)
	}
}

// TestRegisterPerIPLimitedIndependently verifies the best-effort per-IP
// limiter throttles a single IP while a different IP is still admitted
// (both well under the global burst).
func TestRegisterPerIPLimitedIndependently(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	hh.registerLimiter = newRegisterLimiter(0)
	hh.registerLimiterOnce.Do(func() {})

	// Drain IP A's per-IP bucket (burst = perIPRegisterBurst).
	var ipARejected bool
	for i := 0; i < perIPRegisterBurst+2; i++ {
		rr := postRegisterFrom(t, hh, loopbackBody, "198.51.100.10:5555", "")
		if rr.Code == http.StatusTooManyRequests {
			ipARejected = true
			if ra := rr.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("per-IP 429 response missing Retry-After header")
			}
			break
		}
	}
	if !ipARejected {
		t.Fatalf("expected IP A to be per-IP rate limited after %d requests", perIPRegisterBurst)
	}

	// A different IP must still be admitted (its bucket is independent and
	// the global bucket still has tokens).
	rrB := postRegisterFrom(t, hh, loopbackBody, "198.51.100.20:5555", "")
	if rrB.Code != http.StatusCreated {
		t.Fatalf("IP B status = %d, want 201; body=%s", rrB.Code, rrB.Body.String())
	}
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

// TestRegisterAcceptsPrivateUseScheme covers RFC 8252 §7.1 native-app
// private-use redirects: a reverse-DNS (dotted) custom scheme registers
// successfully when "private-use" is enabled on the host.
func TestRegisterAcceptsPrivateUseScheme(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "private-use"})
	rr := postRegister(t, hh, `{"redirect_uris":["ai.knowdrive.interviewer://oauth"],"client_name":"Interviewer"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
	}
}

// TestRegisterRejectsBareSingleLabelPrivateUseScheme pins the §7.1 SHOULD that
// private-use schemes be reverse-DNS: a bare single-label scheme (no dot) is
// the most squat-prone form and must be rejected even when private-use is on.
func TestRegisterRejectsBareSingleLabelPrivateUseScheme(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "private-use"})
	rr := postRegister(t, hh, `{"redirect_uris":["myapp://cb"],"client_name":"Squatter"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

// TestRegisterRejectsPrivateUseSchemeWhenNotEnabled ensures the scheme is
// opt-in: a dotted custom scheme is rejected when the host does not list
// "private-use".
func TestRegisterRejectsPrivateUseSchemeWhenNotEnabled(t *testing.T) {
	hh := newTestHostHandlerWithDCR(t, "dev.knowdrive.ai", []string{"https", "http-loopback"})
	rr := postRegister(t, hh, `{"redirect_uris":["ai.knowdrive.interviewer://oauth"],"client_name":"Interviewer"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}

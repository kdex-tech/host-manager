package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHostHandler_OriginAllowed pins the login-CSRF defense for
// kdex-tech/host-manager#163. State-changing POSTs (login/logout) must reject a
// cross-origin submission: login CSRF works even under SameSite=Lax because the
// attacker supplies their OWN credentials and the browser stores the resulting
// Set-Cookie. originAllowed enforces an Origin check (Referer fallback) against
// the host's configured domains. Both headers absent → allowed (a non-browser
// client, which carries no ambient-credential CSRF risk); this keeps same-origin
// programmatic login (the signup app's post-claim-invite auto-login) working,
// since a same-origin fetch always sends a matching Origin.
func TestHostHandler_OriginAllowed(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "app.example")

	tests := []struct {
		name    string
		origin  string // "" = header absent
		referer string // "" = header absent
		want    bool
	}{
		{"same-origin Origin", "https://app.example", "", true},
		{"cross-origin Origin", "https://evil.example", "", false},
		{"Origin outranks a same-origin Referer", "https://evil.example", "https://app.example/x", false},
		{"no Origin, same-origin Referer", "", "https://app.example/some/path", true},
		{"no Origin, cross-origin Referer", "", "https://evil.example/x", false},
		{"no Origin, no Referer (non-browser)", "", "", true},
		{"malformed Origin", "://nonsense", "", false},
		{"same host, wrong scheme", "http://app.example", "", false},
		{"same host with an extra label (suffix attack)", "https://app.example.evil.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/-/login", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			if got := hh.originAllowed(req); got != tt.want {
				t.Fatalf("originAllowed(origin=%q, referer=%q) = %v, want %v", tt.origin, tt.referer, got, tt.want)
			}
		})
	}
}

// TestLoginPost_RejectsCrossOrigin proves LoginPost wires the CSRF guard: a
// cross-origin submission is rejected with 403 before any credential exchange,
// and no session cookie is issued (#163).
func TestLoginPost_RejectsCrossOrigin(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "app.example")
	req := httptest.NewRequest(http.MethodPost, "/-/login",
		strings.NewReader("username=attacker@evil.example&password=pw&return=/mcp"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()

	hh.LoginPost(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-origin login", rr.Code)
	}
	if cookies := rr.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("a rejected cross-origin login must set no cookie, got %d", len(cookies))
	}
}

// TestLogoutPost_RejectsCrossOrigin proves LogoutPost wires the same guard
// (forced-logout CSRF, #163).
func TestLogoutPost_RejectsCrossOrigin(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "app.example")
	req := httptest.NewRequest(http.MethodPost, "/-/logout", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()

	hh.LogoutPost(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a cross-origin logout", rr.Code)
	}
}

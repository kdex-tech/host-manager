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

// withUserNavigation adds the fetch metadata a browser sends when the user
// submits a form in a top-level page; explicit keys in h win.
func withUserNavigation(h map[string]string) map[string]string {
	out := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-User": "?1"}
	for k, v := range h {
		out[k] = v
	}
	return out
}

func TestConsentOriginAllowed(t *testing.T) {
	domains := []string{"app.example"}
	mk := func(h map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/-/oauth/consent", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	for name, tt := range map[string]struct {
		headers map[string]string
		want    bool
	}{
		"same-origin Origin":       {map[string]string{"Origin": "https://app.example"}, true},
		"same-origin Referer":      {map[string]string{"Referer": "https://app.example/-/oauth/authorize"}, true},
		"no Origin and no Referer": {nil, false},
		"null Origin":              {map[string]string{"Origin": "null"}, false},
		"cross-origin Origin":      {map[string]string{"Origin": "https://evil.example"}, false},
		"same-site fetch metadata": {map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-site"}, false},
		"none fetch metadata": {map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "none"}, false},
		"foreign Origin outranks same-origin Referer": {map[string]string{
			"Origin": "https://evil.example", "Referer": "https://app.example/x"}, false},
		"null Origin outranks same-origin Referer": {map[string]string{
			"Origin": "null", "Referer": "https://app.example/x"}, false},
		"cross-site fetch metadata": {map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "cross-site"}, false},
		"same-origin fetch metadata": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin"}), true},
		"same-origin fetch metadata with Referer": {withUserNavigation(map[string]string{
			"Referer": "https://app.example/-/oauth/authorize", "Sec-Fetch-Site": "same-origin"}), true},
		"same-origin fetch metadata without mode, dest or user": {map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin"}, false},
		"same-origin fetch()": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}), false},
		"same-origin no-cors fetch()": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "no-cors"}), false},
		"same-origin form into an iframe": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "iframe"}), false},
		"same-origin scripted form.submit()": {map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin",
			"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, false},
		"same-origin user activation ?0": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-User": "?0"}), false},
		"user navigation does not rescue a cross-site request": {withUserNavigation(map[string]string{
			"Origin": "https://app.example", "Sec-Fetch-Site": "cross-site"}), false},
		"user navigation does not rescue a foreign Origin": {withUserNavigation(map[string]string{
			"Origin": "https://evil.example", "Sec-Fetch-Site": "same-origin"}), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := consentOriginAllowed(mk(tt.headers), "https", domains); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHostHandler_OriginAllowed_Ports pins that /-/login matches ports strictly:
// a domain without a port accepts only the scheme's default port, and a domain
// that names a port requires it.
func TestHostHandler_OriginAllowed_Ports(t *testing.T) {
	for _, tt := range []struct {
		name, domain, origin string
		want                 bool
	}{
		{"non-default port refused", "app.example", "https://app.example:8443", false},
		{"default port allowed", "app.example", "https://app.example:443", true},
		{"domain with port matches exactly", "app.example:8443", "https://app.example:8443", true},
		{"domain with port refuses bare host", "app.example:8443", "https://app.example", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hh := newTestHostHandlerWithDomain(t, tt.domain)
			req := httptest.NewRequest(http.MethodPost, "/-/login", nil)
			req.Header.Set("Origin", tt.origin)
			if got := hh.originAllowed(req); got != tt.want {
				t.Fatalf("originAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

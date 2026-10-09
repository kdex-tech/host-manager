package auth

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDescribeRedirect(t *testing.T) {
	kind, display, reg := describeRedirect("https://auth.claude.ai:8443/api/cb")
	assert.Equal(t, "web", kind)
	assert.Equal(t, "auth.claude.ai:8443", display)
	assert.Equal(t, "claude.ai", reg)

	kind, display, _ = describeRedirect("http://127.0.0.1:5000/cb")
	assert.Equal(t, "device", kind)
	assert.Equal(t, "http", display)

	kind, display, _ = describeRedirect("cursor://anysphere.cursor/cb")
	assert.Equal(t, "device", kind)
	assert.Equal(t, "cursor", display)

	_, display, reg = describeRedirect("https://xn--clude-6ve.ai/cb")
	assert.Equal(t, "xn--clude-6ve.ai", display, "shown in ASCII, never decoded to look-alike Unicode")
	assert.Equal(t, "xn--clude-6ve.ai", reg)
}

func TestDescribeRedirectIPLiteralHost(t *testing.T) {
	// publicsuffix treats the last label of an IP as a TLD ("113.5"), which
	// would present a made-up domain as the trust signal.
	for _, tc := range []struct{ raw, display, reg string }{
		{"https://203.0.113.5/cb", "203.0.113.5", "203.0.113.5"},
		{"https://203.0.113.5:8443/cb", "203.0.113.5:8443", "203.0.113.5"},
		{"https://[2001:db8::1]:8443/cb", "[2001:db8::1]:8443", "2001:db8::1"},
	} {
		kind, display, reg := describeRedirect(tc.raw)
		assert.Equal(t, "web", kind, tc.raw)
		assert.Equal(t, tc.display, display, tc.raw)
		assert.Equal(t, tc.reg, reg, tc.raw)
	}
}

func TestSanitizeClientName(t *testing.T) {
	assert.Equal(t, "Claude", sanitizeClientName("Cl‮aude\u0000"))
	assert.Equal(t, 64, len([]rune(sanitizeClientName(strings.Repeat("é", 100)))))
}

func TestRenderBuiltinConsentEscapesAndAddsItsCSP(t *testing.T) {
	w := httptest.NewRecorder()
	v := newConsentView(`<script>alert(1)</script>`, "https://app.example/cb", "alice@example.com", "SEALED", []string{"email"})
	RenderBuiltinConsent(w, httptest.NewRequest("GET", "/-/oauth/authorize", nil), v)

	body := w.Body.String()
	assert.NotContains(t, body, "<script>alert(1)</script>")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Contains(t, body, "app.example")
	assert.Contains(t, body, `name="request" value="SEALED"`)
	assert.Contains(t, body, `action="/-/oauth/consent"`)
	// Deny comes first and is the default; Allow is armed by CSS after a second.
	assert.Less(t, strings.Index(body, `value="deny"`), strings.Index(body, `value="allow"`))
	assert.Contains(t, w.Header().Values("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	assert.NotContains(t, strings.Join(w.Header().Values("Content-Security-Policy"), ";"), "form-action")
}

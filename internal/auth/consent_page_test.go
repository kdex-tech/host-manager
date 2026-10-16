package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/render"
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

func TestDescribeRedirectSchemeAndHost(t *testing.T) {
	for _, tc := range []struct{ raw, kind, display string }{
		{"wss://remote.example/cb", "web", "remote.example"},
		{"http://remote.example/cb", "web", "remote.example"},
		{"https://localhost/cb", "device", "https"},
		{"https://[::1]:8443/cb", "device", "https"},
		{"HTTP://127.0.0.1:5000/cb", "device", "http"},
		{"https://APP.Example:8443/cb", "web", "app.example:8443"},
		{"vscode://vscode.github-authentication/cb", "device", "vscode"},
		{"com.example.app:/cb", "device", "com.example.app"},
	} {
		kind, display, _ := describeRedirect(tc.raw)
		assert.Equal(t, tc.kind, kind, tc.raw)
		assert.Equal(t, tc.display, display, tc.raw)
	}
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
	assert.Equal(t, "Claude", sanitizeClientName("Cl\u202eaude\u0000"))
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
	csp := strings.Join(w.Header().Values("Content-Security-Policy"), ";")
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.NotContains(t, csp, "form-action")
}

func TestRenderBuiltinConsentButtonsAndAttributeEscaping(t *testing.T) {
	w := httptest.NewRecorder()
	v := newConsentView("n", `https://app.example/cb?x="><script>`, "a", `"><script>`, nil)
	RenderBuiltinConsent(w, httptest.NewRequest("GET", "/", nil), v)
	body := w.Body.String()
	assert.NotContains(t, body, `"><script>`)
	assert.Regexp(t, `<button[^>]*value="deny"[^>]*autofocus|<button[^>]*autofocus[^>]*value="deny"`, body)
	assert.Regexp(t, `<button[^>]*value="allow"[^>]*class="allow"`, body)
}

var scriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

func renderedConsent(t *testing.T) (body, csp string) {
	t.Helper()
	w := httptest.NewRecorder()
	RenderBuiltinConsent(w, httptest.NewRequest("GET", "/", nil),
		newConsentView("App", "https://app.example/cb", "alice", "SEALED", nil))
	return w.Body.String(), strings.Join(w.Header().Values("Content-Security-Policy"), ";")
}

// The page runs exactly one script, its own, pinned by hash: no inline
// handler, no other source, nothing a theme or an injected string could add.
func TestBuiltinConsent_OnlyItsOwnScriptRuns(t *testing.T) {
	body, csp := renderedConsent(t)

	scripts := scriptRe.FindAllStringSubmatch(body, -1)
	require.Len(t, scripts, 1)
	assert.Equal(t, 1, strings.Count(body, "<script"), "no other script element")
	sum := sha256.Sum256([]byte(scripts[0][1]))
	assert.Contains(t, csp, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"';",
		"script-src allows exactly that script")
	assert.NotRegexp(t, `script-src[^;]*('unsafe-inline'|'unsafe-eval'|https?:|\*|'nonce-)`, csp)
	assert.NotRegexp(t, `(?i)\son[a-z]+=`, body, "no inline event handlers")
}

// Allow is held back until the user really interacts with the visible page.
// The script may only ever hold Allow back: it never acts for the user.
func TestBuiltinConsent_ScriptOnlyHoldsAllowBack(t *testing.T) {
	body, _ := renderedConsent(t)
	script := scriptRe.FindStringSubmatch(body)[1]

	for _, act := range []string{"click(", "submit(", "requestSubmit", "dispatchEvent", "fetch(", "XMLHttpRequest", "location"} {
		assert.NotContains(t, script, act)
	}
	for _, guard := range []string{"isTrusted", "visibilityState", "hasFocus", "preventDefault", "submitter"} {
		assert.Contains(t, script, guard)
	}
}

// Without script the page still holds Allow back for a second with CSS, as
// before; the script only adds to that.
func TestBuiltinConsent_CSSHoldStaysForNoScript(t *testing.T) {
	body, _ := renderedConsent(t)
	assert.Regexp(t, `<button[^>]*value="allow"[^>]*class="allow"`, body)
	assert.Contains(t, body, "@keyframes arm")
}

func englishOnly(string, ...any) (string, bool) { return "", false }

func coreView() ConsentView {
	return ConsentView{
		RedirectKind:      RedirectKindWeb,
		RedirectDisplay:   "app.example.com",
		RegistrableDomain: "example.com",
		RedirectURI:       "https://app.example.com/cb",
		ClientName:        "App",
		Account:           "a@b.c",
		Scopes:            []string{"email", "profile"},
		Request:           "SEALED",
		Action:            OAuthConsentPath,
	}
}

func TestRenderConsentCore_EnglishFallback(t *testing.T) {
	out := string(RenderConsentCore(coreView(), "m1", englishOnly))
	assert.Contains(t, out, "Allow access to your account?")
	assert.Contains(t, out, "Signed in as <strong>a@b.c</strong>.")
	assert.Contains(t, out, "Only allow this if you started connecting this application yourself.")
	assert.Contains(t, out, `name="request" value="SEALED"`)
	assert.Contains(t, out, `action="/-/oauth/consent"`)
	assert.Equal(t, 1, strings.Count(out, ConsentMarkerAttr+`="m1"`))
	assert.True(t, strings.HasPrefix(out, `<div data-kdex-consent="m1">`), "the marker is on the block's root")
	assert.Equal(t, 1, strings.Count(out, "<script>"+consentArmScript+"</script>"), "the block carries the hold-back script")
}

// A stale or partial translation never shows a raw key: every key it lacks
// falls back to its English text.
func TestRenderConsentCore_PartialTranslation(t *testing.T) {
	tr := func(key string, _ ...any) (string, bool) {
		if key == "consent.title" {
			return "Zugriff auf Ihr Konto erlauben?", true
		}
		return "", false
	}
	for _, v := range []ConsentView{coreView(), func() ConsentView {
		v := coreView()
		v.RedirectKind, v.RedirectDisplay, v.RegistrableDomain, v.Scopes = RedirectKindDevice, "cursor", "", nil
		return v
	}()} {
		out := string(RenderConsentCore(v, "m1", tr))
		assert.Contains(t, out, "<h1>Zugriff auf Ihr Konto erlauben?</h1>")
		assert.NotContains(t, out, "Allow access to your account?")
		assert.Contains(t, out, "Signed in as <strong>a@b.c</strong>.")
		assert.Contains(t, out, ">Allow</button>")
		assert.NotContains(t, out, "consent.")
	}
}

// Arguments are never format strings: a client name or account full of verbs
// shows as typed, escaped, and inside <strong>.
func TestRenderConsentCore_ArgsAreLiteral(t *testing.T) {
	v := coreView()
	v.ClientName = "%s<b>&x%!"
	v.Account = "%d@x"
	for _, tr := range []Translator{englishOnly, func(key string, args ...any) (string, bool) {
		return fmt.Sprintf(render.ConsentMessages[key], args...), true
	}} {
		out := string(RenderConsentCore(v, "m1", tr))
		assert.Contains(t, out, "<strong>%s&lt;b&gt;&amp;x%!</strong>")
		assert.Contains(t, out, "<strong>%d@x</strong>")
		assert.NotContains(t, out, "%!(")
		assert.NotContains(t, out, "<b>")
	}
}

// Translations are plain text: markup in one is shown, never interpreted.
func TestRenderConsentCore_TranslationHTMLEscaped(t *testing.T) {
	tr := func(key string, _ ...any) (string, bool) {
		if key == "consent.warning" {
			return "<b>Careful</b>", true
		}
		return "", false
	}
	out := string(RenderConsentCore(coreView(), "m1", tr))
	assert.Contains(t, out, "&lt;b&gt;Careful&lt;/b&gt;")
	assert.NotContains(t, out, "<b>")
}

func TestRenderConsentCore_Conditions(t *testing.T) {
	device := coreView()
	device.RedirectKind, device.RedirectDisplay, device.RegistrableDomain = RedirectKindDevice, "cursor", ""
	out := string(RenderConsentCore(device, "m1", englishOnly))
	assert.Contains(t, out, "<p>Allowing sends access to <strong>an application on this device</strong> (cursor).</p>")
	assert.NotContains(t, out, "Website:")
	assert.NotContains(t, out, `class="where"`)

	out = string(RenderConsentCore(coreView(), "m1", englishOnly))
	assert.Contains(t, out, "<p>Allowing sends access to:</p>")
	assert.Contains(t, out, `<p class="where">app.example.com</p>`)
	assert.Contains(t, out, "<p>Website: <strong>example.com</strong></p>")
	assert.Contains(t, out, `<p class="small">Full address: https://app.example.com/cb</p>`)
	assert.Contains(t, out, "The application calls itself <strong>App</strong>.")
	assert.Contains(t, out, "with your permissions and read: email, profile.")
	assert.NotContains(t, out, "an application on this device")

	web := coreView()
	web.RegistrableDomain = ""
	web.ClientName = ""
	web.Scopes = nil
	out = string(RenderConsentCore(web, "m1", englishOnly))
	assert.NotContains(t, out, "Website:")
	assert.NotContains(t, out, "calls itself")
	assert.Contains(t, out, "<p>It will be able to act on your account with your permissions.</p>")
	assert.NotContains(t, out, "and read:")
}

// Arguments are substituted in one pass: an argument that happens to contain
// another argument's sentinel is shown as itself, never expanded.
func TestRenderConsentCore_SentinelsAreNotRescanned(t *testing.T) {
	v := coreView()
	v.RedirectKind, v.RedirectDisplay, v.RegistrableDomain = RedirectKindDevice, "0", ""
	out := string(RenderConsentCore(v, "m1", englishOnly))
	assert.Equal(t, 1, strings.Count(out, "an application on this device"))
	assert.Contains(t, out, "(0).")
}

// The block's sentinels are private-use runes; view fields drop them so a
// client cannot inject one.
func TestNewConsentViewStripsPrivateUse(t *testing.T) {
	v := newConsentView("App", "https://app.example/cb", "a0@b", "S", nil)
	assert.Equal(t, "App", v.ClientName)
	assert.Equal(t, "a0@b", v.Account)
	assert.Equal(t, "https://app.example/cb", v.RedirectURI)
}

func TestConsentScriptHoldsEveryAllow(t *testing.T) {
	assert.Contains(t, consentArmScript, "querySelectorAll('button[value=allow]')")
	assert.Contains(t, consentArmScript, "matches('button[value=allow]')")
	assert.NotContains(t, consentArmScript, "querySelector('form')", "not only the first form")
}

func TestBuiltinConsentCSPMatchesScript(t *testing.T) {
	body, csp := renderedConsent(t)
	scripts := scriptRe.FindAllStringSubmatch(body, -1)
	require.Len(t, scripts, 1)
	sum := sha256.Sum256([]byte(scripts[0][1]))
	hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	assert.Equal(t, hash, ConsentScriptHash())
	assert.Contains(t, csp, "script-src "+hash+";")
	assert.Contains(t, body, "<title>Allow access?</title>")
	assert.Regexp(t, `data-kdex-consent="[0-9a-f]{32}"`, body)
}

func TestBuiltinConsentMarkerIsFresh(t *testing.T) {
	a, _ := renderedConsent(t)
	b, _ := renderedConsent(t)
	re := regexp.MustCompile(`data-kdex-consent="([0-9a-f]{32})"`)
	assert.NotEqual(t, re.FindStringSubmatch(a)[1], re.FindStringSubmatch(b)[1])
}

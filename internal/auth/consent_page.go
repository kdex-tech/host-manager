package auth

import (
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// ConsentView is the data a consent page renders. Its field names are the
// template contract for the stage-2 Consent utility page, so do not rename
// them casually. It carries data, not copy: an empty Scopes means minimal
// access, and the renderer words that.
type ConsentView struct {
	// RedirectKind is "web" (an https redirect: the code leaves this device)
	// or "device" (loopback or a private-use scheme: an app on this device).
	RedirectKind string
	// RedirectDisplay is the ASCII host[:port] for "web", the scheme for "device".
	RedirectDisplay   string
	RegistrableDomain string
	RedirectURI       string
	ClientName        string
	Account           string
	Scopes            []string
	Request           string
	Action            string
}

const maxClientNameRunes = 64

// ConsentView.RedirectKind values; the templates branch on them.
const (
	RedirectKindWeb    = "web"
	RedirectKindDevice = "device"
)

func newConsentView(clientName, redirectURI, account, sealed string, scopes []string) ConsentView {
	kind, display, registrable := describeRedirect(redirectURI)
	return ConsentView{
		RedirectKind:      kind,
		RedirectDisplay:   display,
		RegistrableDomain: registrable,
		RedirectURI:       redirectURI,
		ClientName:        sanitizeClientName(clientName),
		Account:           account,
		Scopes:            scopes,
		Request:           sealed,
		Action:            OAuthConsentPath,
	}
}

// describeRedirect says where a code will go, in a form a person can judge.
// The host is shown exactly as registered: redirects with non-ASCII hosts are
// refused at registration (dcr.FilterRedirectURIs), and a punycode host is
// never decoded, so a look-alike shows as the xn-- form it really is.
func describeRedirect(raw string) (kind, display, registrable string) {
	u, err := url.Parse(raw)
	if err != nil {
		return RedirectKindWeb, raw, raw
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return RedirectKindDevice, u.Scheme, ""
	}
	display = strings.ToLower(u.Host)
	// An IP literal has no registrable domain, and publicsuffix would invent
	// one from its last labels (203.0.113.5 -> "113.5"), so show the IP itself.
	if _, err := netip.ParseAddr(host); err == nil {
		return RedirectKindWeb, display, host
	}
	registrable, err = publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		registrable = host
	}
	return RedirectKindWeb, display, registrable
}

// sanitizeClientName removes control and format characters (including bidi
// overrides) from the self-declared client name and caps its length.
func sanitizeClientName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxClientNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// builtinConsentCSP is added to the flow's own frame-ancestors policy. No
// form-action: browsers apply it to the redirects after the POST, and those
// leave this origin by design. No script anywhere on this page.
const builtinConsentCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

var builtinConsentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Allow access?</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
.where{font-size:1.4rem;font-weight:600;word-break:break-all}
.small{color:#555;font-size:.85rem;word-break:break-all}
form{display:flex;gap:1rem;margin-top:2rem}
button{font-size:1rem;padding:.6rem 1.4rem;border-radius:.4rem;border:1px solid #888;background:#fff}
.allow{background:#1a56db;color:#fff;border-color:#1a56db;animation:arm 1s steps(1,end)}
@keyframes arm{from{pointer-events:none;opacity:.5}to{pointer-events:auto;opacity:1}}
</style></head><body>
<h1>Allow access to your account?</h1>
<p>Signed in as <strong>{{.Account}}</strong>.</p>
{{if eq .RedirectKind "web"}}
<p>Allowing sends access to:</p>
<p class="where">{{.RedirectDisplay}}</p>
{{if .RegistrableDomain}}<p>Website: <strong>{{.RegistrableDomain}}</strong></p>{{end}}
{{else}}
<p>Allowing sends access to <strong>an application on this device</strong> ({{.RedirectDisplay}}).</p>
{{end}}
<p class="small">Full address: {{.RedirectURI}}</p>
{{if .ClientName}}<p>The application calls itself <strong>{{.ClientName}}</strong>. This name is provided by the application and has not been verified.</p>{{end}}
<p>It will be able to act on your account with your permissions{{if .Scopes}} and read: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s}}{{end}}{{end}}.</p>
<p>Only allow this if you started connecting this application yourself.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="request" value="{{.Request}}">
<button type="submit" name="decision" value="deny" autofocus>Deny</button>
<button type="submit" name="decision" value="allow" class="allow">Allow</button>
</form>
</body></html>`))

// RenderBuiltinConsent is the consent page used when the host supplies none
// (stage 2 falls back to it). The flow has already set the no-store, framing
// and referrer headers.
func RenderBuiltinConsent(w http.ResponseWriter, _ *http.Request, v ConsentView) {
	w.Header().Add("Content-Security-Policy", builtinConsentCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = builtinConsentTemplate.Execute(w, v)
}

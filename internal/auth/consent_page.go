package auth

import (
	"crypto/sha256"
	"encoding/base64"
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
		RedirectURI:       stripControlAndFormat(redirectURI),
		ClientName:        sanitizeClientName(clientName),
		Account:           stripControlAndFormat(account),
		Scopes:            scopes,
		Request:           sealed,
		Action:            OAuthConsentPath,
	}
}

// networkSchemes are delivered over the network to the host in the URI. Any
// other scheme is handed to a local application, even when it has an
// authority (cursor://, vscode://).
var networkSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true}

// describeRedirect says where a code will go, in a form a person can judge.
// A network scheme is "device" only for a loopback host; a custom scheme is
// always "device". Hosts are ASCII because dcr.FilterRedirectURIs refuses
// non-ASCII hosts at registration, and a punycode host is never decoded, so a
// look-alike shows as the xn-- form it really is.
func describeRedirect(raw string) (kind, display, registrable string) {
	u, err := url.Parse(raw)
	if err != nil {
		return RedirectKindWeb, raw, raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if !networkSchemes[scheme] {
		return RedirectKindDevice, scheme, ""
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return RedirectKindDevice, scheme, ""
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

// stripControlAndFormat removes Unicode Cc and Cf characters (including bidi
// overrides) from text that is shown to a person.
func stripControlAndFormat(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// sanitizeClientName cleans the self-declared client name and caps its length.
func sanitizeClientName(s string) string {
	r := []rune(stripControlAndFormat(s))
	if len(r) > maxClientNameRunes {
		r = r[:maxClientNameRunes]
	}
	return strings.TrimSpace(string(r))
}

// consentArmScript holds Allow back until the user really interacts with the
// page while it is visible and focused, plus half a second. Framing is already
// refused; this answers the double-click variant, where a popup asks for a
// double-click and swaps this page in under the second click: that page was
// not visible for the first, and there is no time for a deliberate move.
// Losing focus or visibility holds Allow back again. It only ever holds Allow
// back, never acts for the user, and without script the CSS hold below still
// applies.
const consentArmScript = `(function(){
var f=document.querySelector('form'),a=f&&f.querySelector('button[value=allow]');
if(!a)return;
var armed=false,t=0;
function off(){armed=false;clearTimeout(t);t=0;a.setAttribute('aria-disabled','true');}
function gesture(e){
if(!e.isTrusted||armed||t||document.visibilityState!=='visible'||!document.hasFocus())return;
t=setTimeout(function(){armed=true;t=0;a.removeAttribute('aria-disabled');},500);
}
off();
document.addEventListener('pointermove',gesture);
document.addEventListener('keydown',gesture);
window.addEventListener('blur',off);
document.addEventListener('visibilitychange',function(){if(document.visibilityState!=='visible')off();});
f.addEventListener('submit',function(e){if(e.submitter===a&&!armed)e.preventDefault();});
})();`

// builtinConsentCSP is added to the flow's own frame-ancestors policy. The
// only script allowed is consentArmScript, by hash. No form-action: browsers
// apply it to the redirects after the POST, and those leave this origin by
// design.
var builtinConsentCSP = func() string {
	sum := sha256.Sum256([]byte(consentArmScript))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; style-src 'unsafe-inline'; frame-ancestors 'none'"
}()

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
.allow[aria-disabled]{opacity:.5;cursor:default}
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
<script>` + consentArmScript + `</script>
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

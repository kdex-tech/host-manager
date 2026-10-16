package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
	"kdex.dev/crds/render"
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
// overrides) from text that is shown to a person, and Co (private use)
// characters, which the consent block uses as argument sentinels.
func stripControlAndFormat(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) {
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

// consentArmScript holds every Allow on the page back until the user really
// interacts with the page while it is visible and focused, plus half a second.
// Framing is already refused; this answers the double-click variant, where a
// popup asks for a double-click and swaps this page in under the second
// click: that page was not visible for the first, and there is no time for a
// deliberate move. Losing focus or visibility holds Allow back again. It
// guards every button[value=allow], not only the block's own, and the submit
// guard is delegated so a button added later is held too. It only ever holds
// Allow back, never acts for the user, and without script the CSS hold still
// applies.
const consentArmScript = `(function(){
var armed=false,t=0;
function set(on){var b=document.querySelectorAll('button[value=allow]');for(var i=0;i<b.length;i++){if(on)b[i].removeAttribute('aria-disabled');else b[i].setAttribute('aria-disabled','true');}}
function off(){armed=false;clearTimeout(t);t=0;set(false);}
function gesture(e){
if(!e.isTrusted||armed||t||document.visibilityState!=='visible'||!document.hasFocus())return;
t=setTimeout(function(){armed=true;t=0;set(true);},500);
}
off();
document.addEventListener('pointermove',gesture);
document.addEventListener('keydown',gesture);
window.addEventListener('blur',off);
document.addEventListener('visibilitychange',function(){if(document.visibilityState!=='visible')off();});
document.addEventListener('submit',function(e){var s=e.submitter;if(!armed&&s&&s.matches('button[value=allow]'))e.preventDefault();},true);
})();`

var consentScriptHash = func() string {
	sum := sha256.Sum256([]byte(consentArmScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

// ConsentScriptHash is the CSP source that allows the hold-back script, and
// nothing else: 'sha256-…', quotes included.
func ConsentScriptHash() string { return consentScriptHash }

// builtinConsentCSP is added to the flow's own frame-ancestors policy. The
// only script allowed is consentArmScript, by hash. No form-action: browsers
// apply it to the redirects after the POST, and those leave this origin by
// design.
var builtinConsentCSP = "default-src 'none'; script-src " + ConsentScriptHash() +
	"; style-src 'unsafe-inline'; frame-ancestors 'none'"

// ConsentMarkerAttr is the attribute on the consent block's root that carries
// the per-render marker, so a page that embeds the block can check it is
// there exactly once.
const ConsentMarkerAttr = "data-kdex-consent"

// Translator returns the host's translation of a consent.* key, formatted
// with args, and true; or false when the host's catalog lacks the key.
type Translator func(key string, args ...any) (string, bool)

// consentSentinel stands in for argument i while a message is formatted and
// escaped. Private-use runes cannot reach it from a view field: newConsentView
// strips them.
func consentSentinel(i int) string { return "" + strconv.Itoa(i) + "" }

// consentMessage renders one consent.* message as HTML. The (translated or
// English) text is formatted with sentinels only, then escaped, then each
// sentinel is replaced, in one pass, by its argument, which is HTML the caller
// built from escaped text. So an argument never passes through a format
// string, and a translation is plain text.
func consentMessage(t Translator, key string, args ...template.HTML) template.HTML {
	sentinels := make([]any, len(args))
	pairs := make([]string, 0, 2*len(args))
	for i, a := range args {
		s := consentSentinel(i)
		sentinels[i] = s
		pairs = append(pairs, s, string(a))
	}
	text, ok := "", false
	if t != nil {
		text, ok = t(key, sentinels...)
	}
	if !ok {
		text = fmt.Sprintf(render.ConsentMessages[key], sentinels...)
	}
	escaped := html.EscapeString(text)
	if len(pairs) == 0 {
		return template.HTML(escaped) // escaped above
	}
	return template.HTML(strings.NewReplacer(pairs...).Replace(escaped)) // escaped text, escaped args
}

func consentPlain(s string) template.HTML {
	return template.HTML(html.EscapeString(s)) // escaped
}

func consentStrong(h template.HTML) template.HTML {
	return "<strong>" + h + "</strong>"
}

type consentBlockData struct {
	Marker, Action, Request, RedirectDisplay string
	Web                                      bool
	Title, SignedInAs, SendsTo, Website      template.HTML
	FullAddress, ClientName, Permissions     template.HTML
	Warning, Allow, Deny                     template.HTML
}

var consentBlockTemplate = template.Must(template.New("consent-block").Parse(
	`<div ` + ConsentMarkerAttr + `="{{.Marker}}">
<h1>{{.Title}}</h1>
<p>{{.SignedInAs}}</p>
{{if .Web}}<p>{{.SendsTo}}</p>
<p class="where">{{.RedirectDisplay}}</p>
{{with .Website}}<p>{{.}}</p>
{{end}}{{else}}<p>{{.SendsTo}}</p>
{{end}}<p class="small">{{.FullAddress}}</p>
{{with .ClientName}}<p>{{.}}</p>
{{end}}<p>{{.Permissions}}</p>
<p>{{.Warning}}</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="request" value="{{.Request}}">
<button type="submit" name="decision" value="deny" autofocus>{{.Deny}}</button>
<button type="submit" name="decision" value="allow" class="allow">{{.Allow}}</button>
</form>
<script>` + consentArmScript + `</script>
</div>`))

// RenderConsentCore renders the fixed consent block: the disclosure, the
// Allow/Deny form carrying the sealed request, and the hold-back script, in a
// root element carrying marker as ConsentMarkerAttr. Every string is a
// consent.* key looked up through t, each falling back to its English text,
// so a partial translation never shows a raw key. A nil t means English.
func RenderConsentCore(v ConsentView, marker string, t Translator) template.HTML {
	d := consentBlockData{
		Marker:          marker,
		Action:          v.Action,
		Request:         v.Request,
		RedirectDisplay: v.RedirectDisplay,
		Web:             v.RedirectKind == RedirectKindWeb,
		Title:           consentMessage(t, "consent.title"),
		SignedInAs:      consentMessage(t, "consent.signed-in-as", consentStrong(consentPlain(v.Account))),
		FullAddress:     consentMessage(t, "consent.full-address", consentPlain(v.RedirectURI)),
		Warning:         consentMessage(t, "consent.warning"),
		Allow:           consentMessage(t, "consent.allow"),
		Deny:            consentMessage(t, "consent.deny"),
	}
	if d.Web {
		d.SendsTo = consentMessage(t, "consent.web.sends-to")
		if v.RegistrableDomain != "" {
			d.Website = consentMessage(t, "consent.web.website", consentStrong(consentPlain(v.RegistrableDomain)))
		}
	} else {
		d.SendsTo = consentMessage(t, "consent.device.sends-to",
			consentStrong(consentMessage(t, "consent.device.application")), consentPlain(v.RedirectDisplay))
	}
	if v.ClientName != "" {
		d.ClientName = consentMessage(t, "consent.client-name", consentStrong(consentPlain(v.ClientName)))
	}
	if len(v.Scopes) == 0 {
		d.Permissions = consentMessage(t, "consent.permissions")
	} else {
		d.Permissions = consentMessage(t, "consent.permissions-scopes", consentPlain(strings.Join(v.Scopes, ", ")))
	}
	var b strings.Builder
	if err := consentBlockTemplate.Execute(&b, d); err != nil {
		// The template is fixed and its data is strings, so this cannot fail;
		// an empty block fails the page's exactly-once marker check.
		return ""
	}
	return template.HTML(b.String()) // rendered by html/template
}

var builtinConsentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
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
{{.Block}}
</body></html>`))

// newConsentMarker returns a fresh random marker for one render of the block.
func newConsentMarker() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

// RenderBuiltinConsent is the consent page used when the host supplies none
// (stage 2 falls back to it): the fixed block, in English, in a plain page.
// The flow has already set the no-store, framing and referrer headers.
func RenderBuiltinConsent(w http.ResponseWriter, _ *http.Request, v ConsentView) {
	w.Header().Add("Content-Security-Policy", builtinConsentCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = builtinConsentTemplate.Execute(w, struct{ Title, Block template.HTML }{
		Title: consentMessage(nil, "consent.page-title"),
		Block: RenderConsentCore(v, newConsentMarker(), nil),
	})
}

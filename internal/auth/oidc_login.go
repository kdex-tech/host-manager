package auth

import (
	"cmp"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"golang.org/x/oauth2"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// OAuthLoginPath starts a browser login at the upstream OIDC provider. The
// login page links here (as `oidc.authCodeURL`) rather than straight to the
// provider, because what the callback needs to tell this login apart from any
// other is per-login and the login page is cacheable.
const OAuthLoginPath = "/-/oauth/login"

// loginStateCookieInfix joins the session cookie name and the login's state to
// name the per-login cookie. Keying the name by state lets several logins run
// at once (two tabs) without one overwriting the other's cookie.
const loginStateCookieInfix = "_oidc_"

// loginStateTTL bounds how long a user may sit at the provider's login page.
const loginStateTTL = 10 * time.Minute

// loginStateCookiePath scopes the per-login cookies to the OAuth paths: the
// callback reads them, and the start must see them to bound how many exist.
const loginStateCookiePath = "/-/oauth/"

// Bounds on the per-login cookies a browser holds. Each start sets one and an
// abandoned login's lives loginStateTTL, all carried on every /-/oauth/
// request, so without a bound a page that steers a browser through a few
// starts pushes the Cookie header past what the ingress accepts (8 KB is
// common) and sign-in fails. At most maxLoginsInFlight of at most
// maxLoginStateCookieBytes (name + value) keeps them near 6 KB; a typical
// login's cookie is under 1 KB.
const (
	maxLoginsInFlight        = 3
	maxLoginStateCookieBytes = 2048
)

// loginState is everything the callback needs to finish exactly one login. It
// travels in an encrypted, HttpOnly cookie scoped to /-/oauth/, so it
// is bound to the browser that started the login: a code delivered to any
// other browser arrives without it and is refused (login CSRF, RFC 6749
// §10.12). See kdex-tech/host-manager#234.
type loginState struct {
	State    string `json:"s"`
	Return   string `json:"r"`
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
	Exp      int64  `json:"exp"`
}

// errLoginNotBound is the callback's answer to a code it cannot tie to a login
// this browser started. It is a client error: the request, not the server, is
// at fault.
var errLoginNotBound = errors.New("login was not started from this browser")

// AuthCodeRequest is one browser login's view of the provider's authorization
// endpoint.
type AuthCodeRequest struct {
	State     string
	Verifier  string
	Nonce     string
	Prompt    string
	LoginHint string
}

// upstreamPromptValues are the OIDC Core §3.1.2.1 prompt values a login may
// ask the provider for. `none` is not among them: a browser login is
// interactive by definition.
var upstreamPromptValues = []string{"login", "consent", "select_account"}

// joinPrompt merges the configured prompt values (offline_access sends
// `consent`, #190) with a login's requested ones, dropping anything the spec
// does not define so a crafted link cannot inject text into the provider
// request.
func joinPrompt(configured []string, requested string) string {
	joined := slices.Clone(configured)
	for p := range strings.FieldsSeq(requested) {
		if slices.Contains(upstreamPromptValues, p) && !slices.Contains(joined, p) {
			joined = append(joined, p)
		}
	}
	return strings.Join(joined, " ")
}

// OIDCLoginURL is the link a login page renders for the upstream provider.
// prompt and loginHint are passed on to the provider when set.
func OIDCLoginURL(returnPath, prompt, loginHint string) string {
	v := url.Values{"return": {returnPath}}
	if prompt != "" {
		v.Set("prompt", prompt)
	}
	if loginHint != "" {
		v.Set("login_hint", loginHint)
	}
	return OAuthLoginPath + "?" + v.Encode()
}

// OAuthLoginGet mints a login's state, PKCE verifier and nonce, keeps them in
// the per-login cookie, and sends the browser to the provider.
func (o *OAuth2) OAuthLoginGet(w http.ResponseWriter, r *http.Request) {
	// The provider returns the browser to the one registered redirect_uri, on
	// the primary domain, and a cookie set on any other host never reaches it.
	// A login started on a secondary domain is first moved to the callback's
	// origin, before anything is minted. The target is fixed configuration,
	// never the request, so this cannot redirect anywhere else.
	if cb, err := url.Parse(o.AuthConfig.OIDC.RedirectURL); err == nil && cb.Host != "" &&
		!kdexhttp.SameOrigin(cb.Scheme+"://"+r.Host, cb.Scheme, []string{cb.Host}) {
		target := url.URL{Scheme: cb.Scheme, Host: cb.Host, Path: OAuthLoginPath, RawQuery: r.URL.RawQuery}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}

	q := r.URL.Query()
	st := loginState{
		State:    rand.Text(),
		Return:   kdexhttp.SafeReturnPath(q.Get("return")),
		Verifier: oauth2.GenerateVerifier(),
		Nonce:    rand.Text(),
		Exp:      time.Now().Add(loginStateTTL).Unix(),
	}

	sealed, err := o.AuthExchanger.sealLoginState(st)
	if err != nil {
		logf.FromContext(r.Context()).Error(err, "failed to seal OIDC login state")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	name := o.loginStateCookiePrefix() + st.State
	if len(name)+len(sealed) > maxLoginStateCookieBytes {
		// A browser would silently drop it and fail the login at the callback.
		http.Error(w, "sign-in request too long", http.StatusBadRequest)
		return
	}

	o.expireOldestLogins(w, r)
	http.SetCookie(w, loginStateCookie(r, name, sealed, int(loginStateTTL.Seconds())))
	w.Header().Set("Cache-Control", "no-store")

	http.Redirect(w, r, o.AuthExchanger.AuthCodeURL(AuthCodeRequest{
		State:     st.State,
		Verifier:  st.Verifier,
		Nonce:     st.Nonce,
		Prompt:    q.Get("prompt"),
		LoginHint: q.Get("login_hint"),
	}), http.StatusFound)
}

// consumeLoginState returns the login the callback's state names, and clears
// its cookie whatever the outcome so a state is never usable twice.
func (o *OAuth2) consumeLoginState(w http.ResponseWriter, r *http.Request, state string) (loginState, error) {
	if state == "" {
		return loginState{}, errLoginNotBound
	}
	name := o.loginStateCookiePrefix() + state
	c, err := r.Cookie(name)
	if err != nil {
		return loginState{}, errLoginNotBound
	}
	http.SetCookie(w, loginStateCookie(r, name, "", -1))

	st, err := o.AuthExchanger.openLoginState(c.Value)
	if err != nil {
		return loginState{}, fmt.Errorf("%w: %v", errLoginNotBound, err)
	}
	if subtle.ConstantTimeCompare([]byte(st.State), []byte(state)) != 1 {
		return loginState{}, fmt.Errorf("%w: state does not match its cookie", errLoginNotBound)
	}
	if time.Now().Unix() > st.Exp {
		return loginState{}, fmt.Errorf("%w: login expired", errLoginNotBound)
	}
	return st, nil
}

func (o *OAuth2) loginStateCookiePrefix() string {
	return o.AuthConfig.CookieName + loginStateCookieInfix
}

// loginStateCookie builds a per-login cookie, or its expiry (maxAge < 0), so
// setting and clearing can never disagree on the attributes that identify it.
func loginStateCookie(r *http.Request, name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     loginStateCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		// Lax, not Strict: the provider returns the browser to the callback
		// with a top-level cross-site GET, which Lax admits and Strict does not.
		SameSite: http.SameSiteLaxMode,
	}
}

// expireOldestLogins makes room for the login being started: of the per-login
// cookies this browser sent, all but the newest maxLoginsInFlight-1 are
// expired. One that does not open counts as the oldest.
func (o *OAuth2) expireOldestLogins(w http.ResponseWriter, r *http.Request) {
	type held struct {
		name string
		exp  int64
	}
	var logins []held
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, o.loginStateCookiePrefix()) {
			continue
		}
		var exp int64
		if st, err := o.AuthExchanger.openLoginState(c.Value); err == nil {
			exp = st.Exp
		}
		logins = append(logins, held{c.Name, exp})
	}
	excess := len(logins) - (maxLoginsInFlight - 1)
	if excess <= 0 {
		return
	}
	slices.SortFunc(logins, func(a, b held) int {
		return cmp.Or(cmp.Compare(a.exp, b.exp), strings.Compare(a.name, b.name))
	})
	for _, l := range logins[:excess] {
		http.SetCookie(w, loginStateCookie(r, l.name, "", -1))
	}
}

func (e *Exchanger) sealLoginState(st loginState) (string, error) {
	return e.sealJSON(sealPurposeLoginState, st)
}

func (e *Exchanger) openLoginState(sealed string) (loginState, error) {
	var st loginState
	err := e.openJSON(sealPurposeLoginState, sealed, &st)
	return st, err
}

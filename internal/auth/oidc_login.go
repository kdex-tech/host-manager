package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
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

// loginState is everything the callback needs to finish exactly one login. It
// travels in an encrypted, HttpOnly cookie scoped to the callback path, so it
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

	http.SetCookie(w, &http.Cookie{
		Name:     o.AuthConfig.CookieName + loginStateCookieInfix + st.State,
		Value:    sealed,
		Path:     OAuthCallbackPath,
		MaxAge:   int(loginStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		// Lax, not Strict: the provider returns the browser to the callback
		// with a top-level cross-site GET, which Lax admits and Strict does not.
		SameSite: http.SameSiteLaxMode,
	})
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
	name := o.AuthConfig.CookieName + loginStateCookieInfix + state
	c, err := r.Cookie(name)
	if err != nil {
		return loginState{}, errLoginNotBound
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     OAuthCallbackPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

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

func (e *Exchanger) loginStateKey() []byte {
	key := sha256.Sum256([]byte("oidc-login-state\x00" + e.config.OIDC.BlockKey))
	return key[:]
}

func (e *Exchanger) sealLoginState(st loginState) (string, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: e.loginStateKey()}, nil)
	if err != nil {
		return "", err
	}
	object, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func (e *Exchanger) openLoginState(sealed string) (loginState, error) {
	object, err := jose.ParseEncrypted(sealed, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return loginState{}, err
	}
	payload, err := object.Decrypt(e.loginStateKey())
	if err != nil {
		return loginState{}, err
	}
	var st loginState
	if err := json.Unmarshal(payload, &st); err != nil {
		return loginState{}, err
	}
	return st, nil
}

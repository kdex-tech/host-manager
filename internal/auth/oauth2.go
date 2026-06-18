package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type OAuth2 struct {
	AuthConfig    *Config
	AuthExchanger *Exchanger
}

func (o *OAuth2) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	var clientId, code, codeChallenge, codeChallengeMethod, redirectURI, responseType, scope, state, subject string
	var callbackURL *url.URL
	var err error

	log := logf.FromContext(r.Context())

	defer func() {
		callbackURLStr := ""
		if callbackURL != nil {
			callbackURLStr = callbackURL.String()
		}
		// Intentionally omitted from the log: code, code_challenge, state — these are
		// either live secrets (auth code) or attacker-controlled values we don't want
		// echoed into logs (#11).
		log.V(1).Info(
			"OAuth2 authorization",
			"callback_url", callbackURLStr,
			"client_id", clientId,
			"code_challenge_method", codeChallengeMethod,
			"error", err,
			"redirect_uri", redirectURI,
			"response_type", responseType,
			"scope", scope,
			"subject", subject)
	}()

	// 1. Validate parameters
	clientId = r.URL.Query().Get("client_id")
	codeChallenge = r.URL.Query().Get("code_challenge")
	codeChallengeMethod = r.URL.Query().Get("code_challenge_method")
	redirectURI = r.URL.Query().Get("redirect_uri")
	responseType = r.URL.Query().Get("response_type")
	scope = r.URL.Query().Get("scope")
	state = r.URL.Query().Get("state")

	if clientId == "" {
		err = fmt.Errorf("missing client_id")
		http.Error(w, "Missing client_id", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		err = fmt.Errorf("unsupported response_type")
		http.Error(w, "Unsupported response_type", http.StatusBadRequest)
		return
	}

	authClient, ok := o.AuthExchanger.GetClient(clientId)
	if !ok {
		err = fmt.Errorf("invalid client_id")
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	if len(authClient.AllowedGrantTypes) > 0 && !slices.Contains(authClient.AllowedGrantTypes, "authorization_code") {
		err = fmt.Errorf("grant_type authorization_code not allowed for this client")
		http.Error(w, "Unauthorized grant type", http.StatusUnauthorized)
		return
	}

	if len(authClient.AllowedScopes) > 0 && scope != "" {
		requestedScopes := strings.SplitSeq(scope, " ")
		for s := range requestedScopes {
			if s != "" && !slices.Contains(authClient.AllowedScopes, s) {
				err = fmt.Errorf("scope %s not allowed for this client", s)
				http.Error(w, "Unauthorized scope", http.StatusUnauthorized)
				return
			}
		}
	}

	if authClient.RequirePKCE && codeChallenge == "" {
		err = fmt.Errorf("PKCE is required for this client")
		http.Error(w, "PKCE required: missing code_challenge", http.StatusBadRequest)
		return
	}

	// When PKCE is in use, force S256. Pre-#96 the authorize handler
	// passed code_challenge_method through verbatim and the token
	// endpoint accepted `plain`/empty as a literal string compare —
	// allowing an attacker to downgrade their own flow to plain and
	// redeem an intercepted code with any matching verifier. RFC 7636
	// §4.2 has considered plain unsafe since 2015.
	if codeChallenge != "" && codeChallengeMethod != PKCE_METHOD_S256 {
		err = fmt.Errorf("unsupported code_challenge_method: only S256 is accepted")
		http.Error(w, "Unsupported code_challenge_method: only S256 is accepted", http.StatusBadRequest)
		return
	}

	if !slices.Contains(authClient.RedirectURIs, redirectURI) {
		err = fmt.Errorf("invalid redirect_uri")
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// 2. Parse redirect_uri
	callbackURL, err = url.Parse(redirectURI)
	if err != nil {
		err = fmt.Errorf("invalid redirect_uri")
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// 3. Check Authentication
	ctx := r.Context()
	authCtx, ok := GetAuthContext(ctx)
	if !ok {
		// Not logged in -> Redirect to Login
		// Encode current URL as return URL
		returnURL := r.URL.String()
		http.Redirect(w, r, "/-/login?return="+url.QueryEscape(returnURL), http.StatusSeeOther)
		return
	}

	// We need the Subject.
	subject, err = authCtx.GetSubject()
	if err != nil {
		err = fmt.Errorf("failed to get subject from auth context")
		http.Error(w, "Invalid session", http.StatusInternalServerError)
		return
	}

	// 4. Generate Authorization Code
	claims := AuthorizationCodeClaims{
		AuthMethod:          AuthMethodOAuth2,
		ClientID:            clientId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Subject:             subject,
	}

	code, err = o.AuthExchanger.CreateAuthorizationCode(r.Context(), claims)
	if err != nil {
		err = fmt.Errorf("failed to create auth code")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	q := callbackURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	callbackURL.RawQuery = q.Encode()

	http.Redirect(w, r, callbackURL.String(), http.StatusFound)
}

func (o *OAuth2) OAuthGet(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		http.Error(w, "No code in request", http.StatusBadRequest)
		return
	}

	// Exchange code for ID Token
	rawIDToken, err := o.AuthExchanger.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Error(err, "failed to exchange oauth code")
		http.Error(w, "Failed to exchange token", http.StatusUnauthorized)
		return
	}

	// Exchange ID Token for Local Token
	localToken, err := o.AuthExchanger.ExchangeToken(r.Context(), rawIDToken)
	if err != nil {
		log.Error(err, "failed to exchange for local token")
		http.Error(w, "Failed to exchange for local token", http.StatusUnauthorized)
		return
	}

	store := o.AuthConfig.OIDC.IDTokenStore

	if err := store.Set(w, r, rawIDToken); err != nil {
		log.Error(err, "failed to store session hint")
		http.Error(w, "Failed to store session hint", http.StatusInternalServerError)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     o.AuthConfig.CookieName,
		Value:    localToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Validate state/redirect. state is attacker-controlled (it's the
	// upstream IdP echo of whatever we passed in as our state param), so
	// constrain it to a same-origin path.
	http.Redirect(w, r, kdexhttp.SafeReturnPath(state), http.StatusSeeOther)
}

func (o *OAuth2) OAuth2TokenHandler(w http.ResponseWriter, r *http.Request) {
	var clientId, clientSecret, code, codeVerifier, grantType, password, redirectURI, scope, username string
	var ts TokenSet
	var err error

	log := logf.FromContext(r.Context())
	defer func() {
		// Intentionally omitted from the log: client_secret, code, code_verifier,
		// id_token, password. These are secrets or live credentials and must never
		// appear in logs (#11). Log only structural metadata.
		log.V(1).Info(
			"OAuth2 token exchange",
			"client_id", clientId,
			"client_secret_present", clientSecret != "",
			"code_verifier_present", codeVerifier != "",
			"error", err,
			"grant_type", grantType,
			"id_token_issued", ts.IDToken != "",
			"password_present", password != "",
			"redirect_uri", redirectURI,
			"scope", scope,
			"subject", ts.Subject,
			"username", username)
	}()

	if r.Method != http.MethodPost {
		err = fmt.Errorf("method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err = r.ParseForm(); err != nil {
		err = fmt.Errorf("failed to parse form: %w", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// client_id and client_secret may arrive through basic auth
	clientId, clientSecret, _ = r.BasicAuth()

	/*
		grant_type          |Client Type |Required Parameters                                |Optional Parameters
		====================|============|===================================================|===================
		authorization_code  |Private     |code, redirect_uri, client_id, client_secret       |state
							|Public      |code, redirect_uri, client_id, code_verifier       |state
		client_credentials  |Private     |client_id, client_secret                           |scope
		password            |Private     |username, password, client_id, client_secret       |scope
							|Public      |username, password, client_id                      |scope
		refresh_token       |Private     |refresh_token, client_id, client_secret            |scope
							|Public      |refresh_token, client_id                           |scope
	*/

	if clientId == "" {
		clientId = r.FormValue("client_id")
	}

	client, ok := o.AuthExchanger.GetClient(clientId)

	if !ok {
		err = fmt.Errorf("invalid client_id")
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	if !client.Public {
		if clientSecret == "" {
			clientSecret = r.FormValue("client_secret")
		}
		if clientSecret != client.ClientSecret {
			err = fmt.Errorf("invalid client_secret")
			http.Error(w, "Invalid client_secret", http.StatusBadRequest)
			return
		}
	}

	codeVerifier = r.FormValue("code_verifier")
	grantType = r.FormValue("grant_type")
	scope = r.FormValue("scope")

	if len(client.AllowedGrantTypes) > 0 && !slices.Contains(client.AllowedGrantTypes, grantType) {
		err = fmt.Errorf("grant_type %s not allowed for this client", grantType)
		http.Error(w, "Unauthorized grant type", http.StatusUnauthorized)
		return
	}

	if len(client.AllowedScopes) > 0 && scope != "" {
		for s := range strings.SplitSeq(scope, " ") {
			if s != "" && !slices.Contains(client.AllowedScopes, s) {
				err = fmt.Errorf("scope %s not allowed for this client", s)
				http.Error(w, "Unauthorized scope", http.StatusUnauthorized)
				return
			}
		}
	}

	switch grantType {
	case "authorization_code":
		code = r.FormValue("code")
		if code == "" {
			err = fmt.Errorf("code is required")
			http.Error(w, "code is required", http.StatusBadRequest)
			return
		}
		redirectURI = r.FormValue("redirect_uri")
		if redirectURI == "" {
			err = fmt.Errorf("redirect_uri is required")
			http.Error(w, "redirect_uri is required", http.StatusBadRequest)
			return
		}
		ts, err = o.AuthExchanger.RedeemAuthorizationCode(r.Context(), code, clientId, redirectURI, codeVerifier)
	case "client_credentials":
		if client.Public {
			err = fmt.Errorf("client_credentials grant_type is not supported for public clients")
			http.Error(w, "client_credentials grant_type is not supported for public clients", http.StatusBadRequest)
			return
		}
		ts, err = o.AuthExchanger.LoginClient(r.Context(), clientId, clientSecret, scope)
	case "password":
		username = r.FormValue("username")
		password = r.FormValue("password")
		ts, err = o.AuthExchanger.LoginLocal(r.Context(), username, password, scope, clientId, AuthMethodOAuth2)
	case "refresh_token":
		tokenID := r.FormValue("refresh_token")
		if tokenID == "" {
			err = fmt.Errorf("refresh_token is required")
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}
		ts, err = o.AuthExchanger.RedeemRefreshToken(r.Context(), tokenID, clientId)
	default:
		err = fmt.Errorf("unsupported grant_type")
		http.Error(w, "Unsupported grant_type", http.StatusBadRequest)
		return
	}

	if err != nil {
		err = fmt.Errorf("authentication failed: %w", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	resp := TokenResponse{
		AccessToken:  ts.AccessToken,
		ExpiresIn:    int(o.AuthExchanger.GetTokenTTL().Seconds()),
		IDToken:      ts.IDToken,
		RefreshToken: ts.RefreshToken,
		Scope:        ts.Scope,
		TokenType:    "Bearer",
	}

	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		err = fmt.Errorf("failed to encode token response: %w", err)
		http.Error(w, "Failed to encode token response", http.StatusInternalServerError)
		return
	}
}

// TokenResponse represents the OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type"`
}

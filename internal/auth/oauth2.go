package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type OAuth2 struct {
	AuthConfig    *Config
	AuthExchanger *Exchanger
	// ResourceAudiences is the set of oauth2-protected resource identifiers
	// for this host (both the basePath and the full resource URI forms, per
	// RFC 8707). When a token request carries a `resource` value present in
	// this set, the authorization_code grant mints an audience-bound PASETO
	// PAT as the access_token instead of the standard JWT.
	ResourceAudiences map[string]bool
	// AccessTokenTTL is the lifetime applied to a minted resource PAT.
	AccessTokenTTL time.Duration
}

func (o *OAuth2) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	var clientId, code, codeChallenge, codeChallengeMethod, redirectURI, resource, responseType, scope, state, subject string
	var callbackURL *url.URL
	var err error

	log := logf.FromContext(r.Context())

	defer func() {
		// Intentionally omitted from the log: code, code_challenge, state, and the
		// callback URL itself. The callback URL is built (below) by appending the
		// freshly issued `code` and the `state` to redirect_uri as query params, so
		// logging it re-leaks exactly the live authorization code and CSRF token this
		// handler must never echo (#11). redirect_uri already carries the structural
		// destination; log only whether a code/state was produced.
		log.V(1).Info(
			"OAuth2 authorization",
			"client_id", clientId,
			"code_challenge_method", codeChallengeMethod,
			"code_issued", code != "",
			"error", err,
			"redirect_uri", redirectURI,
			"response_type", responseType,
			"scope", scope,
			"state_present", state != "",
			"subject", subject)
	}()

	// 1. Validate parameters
	clientId = r.URL.Query().Get("client_id")
	codeChallenge = r.URL.Query().Get("code_challenge")
	codeChallengeMethod = r.URL.Query().Get("code_challenge_method")
	redirectURI = r.URL.Query().Get("redirect_uri")
	resource = r.URL.Query().Get("resource")
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

	if len(authClient.AllowedGrantTypes) > 0 && !slices.Contains(authClient.AllowedGrantTypes, GRANT_TYPE_AUTHORIZATION_CODE) {
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
		Resource:            resource,
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
	oidcTokens, err := o.AuthExchanger.ExchangeCode(r.Context(), code)
	if err != nil {
		log.Error(err, "failed to exchange oauth code")
		http.Error(w, "Failed to exchange token", http.StatusUnauthorized)
		return
	}

	// Exchange ID Token for Local Token
	ts, err := o.AuthExchanger.ExchangeToken(r.Context(), oidcTokens)
	if err != nil {
		log.Error(err, "failed to exchange for local token")
		http.Error(w, "Failed to exchange for local token", http.StatusUnauthorized)
		return
	}

	store := o.AuthConfig.OIDC.IDTokenStore

	if err := store.Set(w, r, oidcTokens.RawIDToken); err != nil {
		log.Error(err, "failed to store session hint")
		http.Error(w, "Failed to store session hint", http.StatusInternalServerError)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     o.AuthConfig.CookieName,
		Value:    ts.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})

	// Both AutoExtendSession branches (internal/auth/middleware.go) find the
	// session by THIS cookie, so without it an OIDC session hard-expires at
	// jwt.tokenTTL however long refreshTokenTTL / maxSessionAge are -- the
	// local-login path (internal/host/login.go) has always written it.
	// See kdex-tech/host-manager#189.
	if ts.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     o.AuthConfig.CookieName + "_refresh",
			Value:    ts.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   kdexhttp.IsSecure(r),
			SameSite: http.SameSiteLaxMode,
		})
	}

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
		writeOAuthError(w, http.StatusMethodNotAllowed, errCodeInvalidRequest, "the token endpoint requires POST")
		return
	}

	if err = r.ParseForm(); err != nil {
		err = fmt.Errorf("failed to parse form: %w", err)
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "malformed request body")
		return
	}

	// client_id and client_secret may arrive through basic auth
	var usedBasicAuth bool
	clientId, clientSecret, usedBasicAuth = r.BasicAuth()

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
		writeOAuthError(w, http.StatusBadRequest, errCodeInvalidClient, "unknown client_id")
		return
	}

	if !client.Public {
		if clientSecret == "" {
			clientSecret = r.FormValue("client_secret")
		}
		if clientSecret != client.ClientSecret {
			err = fmt.Errorf("invalid client_secret")
			if usedBasicAuth {
				// 5.2: 401 applies only when client authentication was
				// attempted via the Authorization header, and then obliges
				// a WWW-Authenticate challenge.
				w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
				writeOAuthError(w, http.StatusUnauthorized, errCodeInvalidClient, "client authentication failed")
			} else {
				// Public PKCE clients send no Authorization header, so 5.2
				// permits 400 — and we would have no meaningful challenge to
				// put in WWW-Authenticate anyway. This is the path every
				// current client takes.
				writeOAuthError(w, http.StatusBadRequest, errCodeInvalidClient, "client authentication failed")
			}
			return
		}
	}

	codeVerifier = r.FormValue("code_verifier")
	grantType = r.FormValue("grant_type")
	scope = r.FormValue("scope")
	resource := r.FormValue("resource")

	if len(client.AllowedGrantTypes) > 0 && !slices.Contains(client.AllowedGrantTypes, grantType) {
		err = fmt.Errorf("grant_type %s not allowed for this client", grantType)
		writeOAuthError(w, http.StatusBadRequest, errCodeUnauthorizedClient, "this client is not authorized for that grant_type")
		return
	}

	if len(client.AllowedScopes) > 0 && scope != "" {
		for s := range strings.SplitSeq(scope, " ") {
			if s != "" && !slices.Contains(client.AllowedScopes, s) {
				err = fmt.Errorf("scope %s not allowed for this client", s)
				writeOAuthError(w, http.StatusBadRequest, errCodeInvalidScope, "requested scope is not allowed for this client")
				return
			}
		}
	}

	switch grantType {
	case GRANT_TYPE_AUTHORIZATION_CODE:
		code = r.FormValue("code")
		if code == "" {
			err = fmt.Errorf("code is required")
			writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "code is required")
			return
		}
		redirectURI = r.FormValue("redirect_uri")
		if redirectURI == "" {
			err = fmt.Errorf("redirect_uri is required")
			writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "redirect_uri is required")
			return
		}
		ts, err = o.AuthExchanger.RedeemAuthorizationCode(r.Context(), code, clientId, redirectURI, codeVerifier)
	case "client_credentials":
		if client.Public {
			err = fmt.Errorf("client_credentials grant_type is not supported for public clients")
			writeOAuthError(w, http.StatusBadRequest, errCodeUnauthorizedClient, "client_credentials is not supported for public clients")
			return
		}
		ts, err = o.AuthExchanger.LoginClient(r.Context(), clientId, clientSecret, scope)
	case "password":
		username = r.FormValue("username")
		password = r.FormValue("password")
		ts, err = o.AuthExchanger.LoginLocal(r.Context(), username, password, scope, clientId, AuthMethodOAuth2)
	case GRANT_TYPE_REFRESH_TOKEN:
		tokenID := r.FormValue("refresh_token")
		if tokenID == "" {
			err = fmt.Errorf("refresh_token is required")
			writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "refresh_token is required")
			return
		}
		ts, err = o.AuthExchanger.RedeemRefreshToken(r.Context(), tokenID, clientId)
	default:
		err = fmt.Errorf("unsupported grant_type")
		writeOAuthError(w, http.StatusBadRequest, errCodeUnsupportedGrantType, "unsupported grant_type")
		return
	}

	if err != nil {
		status, code, description := oauthErrorForRedemption(err)
		// Keep the full wrapped cause on `err` for the deferred log; only
		// the classified description reaches the client.
		err = fmt.Errorf("token request failed: %w", err)
		writeOAuthError(w, status, code, description)
		return
	}

	// RFC 8707 resource-bound access token path. Handled returns true when the
	// grant/resource pair is oauth2-protected and the response has already been
	// written (success or error); fall through only for standard-JWT grants.
	if handled, herr := o.writeResourcePATResponse(w, grantType, resource, ts); handled {
		err = herr
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		err = fmt.Errorf("failed to encode token response: %w", err)
		writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)
		return
	}
}

// writeResourcePATResponse mints an RFC 8707 resource-bound PASETO PAT for an
// oauth2-protected MCP resource and writes it as the token response. The PAT's
// aud is the resource URI; entitlements are intentionally NOT baked in — the
// function proxy re-resolves them from the subject's roles at request time.
//
// It applies to both the authorization_code grant and the refresh_token grant.
// The refresh_token case matters for long-lived MCP sessions: without it,
// refreshing silently downgrades the resource-scoped PAT to a host-audience
// JWT, which the function proxy's audience check then rejects.
//
// The boolean reports whether the response was handled here. false means the
// grant/resource pair is not resource-bound and the caller should fall through
// to the standard JWT response. When true, any returned error is for audit
// logging only — the HTTP response has already been written.
func (o *OAuth2) writeResourcePATResponse(w http.ResponseWriter, grantType, resource string, ts TokenSet) (bool, error) {
	if grantType != GRANT_TYPE_AUTHORIZATION_CODE && grantType != GRANT_TYPE_REFRESH_TOKEN {
		return false, nil
	}
	if resource == "" || !o.ResourceAudiences[resource] {
		return false, nil
	}

	pat, err := o.AuthExchanger.MintResourcePAT(resource, ts.Subject, ts.Scope, o.AccessTokenTTL)
	if err != nil {
		// This is the SAME token response MCP clients receive from the
		// standard-JWT path just below — the exact client class #168 was
		// filed about — so it gets the same RFC 6749 5.2 JSON shape, not
		// text/plain.
		writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)
		return true, fmt.Errorf("failed to mint resource PAT: %w", err)
	}

	resp := TokenResponse{
		AccessToken:  pat,
		ExpiresIn:    int(o.AccessTokenTTL.Seconds()),
		RefreshToken: ts.RefreshToken,
		Scope:        ts.Scope,
		TokenType:    "Bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 5.1 requires no-store on the token endpoint's success
	// response; this path bypasses the standard success path below and was
	// missing both headers entirely before #168 review.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)
		return true, fmt.Errorf("failed to encode token response: %w", err)
	}
	return true, nil
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

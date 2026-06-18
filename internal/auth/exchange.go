package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/cel-go/cel"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/cache"
	"golang.org/x/oauth2"
)

type AuthMethod string

const (
	AuthMethodLocal  AuthMethod = "local"
	AuthMethodOIDC   AuthMethod = "oidc"
	AuthMethodOAuth2 AuthMethod = "oauth2"
)

type CompiledMappingRule struct {
	dmapper.MappingRule
	Program cel.Program
}

type Exchanger struct {
	config            Config
	oauth2Config      *oauth2.Config
	oidcProvider      *oidc.Provider
	oidcVerifier      *oidc.IDTokenVerifier
	refreshTokenCache cache.Cache
	refreshTokenTTL   time.Duration
	// authCodeCache tracks the JTI of every unredeemed authorization code.
	// On RedeemAuthorizationCode the JTI is Get-then-Delete'd; an absent
	// JTI signals replay (or expiry) and the redemption is rejected. See
	// kdex-tech/host-manager#65 (RFC 6749 §10.5 single-use requirement).
	authCodeCache cache.Cache
	maxSessionAge time.Duration
	sp            InternalIdentityProvider
}

// authCodeTTL is the upper bound on how long an unredeemed authorization
// code remains valid. Slightly longer than the 10-minute default Exp on
// AuthorizationCodeClaims so the cache TTL doesn't expire the JTI ahead
// of the code itself. Codes are typically redeemed within seconds.
const authCodeTTL = 15 * time.Minute

// RefreshTokenClaims holds the data stored inside a refresh token entry in the cache.
type RefreshTokenClaims struct {
	AuthMethod       AuthMethod `json:"auth_method"`
	ClientID         string     `json:"cid"`
	ExpiresAt        int64      `json:"exp"`
	IssuedAt         int64      `json:"iat"`
	OriginalIssuedAt int64      `json:"oiat"`
	Scope            string     `json:"scp"`
	Subject          string     `json:"sub"`
}

// TokenSet is the result of any successful token minting operation.
type TokenSet struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	Scope        string
	Subject      string
}

func NewExchanger(
	ctx context.Context,
	cfg Config,
	cacheManager cache.CacheManager,
	sp InternalIdentityProvider,
) (*Exchanger, error) {
	ex := &Exchanger{
		config:          cfg,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		maxSessionAge:   cfg.MaxSessionAge,
		sp:              sp,
	}
	if cacheManager != nil {
		ex.refreshTokenCache = cacheManager.GetCache("refresh-tokens", cache.CacheOptions{
			TTL:      &ex.refreshTokenTTL,
			Uncycled: true,
		})
		// Single-use tracking for authorization codes. See #65.
		ttl := authCodeTTL
		ex.authCodeCache = cacheManager.GetCache("auth-codes", cache.CacheOptions{
			TTL:      &ttl,
			Uncycled: true,
		})
	}

	if cfg.IsOIDCEnabled() {
		provider, err := oidc.NewProvider(ctx, cfg.OIDC.ProviderURL)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
		}
		ex.oidcProvider = provider
		ex.oidcVerifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})

		scopes := []string{oidc.ScopeOpenID, "profile", "email"}
		for _, newScope := range cfg.OIDC.Scopes {
			if !slices.Contains(scopes, newScope) {
				scopes = append(scopes, newScope)
			}
		}

		ex.oauth2Config = &oauth2.Config{
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDC.RedirectURL,
			Scopes:       scopes,
		}
	}

	return ex, nil
}

// ResolveInternalRolesAndEntitlements maps a subject (e.g. the `sub` of a
// validated PASETO API token) to its internal roles and entitlements using the
// same KDexRole/KDexRoleBinding resolution the JWT login path uses
// (scopeProvider.FindInternalRolesAndEntitlements). It exists so the proxy's
// PASETO->authContext bridge can derive a structured authorization context for
// API-token callers without duplicating role resolution. Returns empty slices
// (fail-closed) when no identity provider is wired. See
// kdex-tech/host-manager#103.
func (e *Exchanger) ResolveInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	if e == nil || e.sp == nil {
		return nil, nil, nil
	}
	return e.sp.FindInternalRolesAndEntitlements(subject)
}

// MintResourcePAT mints an audience-bound PASETO PAT for an oauth2 protected
// resource. The PAT's aud is the resource URI (RFC 8707); the subject's
// entitlements are NOT baked in — the proxy re-resolves them from the
// subject's KDexRoleBindings at request time.
func (e *Exchanger) MintResourcePAT(resource, subject, scope string, ttl time.Duration) (string, error) {
	if e.config.TokenManager == nil {
		return "", fmt.Errorf("no token manager configured")
	}
	return e.config.TokenManager.MintStatelessKey(resource, subject, "mcp", scope, ttl)
}

func (e *Exchanger) AuthCodeURL(state string) string {
	if e == nil || !e.config.IsOIDCEnabled() {
		return ""
	}
	return e.oauth2Config.AuthCodeURL(state)
}

func (e *Exchanger) EndSessionURL() (string, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return "", nil
	}
	var claims OIDCProviderClaims
	if err := e.oidcProvider.Claims(&claims); err != nil {
		return "", err
	}
	return claims.EndSessionURL, nil
}

func (e *Exchanger) ExchangeCode(ctx context.Context, code string) (string, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return "", fmt.Errorf("OIDC is not configured")
	}

	oauthToken, err := e.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange oauth code %w", err)
	}

	// Extract ID Token from oauthToken
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in response")
	}

	return rawIDToken, nil
}

func (e *Exchanger) ExchangeToken(ctx context.Context, rawIDToken string) (string, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return "", fmt.Errorf("OIDC is not configured")
	}

	// 1. Verify OIDC Token
	idToken, err := e.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("failed to verify ID token: %w", err)
	}

	var signingContext jwt.MapClaims
	if err := idToken.Claims(&signingContext); err != nil {
		return "", fmt.Errorf("failed to parse claims: %w", err)
	}

	signingContext["idp"] = "oidc"

	sub, err := signingContext.GetSubject()
	if err != nil {
		return "", fmt.Errorf("no sub in id_token")
	}

	roles, entitlements, err := e.sp.FindInternalRolesAndEntitlements(sub)
	if err != nil {
		return "", err
	}

	oidcRoles := signingContext["roles"]
	switch v := oidcRoles.(type) {
	case []string:
		oidcRoles = append(v, roles...)
	case string:
		oidcRoles = append([]string{v}, roles...)
	default:
		oidcRoles = roles
	}
	signingContext["roles"] = oidcRoles

	oidcEntitlements := signingContext["entitlements"]
	switch v := oidcEntitlements.(type) {
	case []string:
		oidcEntitlements = append(v, entitlements...)
	case string:
		oidcEntitlements = append([]string{v}, entitlements...)
	default:
		oidcEntitlements = entitlements
	}
	signingContext["entitlements"] = oidcEntitlements

	// 3. Mint Primary Access Token
	return e.config.Signer.Sign(signingContext)
}

func (e *Exchanger) GetClient(clientID string) (AuthClient, bool) {
	if e == nil {
		return AuthClient{}, false
	}
	// Static client map takes precedence.
	if c, ok := e.config.Clients[clientID]; ok {
		return c, true
	}
	// Fall back to dynamically-registered clients (RFC 7591).
	if e.config.DCRStore != nil {
		if dc, ok, _ := e.config.DCRStore.Get(context.Background(), clientID); ok {
			return AuthClient{
				ClientID:          dc.ClientID,
				Public:            true,
				RequirePKCE:       true,
				RedirectURIs:      dc.RedirectURIs,
				AllowedGrantTypes: dc.GrantTypes,
				AllowedScopes:     strings.Fields(dc.Scope),
				Name:              dc.ClientName,
			}, true
		}
	}
	return AuthClient{}, false
}

func (e *Exchanger) GetOIDCClientID() string {
	return e.config.OIDC.ClientID
}

func (e *Exchanger) GetScopesSupported() ([]string, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return nil, nil
	}
	var claims OIDCProviderClaims
	if err := e.oidcProvider.Claims(&claims); err != nil {
		return nil, err
	}
	return claims.ScopesSupported, nil
}

func (e *Exchanger) GetTokenTTL() time.Duration {
	return e.config.TokenTTL
}

func (e *Exchanger) IsRefreshTokenEnabled() bool {
	return e != nil && e.refreshTokenCache != nil
}

// RevokeRefreshToken deletes the refresh-token entry identified by
// tokenID from the cache. Idempotent — returns nil if no entry exists.
// Called from logout flows so a stolen `_refresh` cookie value cannot
// be replayed after the user logs out. See kdex-tech/host-manager#84.
func (e *Exchanger) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	if !e.IsRefreshTokenEnabled() {
		return nil
	}
	return e.refreshTokenCache.Delete(ctx, tokenID)
}

// createRefreshToken is the internal helper that stores a refresh token in the cache.
func (e *Exchanger) createRefreshToken(ctx context.Context, claims RefreshTokenClaims) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	if claims.OriginalIssuedAt == 0 {
		claims.OriginalIssuedAt = claims.IssuedAt
	}
	claims.ExpiresAt = now.Add(e.refreshTokenTTL).Unix()

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal refresh token claims: %w", err)
	}

	tokenID := rand.Text()
	if err := e.refreshTokenCache.Set(ctx, tokenID, string(payload)); err != nil {
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	return tokenID, nil
}

func (e *Exchanger) LoginClient(ctx context.Context, clientID, clientSecret, scope string) (TokenSet, error) {
	if e == nil {
		return TokenSet{}, fmt.Errorf("auth not configured")
	}

	if !e.config.IsM2MEnabled() {
		return TokenSet{}, fmt.Errorf("M2M auth not configured")
	}

	client, ok := e.GetClient(clientID)
	if !ok {
		return TokenSet{}, fmt.Errorf("invalid client_id")
	}

	if client.ClientSecret != clientSecret {
		return TokenSet{}, fmt.Errorf("invalid client_secret")
	}

	signingContext := jwt.MapClaims{
		"sub":         clientID,
		"azp":         clientID,
		"auth_method": string(AuthMethodOAuth2),
		"grant_type":  "client_credentials",
	}

	// Determine granted scopes, filtered by the client's AllowedScopes if configured.
	requestedScopes := strings.Split(scope, " ")
	grantedScopes := []string{}
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		if len(client.AllowedScopes) > 0 && !slices.Contains(client.AllowedScopes, s) {
			return TokenSet{}, fmt.Errorf("scope %s not allowed for this client", s)
		}
		grantedScopes = append(grantedScopes, s)
	}
	grantedScopeStr := strings.Join(grantedScopes, " ")
	if grantedScopeStr != "" {
		signingContext["scope"] = grantedScopeStr
	}

	// Resolve the client's roles/entitlements via the same resolver every other
	// grant type already uses (password -> FindInternal; authorization_code,
	// refresh_token and OIDC token-exchange -> FindInternalRolesAndEntitlements),
	// so a client_credentials token carries an authorization context the proxy
	// identity gate can evaluate. Without this the token verifies cleanly but
	// 404s on every secured function path. Gated on requested scope; when no
	// scope is requested, default to including both (mirrors LoginLocal's
	// default-scope set). See kdex-tech/host-manager#105.
	wantRoles := len(grantedScopes) == 0 || slices.Contains(grantedScopes, "roles")
	wantEntitlements := len(grantedScopes) == 0 || slices.Contains(grantedScopes, "entitlements")
	if wantRoles || wantEntitlements {
		roles, entitlements, rerr := e.ResolveInternalRolesAndEntitlements(clientID)
		if rerr != nil {
			return TokenSet{}, fmt.Errorf("failed to resolve roles/entitlements for client %s: %w", clientID, rerr)
		}
		if wantRoles {
			signingContext["roles"] = roles
		}
		if wantEntitlements {
			signingContext["entitlements"] = entitlements
		}
	}

	accessToken, err := e.config.Signer.Sign(signingContext)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	// client_credentials does not issue refresh tokens (M2M flows re-authenticate directly).
	return TokenSet{
		AccessToken: accessToken,
		Scope:       grantedScopeStr,
		Subject:     clientID,
	}, nil
}

func (e *Exchanger) LoginLocal(ctx context.Context, username, password, scope, clientID string, authMethod AuthMethod) (TokenSet, error) {
	if e == nil || !e.config.IsAuthEnabled() {
		return TokenSet{}, fmt.Errorf("local auth not configured")
	}

	signingContext, err := e.sp.FindInternal(username, password)
	if err != nil {
		return TokenSet{}, err
	}

	switch authMethod {
	case AuthMethodLocal:
		signingContext["auth_method"] = string(AuthMethodLocal)
	case AuthMethodOAuth2:
		signingContext["auth_method"] = string(AuthMethodOAuth2)
	default:
		return TokenSet{}, fmt.Errorf("unsupported local login auth method: %s", authMethod)
	}

	// Determine granted scopes and filter claims
	requestedScopes := strings.Split(scope, " ")
	if scope == "" {
		// Default scopes for local login if none requested
		requestedScopes = []string{"email", "entitlements", "openid", "profile", "roles"}
	}

	grantedScopes := []string{}
	hasScope := func(s string) bool {
		return slices.Contains(requestedScopes, s)
	}

	// openid scope
	if hasScope("openid") {
		grantedScopes = append(grantedScopes, "openid")
	}

	// email scope
	if hasScope("email") {
		grantedScopes = append(grantedScopes, "email")
	} else {
		delete(signingContext, "email")
	}

	// profile scope
	if hasScope("profile") {
		grantedScopes = append(grantedScopes, "profile")
	} else {
		delete(signingContext, "family_name")
		delete(signingContext, "given_name")
		delete(signingContext, "middle_name")
		delete(signingContext, "name")
		delete(signingContext, "nickname")
		delete(signingContext, "picture")
		delete(signingContext, "updated_at")
	}

	// entitlements and roles
	if hasScope("entitlements") {
		grantedScopes = append(grantedScopes, "entitlements")
	} else {
		delete(signingContext, "entitlements")
	}
	if hasScope("roles") {
		grantedScopes = append(grantedScopes, "roles")
	} else {
		delete(signingContext, "roles")
	}

	// Map any remaining identity scopes
	if sc, ok := signingContext["scope"].(string); ok && sc != "" {
		for s := range strings.SplitSeq(sc, " ") {
			if !slices.Contains(grantedScopes, s) {
				grantedScopes = append(grantedScopes, s)
			}
		}
	}

	grantedScopeStr := strings.Join(grantedScopes, " ")
	if grantedScopeStr != "" {
		signingContext["scope"] = grantedScopeStr
	}

	accessToken, err := e.config.Signer.Sign(signingContext)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idTokenContext := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idTokenContext, signingContext)
		idTokenContext["aud"] = clientID
		delete(idTokenContext, "scope")
		idToken, err = e.config.Signer.Sign(idTokenContext)
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to sign id token: %w", err)
		}
	}

	ts := TokenSet{
		AccessToken: accessToken,
		IDToken:     idToken,
		Scope:       grantedScopeStr,
		Subject:     username,
	}

	if e.IsRefreshTokenEnabled() {
		ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: authMethod,
			ClientID:   clientID,
			Scope:      grantedScopeStr,
			Subject:    username,
		})
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to create refresh token: %w", err)
		}
	}

	return ts, nil
}

// RedeemAuthorizationCode validates and exchanges an authorization code for a TokenSet.
func (e *Exchanger) RedeemAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (TokenSet, error) {
	if e == nil {
		return TokenSet{}, fmt.Errorf("auth not configured")
	}

	// 1. Parse JWE
	object, err := jose.ParseEncrypted(code, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to parse auth code: %w", err)
	}

	// 2. Derive Key
	key := sha256.Sum256([]byte(e.config.OIDC.BlockKey))

	// 3. Decrypt
	decrypted, err := object.Decrypt(key[:])
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to decrypt auth code: %w", err)
	}

	var claims AuthorizationCodeClaims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return TokenSet{}, fmt.Errorf("failed to unmarshal auth code claims: %w", err)
	}

	// 4. Validate
	if time.Now().Unix() > claims.Exp {
		return TokenSet{}, fmt.Errorf("authorization code expired")
	}

	if claims.ClientID != clientID {
		return TokenSet{}, fmt.Errorf("client_id mismatch")
	}

	if claims.RedirectURI != redirectURI {
		return TokenSet{}, fmt.Errorf("redirect_uri mismatch")
	}

	client, ok := e.GetClient(clientID)
	if !ok {
		return TokenSet{}, fmt.Errorf("invalid client_id")
	}

	// PKCE verification
	if client.RequirePKCE && claims.CodeChallenge == "" {
		return TokenSet{}, fmt.Errorf("PKCE is required for this client")
	}

	if claims.CodeChallenge != "" {
		if codeVerifier == "" {
			return TokenSet{}, fmt.Errorf("code_verifier is required for PKCE")
		}

		// Only S256 is accepted. Pre-#96 the `plain` and empty-method
		// branches made code-verifier verification a literal string
		// compare against the unhashed challenge, allowing an attacker
		// who could intercept the code to redeem it with any matching
		// verifier of their choosing — a PKCE downgrade. RFC 7636
		// §4.2 has considered plain unsafe since 2015.
		if claims.CodeChallengeMethod != PKCE_METHOD_S256 {
			return TokenSet{}, fmt.Errorf("unsupported code_challenge_method: only S256 is accepted")
		}
		h := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != claims.CodeChallenge {
			return TokenSet{}, fmt.Errorf("invalid code_verifier")
		}
	}

	// 5. Single-use enforcement (RFC 6749 §10.5). Atomic GetAndDelete
	// closes the concurrent-redeem race that the pre-#71 Get-then-
	// Delete pair left open: two simultaneous redemptions of the same
	// code would both pass Get before either reached Delete. With
	// GetAndDelete only one caller observes found=true; the loser is
	// rejected as a replay. Skipped only when no cache is configured.
	// See kdex-tech/host-manager#65 (single-use) and #71 (atomicity).
	if e.authCodeCache != nil {
		if claims.JTI == "" {
			// Pre-#65 codes have no JTI; treat as already-consumed
			// rather than honour them — the upgrade window is the
			// 10-minute code expiry, well under the typical deploy
			// rollout.
			return TokenSet{}, fmt.Errorf("authorization code already consumed or expired")
		}
		_, found, _, err := e.authCodeCache.GetAndDelete(ctx, claims.JTI)
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to check auth code consumption: %w", err)
		}
		if !found {
			return TokenSet{}, fmt.Errorf("authorization code already consumed or expired")
		}
	}

	// 6. Mint tokens — subject is known from the decrypted code claims.
	return e.mintTokensFromCode(ctx, claims)
}

// RedeemRefreshToken validates and consumes a refresh token (one-time use / rotation),
// then returns a fresh TokenSet including a rotated refresh token.
func (e *Exchanger) RedeemRefreshToken(ctx context.Context, tokenID, clientID string) (TokenSet, error) {
	if !e.IsRefreshTokenEnabled() {
		return TokenSet{}, fmt.Errorf("refresh token storage not configured")
	}

	// Atomic GetAndDelete is what makes rotation actually single-use
	// under concurrent redemptions. Pre-#71 the Get-then-Delete pattern
	// let two simultaneous redemptions of the same refresh token both
	// pass Get before either reached Delete; both then minted parallel
	// session lineages that rotation never detected.
	raw, found, _, err := e.refreshTokenCache.GetAndDelete(ctx, tokenID)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to read refresh token: %w", err)
	}
	if !found {
		return TokenSet{}, fmt.Errorf("refresh token not found or expired")
	}

	var claims RefreshTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return TokenSet{}, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Validate expiry (belt-and-suspenders; cache TTL should cover this).
	// The token is already consumed by GetAndDelete above, so we just
	// reject and let the caller re-authenticate.
	if time.Now().Unix() > claims.ExpiresAt {
		return TokenSet{}, fmt.Errorf("refresh token expired")
	}

	// Validate absolute session timeout
	if e.maxSessionAge > 0 && time.Since(time.Unix(claims.OriginalIssuedAt, 0)) > e.maxSessionAge {
		return TokenSet{}, fmt.Errorf("session absolute timeout reached")
	}

	// Validate the client matches what was issued.
	if claims.ClientID != clientID {
		return TokenSet{}, fmt.Errorf("refresh token was not issued to this client")
	}

	// Mint fresh tokens — re-resolves roles/entitlements for freshness.
	ts, err := e.mintTokensFromSubject(claims.Subject, claims.ClientID, claims.Scope, claims.AuthMethod)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to mint tokens from refresh: %w", err)
	}

	// Rotate: issue a new refresh token.
	ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod:       claims.AuthMethod,
		ClientID:         claims.ClientID,
		OriginalIssuedAt: claims.OriginalIssuedAt,
		Scope:            claims.Scope,
		Subject:          claims.Subject,
	})
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return ts, nil
}

func (e *Exchanger) verifyIDToken(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return nil, fmt.Errorf("OIDC is not configured")
	}
	return e.oidcVerifier.Verify(ctx, rawIDToken)
}

type OIDCProviderClaims struct {
	EndSessionURL   string   `json:"end_session_endpoint"`
	ScopesSupported []string `json:"scopes_supported"`
}

type AuthorizationCodeClaims struct {
	AuthMethod          AuthMethod `json:"auth_method"`
	ClientID            string     `json:"cid"`
	CodeChallenge       string     `json:"challenge,omitempty"`
	CodeChallengeMethod string     `json:"challenge_method,omitempty"`
	Exp                 int64      `json:"exp"`
	// JTI is the random per-code identifier used to enforce single-use
	// semantics. Set on mint, looked up + deleted on redeem. See
	// kdex-tech/host-manager#65.
	JTI         string `json:"jti,omitempty"`
	RedirectURI string `json:"uri"`
	// Resource is the RFC 8707 resource indicator supplied by the client
	// during the authorization request. It is encrypted inside the auth
	// code JWE and can be inspected by the token endpoint if needed.
	Resource string `json:"resource,omitempty"`
	Scope    string `json:"scp"`
	Subject  string `json:"sub"`
}

func (e *Exchanger) CreateAuthorizationCode(ctx context.Context, claims AuthorizationCodeClaims) (string, error) {
	if e == nil {
		return "", fmt.Errorf("auth not configured")
	}

	// 1. Prepare the payload
	// Set expiration if not set (e.g. 10 minutes)
	if claims.Exp == 0 {
		claims.Exp = time.Now().Add(10 * time.Minute).Unix()
	}
	// Random per-code JTI for single-use tracking. Sized so collisions
	// across the issuing host's lifetime are negligible. See #65.
	if claims.JTI == "" {
		jtiBytes := make([]byte, 16)
		if _, err := rand.Read(jtiBytes); err != nil {
			return "", fmt.Errorf("failed to generate auth code jti: %w", err)
		}
		claims.JTI = base64.RawURLEncoding.EncodeToString(jtiBytes)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth code claims: %w", err)
	}

	// Register the JTI as "unredeemed" in the consumption cache so
	// RedeemAuthorizationCode can enforce single-use. If no cache is
	// configured we fall back to the pre-#65 stateless behaviour
	// (vulnerable, but compatible with cache-less setups).
	if e.authCodeCache != nil {
		if err := e.authCodeCache.Set(ctx, claims.JTI, "1"); err != nil {
			return "", fmt.Errorf("failed to register auth code jti: %w", err)
		}
	}

	// 2. Derive Key
	key := sha256.Sum256([]byte(e.config.OIDC.BlockKey))

	// 3. Encrypt
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key[:]}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	object, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt auth code: %w", err)
	}

	return object.CompactSerialize()
}

// mintTokensFromCode mints access + id tokens from the claims carried in an authorization code.
// It also creates a refresh token if storage is configured.
func (e *Exchanger) mintTokensFromCode(ctx context.Context, claims AuthorizationCodeClaims) (TokenSet, error) {
	signingContext := jwt.MapClaims{}

	signingContext["sub"] = claims.Subject
	signingContext["auth_method"] = claims.AuthMethod

	// Resolve Roles/Entitlements fresh.
	roles, entitlements, err := e.sp.FindInternalRolesAndEntitlements(claims.Subject)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to resolve roles: %w", err)
	}
	signingContext["roles"] = roles
	signingContext["entitlements"] = entitlements

	// Handle Scopes
	requestedScopes := strings.Split(claims.Scope, " ")
	grantedScopes := []string{}
	hasScope := func(s string) bool {
		return slices.Contains(requestedScopes, s)
	}

	if hasScope("openid") {
		grantedScopes = append(grantedScopes, "openid")
	}
	if hasScope("email") {
		grantedScopes = append(grantedScopes, "email")
	}
	if hasScope("profile") {
		grantedScopes = append(grantedScopes, "profile")
	}
	// Mirror mintTokensFromSubject: when the client did not request the
	// entitlements or roles scope, strip those claims from the signing
	// context so the access-token JWT doesn't leak them. Pre-fix
	// mintTokensFromCode set both claims unconditionally and the scope
	// claim disagreed with the claims actually present — downstream
	// consumers trusting either side reached different access
	// decisions, and the same session lost the leaked claims after the
	// first refresh (since mintTokensFromSubject filters correctly).
	// See kdex-tech/host-manager#80.
	if hasScope("entitlements") {
		grantedScopes = append(grantedScopes, "entitlements")
	} else {
		delete(signingContext, "entitlements")
	}
	if hasScope("roles") {
		grantedScopes = append(grantedScopes, "roles")
	} else {
		delete(signingContext, "roles")
	}

	// Pass through any other requested scopes.
	for _, s := range requestedScopes {
		if !slices.Contains(grantedScopes, s) && s != "" {
			grantedScopes = append(grantedScopes, s)
		}
	}

	grantedScopeStr := strings.Join(grantedScopes, " ")
	if grantedScopeStr != "" {
		signingContext["scope"] = grantedScopeStr
	}

	accessToken, err := e.config.Signer.Sign(signingContext)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idTokenContext := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idTokenContext, signingContext)
		idTokenContext["aud"] = claims.ClientID
		delete(idTokenContext, "scope")
		idToken, err = e.config.Signer.Sign(idTokenContext)
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to sign id token: %w", err)
		}
	}

	ts := TokenSet{
		AccessToken: accessToken,
		IDToken:     idToken,
		Scope:       grantedScopeStr,
		Subject:     claims.Subject,
	}

	if e.IsRefreshTokenEnabled() {
		ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: claims.AuthMethod,
			ClientID:   claims.ClientID,
			Scope:      grantedScopeStr,
			Subject:    claims.Subject,
		})
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to create refresh token: %w", err)
		}
	}

	return ts, nil
}

// mintTokensFromSubject re-mints tokens for a known-authenticated subject (used by the refresh flow).
// It re-resolves roles/entitlements to ensure freshness.
func (e *Exchanger) mintTokensFromSubject(subject, clientID, scope string, authMethod AuthMethod) (TokenSet, error) {
	roles, entitlements, err := e.sp.FindInternalRolesAndEntitlements(subject)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to resolve roles: %w", err)
	}

	signingContext := jwt.MapClaims{
		"auth_method":  string(authMethod),
		"entitlements": entitlements,
		"roles":        roles,
		"sub":          subject,
	}

	requestedScopes := strings.Split(scope, " ")
	grantedScopes := []string{}
	hasScope := func(s string) bool { return slices.Contains(requestedScopes, s) }

	if hasScope("openid") {
		grantedScopes = append(grantedScopes, "openid")
	}
	if hasScope("email") {
		grantedScopes = append(grantedScopes, "email")
	}
	if hasScope("profile") {
		grantedScopes = append(grantedScopes, "profile")
	}
	if hasScope("entitlements") {
		grantedScopes = append(grantedScopes, "entitlements")
	} else {
		delete(signingContext, "entitlements")
	}
	if hasScope("roles") {
		grantedScopes = append(grantedScopes, "roles")
	} else {
		delete(signingContext, "roles")
	}
	for _, s := range requestedScopes {
		if s != "" && !slices.Contains(grantedScopes, s) {
			grantedScopes = append(grantedScopes, s)
		}
	}

	grantedScope := strings.Join(grantedScopes, " ")
	if grantedScope != "" {
		signingContext["scope"] = grantedScope
	}

	accessToken, err := e.config.Signer.Sign(signingContext)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idCtx := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idCtx, signingContext)
		idCtx["aud"] = clientID
		delete(idCtx, "scope")
		idToken, err = e.config.Signer.Sign(idCtx)
		if err != nil {
			return TokenSet{}, fmt.Errorf("failed to sign id token: %w", err)
		}
	}

	return TokenSet{
		AccessToken: accessToken,
		IDToken:     idToken,
		Scope:       grantedScope,
		Subject:     subject,
	}, nil
}

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ErrServerError marks a failure of OUR infrastructure — a cache read, a
// signing operation, a stored-record unmarshal — as distinct from a failure
// of the client's grant. The token endpoint maps it to RFC 6749 5.2's
// server_error (500) rather than invalid_grant (400), because telling a
// client its credential is dead during a transient outage makes it discard
// a working refresh token and re-authorize for no reason. See
// kdex-tech/host-manager#168.
var ErrServerError = errors.New("server error")

// ErrGrantFailure marks a rejection that is genuinely ABOUT the grant the
// caller presented — not found, expired, mismatched, already consumed — and
// is therefore safe to describe back to an unauthenticated caller. This is
// an opt-in allowlist, not a fallthrough: RedeemRefreshToken and
// RedeemAuthorizationCode call out to mintTokensFromCode, LoginLocal and
// LoginClient, whose infrastructure failures (signer down, identity-provider
// HTTP lookup down, resolver down) are NOT marked with this and must not
// have their message echoed — a raw HTTP dial error can carry an internal
// service URL and pod IP. The token endpoint's classifier
// (oauthErrorForRedemption) treats anything carrying neither this nor
// ErrServerError as a grant failure too, but with a fixed generic
// description rather than its own message: a future error added anywhere in
// the call graph that forgets to mark itself must disclose nothing. See
// kdex-tech/host-manager#168.
//
// Errors are classified against this sentinel via errors.Is, but are never
// built by wrapping it with fmt.Errorf("%w: ...", ErrGrantFailure) — doing
// so would put ErrGrantFailure's own "grant failure" text on the wire ahead
// of the actual message (e.g. "grant failure: refresh token not found or
// expired" instead of the exact string #168's reporter is matching on).
// Build grant-failure errors with grantFailuref instead: it classifies
// against this sentinel via the errors.Is opt-in Is(error) bool hook, with
// the message left untouched.
var ErrGrantFailure = errors.New("grant failure")

// grantFailureError carries a client-facing rejection message and classifies
// as ErrGrantFailure without that sentinel's own text ever appearing in
// Error(). See grantFailuref and the ErrGrantFailure doc comment above.
type grantFailureError string

func (e grantFailureError) Error() string { return string(e) }

// Is implements the errors.Is opt-in hook documented on the errors package:
// errors.Is(err, ErrGrantFailure) calls this method with target set to
// ErrGrantFailure, letting a plain string-backed error type classify as the
// sentinel without embedding the sentinel's text.
func (e grantFailureError) Is(target error) bool { return target == ErrGrantFailure }

// grantFailuref builds a grantFailureError, printf-style. Use it (directly,
// or via a function-local grantFailed closure that also attaches the known
// Subject, mirroring the existing failed closures) at rejections that are
// genuinely ABOUT the presented grant.
func grantFailuref(format string, args ...any) error {
	return grantFailureError(fmt.Sprintf(format, args...))
}

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
	// refreshGraceCache and refreshGraceWindow implement the #169 rotation
	// grace window: refreshGraceCache is nil (and replayFromGrace/
	// publishToGrace are no-ops) unless Config.RefreshGraceWindow > 0.
	refreshGraceCache  cache.Cache
	refreshGraceWindow time.Duration
	// authCodeCache tracks the JTI of every unredeemed authorization code.
	// On RedeemAuthorizationCode the JTI is Get-then-Delete'd; an absent
	// JTI signals replay (or expiry) and the redemption is rejected. See
	// kdex-tech/host-manager#65 (RFC 6749 §10.5 single-use requirement).
	authCodeCache cache.Cache
	// subjectResolveCache briefly memoizes the password-less backend claim
	// resolve backend claim the token bridge does per request, so a burst of
	// PAT/OAuth calls from one subject doesn't hit the backend every time. Short
	// TTL keeps grants fresh (the point of #138). Keyed by subject.
	subjectResolveCache cache.Cache
	maxSessionAge       time.Duration
	sp                  InternalIdentityProvider
}

// subjectResolveCacheTTL bounds how stale a bridged caller's re-resolved backend
// claims can be. Short by design — the whole point of the fresh resolve is that
// a membership change reflects quickly (unlike a login-time snapshot).
const subjectResolveCacheTTL = 60 * time.Second

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

// TokenSet is the result of a token minting operation.
//
// On success every field is populated as the grant allows. On failure the
// zero value is returned EXCEPT for Subject, which is set whenever the
// failing operation had already established a server-vouched subject --
// decrypted authorization-code claims, a stored refresh-token record, a
// credential-store hit, or an authenticated client. This lets the token
// endpoint attribute a rejected exchange to an identity instead of logging
// `"subject": ""`. See kdex-tech/host-manager#158.
//
// Callers must still gate on the returned error: a non-empty Subject says
// who the request was about, never that it succeeded.
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
		// Short-lived memoization of the token-bridge backend claim resolve. See #138.
		srTTL := subjectResolveCacheTTL
		ex.subjectResolveCache = cacheManager.GetCache("subject-resolve", cache.CacheOptions{
			TTL:      &srTTL,
			Uncycled: true,
		})
		// Grace window for concurrent refresh presentations (#169). Holds
		// the winner's MINTED RESULT keyed by the CONSUMED token id, so
		// losers replay it rather than minting a second lineage.
		if cfg.RefreshGraceWindow > 0 {
			gw := cfg.RefreshGraceWindow
			ex.refreshGraceWindow = gw
			ex.refreshGraceCache = cacheManager.GetCache("refresh-grace", cache.CacheOptions{
				TTL:      &gw,
				Uncycled: true,
			})
		}
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

// ResolveSubjectClaims resolves a subject's data-driven backend claims (e.g.
// a backend claim) FRESH and password-lessly for the token bridge, memoized for
// a short window to bound backend load. Returns nil when the identity provider
// can't resolve them (e.g. no http-lookup resolve endpoint wired), so the bridge
// degrades to role-only entitlements. See kdex-tech/host-manager#138.
func (e *Exchanger) ResolveSubjectClaims(subject string) jwt.MapClaims {
	if e == nil || subject == "" {
		return nil
	}
	if e.subjectResolveCache != nil {
		if raw, found, _, err := e.subjectResolveCache.Get(context.Background(), subject); err == nil && found && raw != "" {
			var claims jwt.MapClaims
			if json.Unmarshal([]byte(raw), &claims) == nil {
				return claims
			}
		}
	}
	// Optional capability: only the cluster-backed scopeProvider resolves
	// backend claims. Test stubs and other providers simply don't, so the
	// bridge gets nil (role-only) without every InternalIdentityProvider having
	// to implement it.
	resolver, ok := e.sp.(interface {
		ResolveClaims(string) jwt.MapClaims
	})
	if !ok {
		return nil
	}
	claims := resolver.ResolveClaims(subject)
	if e.subjectResolveCache != nil && len(claims) > 0 {
		if payload, err := json.Marshal(claims); err == nil {
			_ = e.subjectResolveCache.Set(context.Background(), subject, string(payload))
		}
	}
	return claims
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
		// Deployment/config facts, not anything the client presented. See
		// kdex-tech/host-manager#168 review round 2.
		return TokenSet{}, fmt.Errorf("%w: auth not configured", ErrServerError)
	}

	if !e.config.IsM2MEnabled() {
		return TokenSet{}, fmt.Errorf("%w: M2M auth not configured", ErrServerError)
	}

	client, ok := e.GetClient(clientID)
	if !ok {
		return TokenSet{}, fmt.Errorf("invalid client_id")
	}

	if client.ClientSecret != clientSecret {
		return TokenSet{}, fmt.Errorf("invalid client_secret")
	}

	// The client has now authenticated, so clientID is a vouched subject --
	// this grant's subject IS the client (see `sub` below). Deliberately not
	// set on the two rejections above: an unauthenticated caller can assert
	// any client_id, and an audit log that cannot distinguish an asserted
	// identity from a verified one is worse than one that stays silent.
	// See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: clientID}, fmt.Errorf(format, args...)
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
			return failed("scope %s not allowed for this client", s)
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
			// Resolver failure, not a fact about the presented client
			// credentials (already verified above). See #168 round 2.
			return failed("%w: failed to resolve roles/entitlements for client %s: %v", ErrServerError, clientID, rerr)
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
		return failed("%w: failed to sign access token: %v", ErrServerError, err)
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
		// Deployment/config fact, not anything the client presented. See
		// kdex-tech/host-manager#168 review round 2.
		return TokenSet{}, fmt.Errorf("%w: local auth not configured", ErrServerError)
	}

	signingContext, err := e.sp.FindInternal(username, password)
	if err != nil {
		// Credentials did not resolve, so there is no vouched subject to
		// report. The handler still logs `username`, which is the only
		// identity handle that exists at this point.
		//
		// Deliberately NOT marked ErrServerError, even though #168 round
		// 2's review flagged this as "the httpLookup dial case": this same
		// return value ALSO carries genuinely client-caused rejections.
		// scopeProvider.FindInternal (roles.go) folds a lookup's transport
		// failure and its explicit "backend says these credentials are
		// wrong" answer into the identical `error` return -- see
		// httpLookup.FindInternal in lookup_http.go, whose `!parsed.OK`
		// branch (an ordinary wrong-password rejection, HTTP 200 from the
		// backend) and its dial/decode failures both surface as `err` here
		// with no way to tell them apart. Marking ErrServerError would
		// turn every routine bad-password ROPC attempt into 500
		// server_error. The classifier's post-#168-round-1 safe default
		// (neither sentinel -> 400 invalid_grant, fixed generic
		// description, cause logged only) already closes the disclosure
		// this was flagged for, without that misclassification cost.
		// Flagged for the repo owner rather than guessed at; see the task
		// report.
		return TokenSet{}, err
	}

	// The credential store has vouched for this identity, so from here the
	// subject is known. Use `username` to match this function's success path
	// (and the refresh-token claims it mints), so the same request reports
	// the same subject whether it succeeds or fails.
	// See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: username}, fmt.Errorf(format, args...)
	}

	// The credential store establishes identity (sub) but must not set reserved
	// auth-flow / mint-time claims — strip them so a misbehaving backend cannot
	// inject scope/scp/idp/grant_type/exp/… The mint sets auth_method (below) and
	// scope (applyScopeFilter) authoritatively. See kdex-tech/host-manager#140.
	for k := range reservedMintClaims {
		if k == "sub" {
			continue
		}
		delete(signingContext, k)
	}

	switch authMethod {
	case AuthMethodLocal:
		signingContext["auth_method"] = string(AuthMethodLocal)
	case AuthMethodOAuth2:
		signingContext["auth_method"] = string(AuthMethodOAuth2)
	default:
		return failed("unsupported local login auth method: %s", authMethod)
	}

	// Determine granted scopes; claim confinement of the scope-controlled
	// families (email/profile/entitlements/roles) happens post-mapper in
	// SignScoped, so it holds regardless of what ClaimMappings injected — this
	// also closes the latent leak the old pre-mapper strip had. Default to the
	// full identity set when the client requested no scope (local-login default).
	grantedScopes := applyScopeFilter(signingContext, scope,
		[]string{"email", "entitlements", "openid", "profile", "roles"})
	grantedScopeStr := strings.Join(grantedScopes, " ")

	accessToken, err := e.config.Signer.SignScoped(signingContext, grantedScopes)
	if err != nil {
		return failed("%w: failed to sign access token: %v", ErrServerError, err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idTokenContext := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idTokenContext, signingContext)
		idTokenContext["aud"] = clientID
		delete(idTokenContext, "scope")
		idToken, err = e.config.Signer.SignScoped(idTokenContext, grantedScopes)
		if err != nil {
			return failed("%w: failed to sign id token: %v", ErrServerError, err)
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
			return TokenSet{}, fmt.Errorf("%w: failed to create refresh token: %v", ErrServerError, err)
		}
	}

	return ts, nil
}

// RedeemAuthorizationCode validates and exchanges an authorization code for a TokenSet.
func (e *Exchanger) RedeemAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (TokenSet, error) {
	if e == nil {
		return TokenSet{}, fmt.Errorf("%w: auth not configured", ErrServerError)
	}

	// 1. Parse JWE
	object, err := jose.ParseEncrypted(code, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		// The presented code itself is malformed -- that is ABOUT the
		// grant, not our infrastructure, so it is safe to describe.
		return TokenSet{}, grantFailuref("failed to parse auth code: %v", err)
	}

	// 2. Derive Key
	key := sha256.Sum256([]byte(e.config.OIDC.BlockKey))

	// 3. Decrypt
	decrypted, err := object.Decrypt(key[:])
	if err != nil {
		// Same reasoning: a caller-presented ciphertext that does not
		// decrypt against our current key is an invalid grant.
		return TokenSet{}, grantFailuref("failed to decrypt auth code: %v", err)
	}

	var claims AuthorizationCodeClaims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to unmarshal auth code claims: %v", ErrServerError, err)
	}

	// From here the subject is known and server-vouched: it came out of a
	// JWE we minted and just decrypted with our own block key, so it is not
	// caller-assertable. Every failure below returns it for audit logging --
	// a rejected redemption is exactly when an operator needs to know WHOSE
	// code was rejected. See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: claims.Subject}, fmt.Errorf(format, args...)
	}
	// grantFailed is `failed` for rejections that are genuinely ABOUT the
	// presented grant (expiry, binding mismatches, PKCE): same Subject
	// attribution, but the error classifies as ErrGrantFailure so the token
	// endpoint's classifier echoes the message. "invalid client_id" below
	// deliberately still goes through plain `failed`: it fires only if the
	// client was deleted between the handler's earlier lookup and here, is
	// not one of the enumerated safe categories, and defaults closed.
	grantFailed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: claims.Subject}, grantFailuref(format, args...)
	}

	// 4. Validate.
	if time.Now().Unix() > claims.Exp {
		return grantFailed("authorization code expired")
	}

	if claims.ClientID != clientID {
		return grantFailed("client_id mismatch")
	}

	if claims.RedirectURI != redirectURI {
		return grantFailed("redirect_uri mismatch")
	}

	client, ok := e.GetClient(clientID)
	if !ok {
		return failed("invalid client_id")
	}

	// PKCE verification
	if client.RequirePKCE && claims.CodeChallenge == "" {
		return grantFailed("PKCE is required for this client")
	}

	if claims.CodeChallenge != "" {
		if codeVerifier == "" {
			return grantFailed("code_verifier is required for PKCE")
		}

		// Only S256 is accepted. Pre-#96 the `plain` and empty-method
		// branches made code-verifier verification a literal string
		// compare against the unhashed challenge, allowing an attacker
		// who could intercept the code to redeem it with any matching
		// verifier of their choosing — a PKCE downgrade. RFC 7636
		// §4.2 has considered plain unsafe since 2015.
		if claims.CodeChallengeMethod != PKCE_METHOD_S256 {
			return grantFailed("unsupported code_challenge_method: only S256 is accepted")
		}
		h := sha256.Sum256([]byte(codeVerifier))
		challenge := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != claims.CodeChallenge {
			return grantFailed("invalid code_verifier")
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
			return grantFailed("authorization code already consumed or expired")
		}
		_, found, _, err := e.authCodeCache.GetAndDelete(ctx, claims.JTI)
		if err != nil {
			return failed("%w: failed to check auth code consumption: %v", ErrServerError, err)
		}
		if !found {
			// Replay, or a legitimate code past its window. Either way the
			// subject is the operationally interesting part.
			return grantFailed("authorization code already consumed or expired")
		}
	}

	// 6. Mint tokens — subject is known from the decrypted code claims.
	return e.mintTokensFromCode(ctx, claims)
}

// RedeemRefreshToken validates and consumes a refresh token (one-time use / rotation),
// then returns a fresh TokenSet including a rotated refresh token.
func (e *Exchanger) RedeemRefreshToken(ctx context.Context, tokenID, clientID string) (TokenSet, error) {
	if !e.IsRefreshTokenEnabled() {
		// This is a server misconfiguration (refresh tokens were never set
		// up), not a fact about the presented token — the client did
		// nothing wrong. See kdex-tech/host-manager#168 review round 2.
		return TokenSet{}, fmt.Errorf("%w: refresh token storage not configured", ErrServerError)
	}

	// Atomic GetAndDelete is what makes rotation actually single-use
	// under concurrent redemptions. Pre-#71 the Get-then-Delete pattern
	// let two simultaneous redemptions of the same refresh token both
	// pass Get before either reached Delete; both then minted parallel
	// session lineages that rotation never detected.
	raw, found, _, err := e.refreshTokenCache.GetAndDelete(ctx, tokenID)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to read refresh token: %v", ErrServerError, err)
	}
	if !found {
		// A concurrent caller may have won the rotation microseconds ago.
		// Replay its result rather than failing this one (#169). A non-nil
		// graceErr is already fully classified by replayFromGrace: either
		// ErrServerError (the grace cache itself is unreadable/corrupt, or
		// our own poll was canceled -- OUR infrastructure, not a fact
		// about the presented token) or a grantFailuref client_id mismatch
		// (see below) -- so it is safe to return verbatim either way.
		// `replayed` carries Subject attribution on the mismatch path
		// (#158) and is the zero value on every other error path, so
		// returning it alongside graceErr is correct for both.
		replayed, ok, graceErr := e.replayFromGrace(ctx, tokenID, clientID)
		if graceErr != nil {
			return replayed, graceErr
		}
		if ok {
			return replayed, nil
		}
		// This is the literal kdex-tech/host-manager#168 reproduction: a
		// dead/unknown refresh token is squarely ABOUT the presented grant,
		// so it is marked safe to describe.
		return TokenSet{}, grantFailuref("refresh token not found or expired")
	}

	var claims RefreshTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to parse refresh token: %v", ErrServerError, err)
	}

	// The stored record is ours, so from here the subject is known and
	// server-vouched. Carry it on every rejection below -- these are the
	// cases an operator most needs attributed (a client stuck refreshing
	// against the wrong client_id, a session hitting its absolute cap).
	// See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: claims.Subject}, fmt.Errorf(format, args...)
	}
	// grantFailed is `failed` for rejections genuinely ABOUT the presented
	// grant; see the identical comment in RedeemAuthorizationCode above.
	grantFailed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: claims.Subject}, grantFailuref(format, args...)
	}

	// The token is consumed and its record is known-good: mark it
	// in-flight for the grace window BEFORE the (comparatively slow)
	// validation/minting work below, so a concurrent loser's poll can tell
	// "a rotation for this exact token is under way" from "nothing is
	// happening, don't bother polling" -- the common case of a bogus or
	// already-expired token presented with no concurrent redemption at all
	// (kdex-tech/host-manager#169 fix round 2, cost finding). Cleared again
	// on any rejection below via the deferred cleanup so a loser's poll
	// sees the marker vanish and stops immediately rather than waiting out
	// the full budget for a result that will never come -- the marker
	// never survives long enough to be a second "publish" of anything a
	// rejected redemption produced (that property -- a rejected redemption
	// publishes no RESULT -- is unchanged; see publishToGrace below).
	e.markGraceInFlight(ctx, tokenID, claims.ClientID)
	published := false
	defer func() {
		if !published {
			e.clearGraceInFlight(ctx, tokenID)
		}
	}()

	// Validate expiry (belt-and-suspenders; cache TTL should cover this).
	// The token is already consumed by GetAndDelete above, so we just
	// reject and let the caller re-authenticate. All three rejections below
	// are genuinely ABOUT the presented grant, so they are marked
	// ErrGrantFailure and their message reaches the caller.
	if time.Now().Unix() > claims.ExpiresAt {
		return grantFailed("refresh token expired")
	}

	// Validate absolute session timeout
	if e.maxSessionAge > 0 && time.Since(time.Unix(claims.OriginalIssuedAt, 0)) > e.maxSessionAge {
		return grantFailed("session absolute timeout reached")
	}

	// Validate the client matches what was issued.
	if claims.ClientID != clientID {
		return grantFailed("refresh token was not issued to this client")
	}

	// Mint fresh tokens — re-resolves roles/entitlements for freshness.
	ts, err := e.mintTokensFromSubject(claims.Subject, claims.ClientID, claims.Scope, claims.AuthMethod)
	if err != nil {
		return failed("%w: failed to mint tokens from refresh: %v", ErrServerError, err)
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
		return failed("%w: failed to rotate refresh token: %v", ErrServerError, err)
	}

	// Publish the winner's result so any concurrent loser presenting the
	// SAME (now-consumed) tokenID within the grace window replays it
	// instead of minting a second lineage. Only a successful rotation
	// reaches here — a rejected redemption above returns before this
	// point (and its deferred cleanup removes the in-flight marker instead
	// of leaving anything published). See kdex-tech/host-manager#169.
	//
	// The record carries claims.ClientID -- the client the token was
	// ORIGINALLY issued to -- so a loser presenting a different client_id
	// against the same tokenID is rejected by replayFromGrace exactly as
	// the strict `claims.ClientID != clientID` check above would reject
	// it, instead of the grace window handing a live rotating credential
	// to a caller that never owned the session.
	e.publishToGrace(ctx, tokenID, claims.ClientID, ts)
	published = true

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
// subjectSigningContext resolves the full authorization context for a subject
// used by the non-password subject mints (authorization_code, refresh_token):
// the static KDexRole-derived roles/entitlements PLUS the fresh data-driven
// backend claims that only the credential backend knows.
// Folding the backend claims into the PRIMARY mint — upstream of every
// attenuation point — is what lets an OAuth/MCP access token (and everything
// attenuated from it: FAT, mint_token, scope down-scope) carry per-subject
// grants. Password login (LoginLocal) receives the same set for free from
// FindInternal's credential Lookup, so it does not use this. A nil/failed
// resolve degrades to role-only (never more). See kdex-tech/host-manager#140.
func (e *Exchanger) subjectSigningContext(subject string) (roles, entitlements []string, backend jwt.MapClaims, err error) {
	roles, entitlements, err = e.sp.FindInternalRolesAndEntitlements(subject)
	if err != nil {
		return nil, nil, nil, err
	}
	return roles, entitlements, e.ResolveSubjectClaims(subject), nil
}

// reservedMintClaims are claims the mint and signer control authoritatively; the
// authoritative user store (ResolveClaims / FindInternal) and ClaimMappings may
// supplement ANY other claim (roles, entitlements, email, custom
// …) — that is the feature — but must never set these. They split into
// auth-flow / identity claims (a backend-supplied `scope` would hijack scope
// confinement, `sub`/`idp` would rebind identity) and server-controlled mint-time
// values (`iat`/`exp`/`jti`/…). See kdex-tech/host-manager#140 (review hardening).
var reservedMintClaims = map[string]struct{}{
	"scope": {}, "scp": {}, "sub": {}, "grant_type": {}, "auth_method": {}, "idp": {},
	"iat": {}, "exp": {}, "jti": {}, "iss": {}, "aud": {}, "nbf": {},
}

// mergeBackendClaims folds a subject's data-driven backend claims into the
// signing context, skipping reservedMintClaims and never overwriting a claim
// already set. The subsequent Project runs the host ClaimMappings over the
// enriched context; this code never names a specific backend claim —
// such a claim is only an instance of a mapper input. See
// kdex-tech/host-manager#140.
func mergeBackendClaims(signingContext, backend jwt.MapClaims) {
	for k, v := range backend {
		if _, reserved := reservedMintClaims[k]; reserved {
			continue
		}
		if _, exists := signingContext[k]; !exists {
			signingContext[k] = v
		}
	}
}

// applyScopeFilter computes the granted OAuth scope set for a mint from the
// CLIENT-requested scopes (or defaultScopes when none was requested) and records
// it authoritatively in signingContext["scope"]; it does NOT strip claims.
// Confinement of the scope-controlled claim families (email/profile/entitlements/
// roles) happens post-mapper in Signer.SignScoped, so it holds regardless of what
// ClaimMappings injected. `scope` is a reserved, mint-controlled claim: this
// OVERWRITES (or clears) any value a backend or identity store placed on the
// context, so a user-store-supplied scope can never widen the granted set or the
// advertised scope. openid is returned so the caller can decide id_token
// issuance. See kdex-tech/host-manager#140, #80.
func applyScopeFilter(signingContext jwt.MapClaims, requestedScope string, defaultScopes []string) []string {
	requested := strings.Fields(requestedScope)
	if len(requested) == 0 && len(defaultScopes) > 0 {
		requested = defaultScopes
	}
	granted := []string{}
	for _, known := range []string{"openid", "email", "profile", "entitlements", "roles"} {
		if slices.Contains(requested, known) {
			granted = append(granted, known)
		}
	}
	for _, s := range requested {
		if s != "" && !slices.Contains(granted, s) {
			granted = append(granted, s)
		}
	}
	if len(granted) > 0 {
		signingContext["scope"] = strings.Join(granted, " ")
	} else {
		delete(signingContext, "scope")
	}
	return granted
}

func (e *Exchanger) mintTokensFromCode(ctx context.Context, claims AuthorizationCodeClaims) (TokenSet, error) {
	// Resolve the subject's static roles/entitlements AND fresh data-driven
	// backend claims, then fold both into the signing context pre-attenuation
	// (#140). Scope confinement of entitlements/roles happens post-mapper in
	// SignScoped, so a ClaimMappings-injected grant is governed by scope too.
	// The subject is an input here, so it is known before anything can fail.
	// Mint failures (resolver down, signer misconfigured) are precisely the
	// ones worth attributing. See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: claims.Subject}, fmt.Errorf(format, args...)
	}

	roles, entitlements, backend, err := e.subjectSigningContext(claims.Subject)
	if err != nil {
		// The subject is already known/vouched (decrypted from our own
		// auth code); this is a role-resolver failure, not anything the
		// client presented. See kdex-tech/host-manager#168 review round 2.
		return failed("%w: failed to resolve roles: %v", ErrServerError, err)
	}

	signingContext := jwt.MapClaims{
		"sub":          claims.Subject,
		"auth_method":  claims.AuthMethod,
		"roles":        roles,
		"entitlements": entitlements,
	}
	mergeBackendClaims(signingContext, backend)

	grantedScopes := applyScopeFilter(signingContext, claims.Scope, nil)
	grantedScopeStr := strings.Join(grantedScopes, " ")

	accessToken, err := e.config.Signer.SignScoped(signingContext, grantedScopes)
	if err != nil {
		return failed("%w: failed to sign access token: %v", ErrServerError, err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idTokenContext := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idTokenContext, signingContext)
		idTokenContext["aud"] = claims.ClientID
		delete(idTokenContext, "scope")
		idToken, err = e.config.Signer.SignScoped(idTokenContext, grantedScopes)
		if err != nil {
			return failed("%w: failed to sign id token: %v", ErrServerError, err)
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
			return TokenSet{}, fmt.Errorf("%w: failed to create refresh token: %v", ErrServerError, err)
		}
	}

	return ts, nil
}

// mintTokensFromSubject re-mints tokens for a known-authenticated subject (used by the refresh flow).
// It re-resolves roles/entitlements to ensure freshness.
func (e *Exchanger) mintTokensFromSubject(subject, clientID, scope string, authMethod AuthMethod) (TokenSet, error) {
	// As in mintTokensFromCode: subject is an input, so every failure below
	// can be attributed. See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: subject}, fmt.Errorf(format, args...)
	}

	roles, entitlements, backend, err := e.subjectSigningContext(subject)
	if err != nil {
		return failed("failed to resolve roles: %w", err)
	}

	signingContext := jwt.MapClaims{
		"auth_method":  string(authMethod),
		"entitlements": entitlements,
		"roles":        roles,
		"sub":          subject,
	}
	mergeBackendClaims(signingContext, backend)

	grantedScopes := applyScopeFilter(signingContext, scope, nil)
	grantedScope := strings.Join(grantedScopes, " ")

	accessToken, err := e.config.Signer.SignScoped(signingContext, grantedScopes)
	if err != nil {
		return failed("failed to sign access token: %w", err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idCtx := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idCtx, signingContext)
		idCtx["aud"] = clientID
		delete(idCtx, "scope")
		idToken, err = e.config.Signer.SignScoped(idCtx, grantedScopes)
		if err != nil {
			return failed("failed to sign id token: %w", err)
		}
	}

	return TokenSet{
		AccessToken: accessToken,
		IDToken:     idToken,
		Scope:       grantedScope,
		Subject:     subject,
	}, nil
}

// graceReplayAttempts and graceReplayInterval bound the poll a losing caller
// does while the winner is still publishing its result. A loser can arrive
// after the winner's GetAndDelete but before its Set, an interval that is
// sub-millisecond in memory but a network round trip under Valkey. Bounded
// at 200ms; the winner either publishes within it or has failed, in which
// case not-found is the correct answer.
//
// graceFastBailoutAttempts bounds a SHORTER leading sub-window used to
// decide whether to poll at all. markGraceInFlight writes a lightweight
// pending marker as a single fast cache op immediately after GetAndDelete
// succeeds -- well before the (comparatively slow) validation/minting work
// -- so if nothing at all (not even that marker) is visible within this
// short sub-window, no winner exists for this token: it is bogus, expired,
// or outside the window, and continuing to poll would only pay Valkey round
// trips and pin a goroutine for a redemption that is never coming. This is
// what makes an ordinary invalid refresh (the common case) cheap again: one
// cache miss plus up to two retries, not the full 10-attempt/180ms budget.
//
// Set to 3 (~40ms: two sleeps of graceReplayInterval), not 2 (~20ms): the
// failure mode of too-tight a bailout IS #169 itself -- a legitimate
// concurrent refresh fast-bailing because the in-flight marker hasn't
// propagated under a loaded Valkey degrades straight back into the
// single-winner-fails-the-rest bug this task exists to fix. It fails
// closed (never a wrong result, only a missed replay), but regressing into
// the original availability bug under exactly the load #169 targets is a
// bad trade for 20ms. Three attempts still gives roughly a 4x reduction
// against the old ~180ms-for-every-miss cost while leaving real headroom
// over Valkey p99 write-visibility latency. See
// kdex-tech/host-manager#169 fix round 2 (cost finding) and round 3
// (bailout-window review).
const (
	graceReplayAttempts      = 10
	graceReplayInterval      = 20 * time.Millisecond
	graceFastBailoutAttempts = 3
)

// graceRecord is what the grace cache actually stores, keyed by the
// CONSUMED token id. ClientID is the client the token was ORIGINALLY issued
// to (claims.ClientID from the record RedeemRefreshToken just consumed),
// carried so replayFromGrace can reject a caller presenting a different
// client_id exactly as the strict `claims.ClientID != clientID` check does
// on the non-grace path -- without it, the grace window would hand a live
// rotating credential to any caller that merely knew the consumed token id.
// See kdex-tech/host-manager#169 (CRITICAL review finding).
//
// Pending marks an in-flight marker written by markGraceInFlight before the
// winner has minted anything: TokenSet is the zero value until
// publishToGrace overwrites the same key with the real result. See
// markGraceInFlight / clearGraceInFlight.
type graceRecord struct {
	ClientID string   `json:"cid"`
	Pending  bool     `json:"pending,omitempty"`
	TokenSet TokenSet `json:"ts"`
}

// graceCacheSet is the shared best-effort write path for both the in-flight
// marker and the final result: it always uses a context detached from the
// caller's own (context.WithoutCancel), because both writes matter to OTHER
// concurrent callers, not to whether THIS caller's own request is still
// live. Without this, a winner whose client disconnects or whose deadline
// fires between mint and publish would cancel `ctx`, the Set would fail,
// nothing would be published, and every loser would fall through to
// not-found -- precisely the #169 scenario a request that times out and
// triggers a retry burst is the canonical trigger for. See
// kdex-tech/host-manager#169 fix round 2 (IMPORTANT finding).
func (e *Exchanger) graceCacheSet(ctx context.Context, tokenID string, rec graceRecord) {
	if e.refreshGraceCache == nil {
		return
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_ = e.refreshGraceCache.Set(context.WithoutCancel(ctx), tokenID, string(payload), cache.WithTTL(e.refreshGraceWindow))
}

// markGraceInFlight publishes the lightweight in-flight marker described on
// graceRecord. Called immediately after the token is consumed and its
// record parses cleanly -- before the validation checks and minting in
// RedeemRefreshToken -- so a concurrent loser's poll can distinguish "a
// rotation for this token is happening right now" from "nothing is
// happening" almost as fast as the winner's own GetAndDelete completed.
func (e *Exchanger) markGraceInFlight(ctx context.Context, tokenID, clientID string) {
	e.graceCacheSet(ctx, tokenID, graceRecord{ClientID: clientID, Pending: true})
}

// clearGraceInFlight removes the in-flight marker after a redemption that
// consumed the token but was then rejected (expired, session cap, client_id
// mismatch, or a minting/rotation failure), so a concurrent loser's poll
// sees the marker vanish and stops immediately instead of waiting out the
// full budget for a result that is never coming. It does NOT weaken "a
// rejected redemption publishes nothing": the marker it removes never
// carried a result, only the fact that a (now-rejected) redemption was
// attempted.
func (e *Exchanger) clearGraceInFlight(ctx context.Context, tokenID string) {
	if e.refreshGraceCache == nil {
		return
	}
	_ = e.refreshGraceCache.Delete(context.WithoutCancel(ctx), tokenID)
}

// publishToGrace makes the winner's result replayable for the window,
// overwriting whatever in-flight marker markGraceInFlight left. Called only
// on a SUCCESSFUL rotation: a rejected redemption never reaches this call
// (its deferred cleanup in RedeemRefreshToken clears the marker instead), so
// its concurrent losers fall through to not-found rather than replaying a
// failure. See kdex-tech/host-manager#169.
func (e *Exchanger) publishToGrace(ctx context.Context, tokenID, clientID string, ts TokenSet) {
	e.graceCacheSet(ctx, tokenID, graceRecord{ClientID: clientID, TokenSet: ts})
}

// replayFromGrace returns the winner's result for a token that was already
// rotated inside the grace window, for a caller presenting the SAME
// client_id the token was originally issued to. Exactly one rotation still
// occurred, so #71's single-lineage theft-detection guarantee is preserved:
// losers mint nothing, they receive a copy.
//
// A non-nil error is already fully classified:
//   - a client_id mismatch on a live grace record is a grantFailuref, the
//     exact rejection and message the strict (non-grace) path uses for the
//     same case, so a caller cannot use the grace window to bypass client
//     binding (kdex-tech/host-manager#169 CRITICAL review finding).
//   - an unreadable/corrupt grace cache entry, or this poll's own context
//     being canceled (OUR deadline, not a fact about the presented token),
//     is ErrServerError so the token endpoint maps it to 500 server_error
//     rather than telling a caller its refresh token doesn't exist. See
//     kdex-tech/host-manager#168 and #169 fix round 2.
//
// A clean "nothing published" (or "published and rejected", once the
// in-flight marker has been cleared) result is NOT an error:
// (TokenSet{}, false, nil).
func (e *Exchanger) replayFromGrace(ctx context.Context, tokenID, clientID string) (TokenSet, bool, error) {
	if e.refreshGraceCache == nil {
		return TokenSet{}, false, nil
	}
	sawInFlight := false
	for attempt := range graceReplayAttempts {
		raw, found, _, err := e.refreshGraceCache.Get(ctx, tokenID)
		if err != nil {
			return TokenSet{}, false, fmt.Errorf("%w: failed to read refresh-grace entry: %v", ErrServerError, err)
		}
		if found {
			var rec graceRecord
			if json.Unmarshal([]byte(raw), &rec) != nil {
				return TokenSet{}, false, fmt.Errorf("%w: failed to parse refresh-grace entry", ErrServerError)
			}
			if rec.Pending {
				// A rotation is confirmed in progress; keep polling below
				// for the real result within the full budget.
				sawInFlight = true
			} else {
				if rec.ClientID != clientID {
					// Subject attribution, consistent with the identical
					// strict-path rejection (`grantFailed` above, #158):
					// an operator investigating a rejected redemption
					// needs to see WHOSE session it belongs to. The
					// record already carries it on the minted result.
					return TokenSet{Subject: rec.TokenSet.Subject}, false, grantFailuref("refresh token was not issued to this client")
				}
				return rec.TokenSet, true, nil
			}
		} else if sawInFlight {
			// The in-flight marker we previously observed is gone: the
			// winner consumed the token, marked it in-flight, then
			// rejected the redemption and cleared the marker. Stop now
			// rather than burning the remaining poll budget on a result
			// that will never arrive.
			return TokenSet{}, false, nil
		} else if attempt == graceFastBailoutAttempts-1 {
			// Nothing published at all within the fast-bailout window --
			// not even the in-flight marker, which a winner writes
			// immediately. No rotation is happening for this token.
			return TokenSet{}, false, nil
		}
		if attempt == graceReplayAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return TokenSet{}, false, fmt.Errorf("%w: refresh-grace replay canceled: %v", ErrServerError, ctx.Err())
		case <-time.After(graceReplayInterval):
		}
	}
	return TokenSet{}, false, nil
}

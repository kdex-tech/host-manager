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
	"github.com/kdex-tech/host-manager/internal/sign"
	"golang.org/x/oauth2"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
	config       Config
	oauth2Config *oauth2.Config
	// oidcAuthCodeOptions are the extra authorization-URL parameters this
	// host sends the IdP -- non-empty only when offline access was requested.
	// See kdex-tech/host-manager#190.
	oidcAuthCodeOptions []oauth2.AuthCodeOption
	oidcProvider        *oidc.Provider
	oidcVerifier        *oidc.IDTokenVerifier
	refreshTokenCache   cache.Cache
	refreshTokenTTL     time.Duration
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

// MaxRefreshGraceWindow is the hard ceiling on Config.RefreshGraceWindow.
// The window exists to absorb the few hundred milliseconds a real client's
// parallel refreshes span (RFC 9700 4.14); anything on that order is
// covered well inside a minute. Past it the knob stops being a race
// absorber and becomes a replay window: a consumed refresh token keeps
// returning a live access/ID/refresh set for its whole duration, and the
// minted set sits at rest in the cache for just as long. A misconfigured
// `--refresh-grace-window=24h` would silently convert single-use rotation
// into 24h replay, so NewExchanger clamps to this and says so.
const MaxRefreshGraceWindow = 60 * time.Second

// refreshGraceMaxItems bounds the in-memory grace cache. See the comment at
// its GetCache call in NewExchanger for the arithmetic.
const refreshGraceMaxItems = 10000

// scopeOfflineAccess is the OIDC Core 11 scope that asks the provider for a
// refresh token. It is NOT one of SupportedScopes: that vocabulary is what
// THIS host grants its own clients, whereas this value is only ever sent
// upstream. See kdex-tech/host-manager#190.
const scopeOfflineAccess = "offline_access"

// defaultSessionScopes is what a browser session is granted when no client
// asked for a scope: the full identity set. Shared by the two flows that
// establish a browser session -- LoginLocal and the OIDC callback -- so a
// session's granted scope does not depend on which one minted it, and so a
// rotation of either reproduces the same set. See kdex-tech/host-manager#189.
var defaultSessionScopes = []string{"email", "entitlements", "openid", "profile", "roles"}

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
	// PredecessorID is the id of the refresh token this one ROTATED FROM,
	// set only by RedeemRefreshToken. It is the key the #169 grace record
	// for that rotation lives under, and exists so RevokeRefreshToken can
	// tear the record down at logout -- the grace record is keyed by the
	// CONSUMED token, which is not the value the cookie holds afterwards,
	// so revocation has no other way to find it. Empty on a freshly minted
	// (non-rotated) token and on records written before this field
	// existed; omitempty keeps those round-tripping unchanged.
	PredecessorID string `json:"pid,omitempty"`
	Scope         string `json:"scp"`
	Subject       string `json:"sub"`
	// IDPClaims is the claim set the upstream IdP asserted at login, minus
	// reservedMintClaims. Rotation re-mints through mintTokensFromSubject,
	// which knows only what FindInternalRolesAndEntitlements returns -- so
	// without this every IdP-supplied claim (email, profile, and any custom
	// claim a host's ClaimMappings reads as an INPUT) would vanish at the
	// first rotation, an hour into the session. Empty for non-OIDC grants
	// and for records written before this field existed; omitempty keeps
	// those round-tripping unchanged.
	//
	// Deliberately NOT allowlisted down to the claims the signer projects: a
	// host's ClaimMappings is CEL over the WHOLE signing context, so any claim
	// can be a mapper INPUT, and a fixed allowlist is exactly what would drop
	// the custom one some tenant depends on. The cost is that identity claims
	// (email, name, ...) now sit in the refresh-token cache beside the `sub`
	// already there -- same store, same trust boundary, more PII at rest.
	// See kdex-tech/host-manager#189.
	IDPClaims jwt.MapClaims `json:"idpc,omitempty"`
	// UpstreamRefreshToken is the refresh token the IdP issued for this
	// session, held so a rotation can re-derive the user from the IdP instead
	// of replaying IDPClaims. Empty unless offline access was requested and
	// the provider issued one.
	//
	// This is a long-lived THIRD-PARTY credential living in the same cache as
	// this host's own refresh tokens -- the trust boundary is unchanged, but
	// the value of the store is not. See kdex-tech/host-manager#190.
	UpstreamRefreshToken string `json:"urt,omitempty"`
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
			if gw > MaxRefreshGraceWindow {
				// Clamped, not rejected: this process is the site's
				// serving path, and refusing to start over one flag takes
				// the whole host down, which is a worse outcome than
				// running with a safe window. Clamped LOUDLY rather than
				// silently, because the running config no longer matches
				// what the operator asked for.
				logf.FromContext(ctx).Info(
					"refresh grace window exceeds the maximum and has been clamped; "+
						"the window is a replay window, and a long one turns single-use rotation "+
						"into ordinary replay while keeping a live minted token set at rest for its duration",
					"requested", cfg.RefreshGraceWindow.String(),
					"applied", MaxRefreshGraceWindow.String())
				gw = MaxRefreshGraceWindow
			}
			ex.refreshGraceWindow = gw
			// MaxItems is set explicitly: the cache defaults to 1000 with
			// LRU eviction, which at the 10s default window is only ~100
			// refreshes/s before records are evicted INSIDE their own
			// window and concurrent losers fall silently to not-found --
			// fail-closed, but a silent regression back into #169 on
			// exactly the load it targets. 10000 gives ~1000/s at the
			// default and ~166/s at the 60s ceiling. Only the in-memory
			// backend enforces this; ValkeyCache stores the value and
			// leaves eviction to the server.
			graceMaxItems := refreshGraceMaxItems
			ex.refreshGraceCache = cacheManager.GetCache("refresh-grace", cache.CacheOptions{
				MaxItems: &graceMaxItems,
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

		// `offline_access` (OIDC Core 11) is the standard way to ask for a
		// refresh token, and is what an operator writes in the CR. Google
		// ignores it and wants access_type=offline instead, so the scope is
		// carried AND translated. See kdex-tech/host-manager#190.
		if slices.Contains(scopes, scopeOfflineAccess) {
			ex.oidcAuthCodeOptions = []oauth2.AuthCodeOption{
				oauth2.AccessTypeOffline,
				// Without this Google returns a refresh token only on a
				// user's FIRST consent for the client, so a re-login after
				// the token is lost silently yields a session with no
				// upstream grant -- some sessions re-validated against the
				// IdP and some not, with nothing to distinguish them. The
				// cost is a consent screen on every login, which is why the
				// whole thing is opt-in.
				oauth2.SetAuthURLParam("prompt", "consent"),
			}
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
	return e.oauth2Config.AuthCodeURL(state, e.oidcAuthCodeOptions...)
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

// OIDCExchange is what an authorization-code exchange with the upstream IdP
// yielded. UpstreamRefreshToken is empty unless offline access was requested
// AND the provider issued one -- it was previously discarded outright, which
// is the second half of kdex-tech/host-manager#190.
type OIDCExchange struct {
	RawIDToken           string
	UpstreamRefreshToken string
}

func (e *Exchanger) ExchangeCode(ctx context.Context, code string) (OIDCExchange, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return OIDCExchange{}, fmt.Errorf("OIDC is not configured")
	}

	oauthToken, err := e.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return OIDCExchange{}, fmt.Errorf("failed to exchange oauth code %w", err)
	}

	// Extract ID Token from oauthToken
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return OIDCExchange{}, fmt.Errorf("no id_token in response")
	}

	return OIDCExchange{
		RawIDToken:           rawIDToken,
		UpstreamRefreshToken: oauthToken.RefreshToken,
	}, nil
}

func (e *Exchanger) ExchangeToken(ctx context.Context, oidcTokens OIDCExchange) (TokenSet, error) {
	if e == nil || !e.config.IsOIDCEnabled() {
		return TokenSet{}, fmt.Errorf("OIDC is not configured")
	}

	// 1. Verify OIDC Token
	idToken, err := e.verifyIDToken(ctx, oidcTokens.RawIDToken)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var signingContext jwt.MapClaims
	if err := idToken.Claims(&signingContext); err != nil {
		return TokenSet{}, fmt.Errorf("failed to parse claims: %w", err)
	}

	signingContext["idp"] = "oidc"

	sub, err := signingContext.GetSubject()
	// `err != nil` alone never fired for the case this check was written for.
	// jwt.MapClaims.GetSubject reports a MISSING `sub` as ("", nil) and errors
	// only on a wrong-TYPED one, so "no sub in id_token" was unreachable for
	// an id_token that simply omitted the claim -- the empty string went on to
	// be signed into a host session. OIDC Core 2 makes `sub` mandatory, so an
	// id_token without one is a broken IdP, and the login fails closed rather
	// than minting a session nobody can be attributed to.
	// See sign.ErrSubjectlessCredential.
	if err != nil || sub == "" {
		logf.FromContext(ctx).Error(sign.ErrSubjectlessCredential,
			"the upstream IdP returned an id_token with no `sub`; "+
				"OIDC Core 2 requires one -- fix the IdP or its scope/claims configuration",
			"providerURL", e.config.OIDC.ProviderURL)
		return TokenSet{}, fmt.Errorf("%w: no sub in id_token", sign.ErrSubjectlessCredential)
	}

	// Snapshot what the IdP asserted BEFORE the merges below fold our own
	// roles/entitlements in, so a rotation re-runs the same merge against
	// freshly-resolved internal grants instead of compounding the union it
	// already produced. See kdex-tech/host-manager#189.
	idpClaims := idpClaimSnapshot(signingContext)

	roles, entitlements, err := e.sp.FindInternalRolesAndEntitlements(sub)
	if err != nil {
		return TokenSet{}, err
	}

	signingContext["roles"] = mergeIDPList(signingContext["roles"], roles)
	signingContext["entitlements"] = mergeIDPList(signingContext["entitlements"], entitlements)

	// 3. Mint the session access token the same way LoginLocal does -- scope
	// filter with the browser-session default, then SignScoped. This path used
	// a bare Sign, which left the token with no `scope` claim at all while a
	// rotation of the SAME session (mintTokensFromSubject -> SignScoped) minted
	// one. GetParsedEntitlements files the signed `scope` claim into the oauth2
	// scheme bucket, so that asymmetry let an OIDC session satisfy oauth2-scheme
	// requirements after its first rotation that it could not satisfy at login.
	// See kdex-tech/host-manager#189.
	grantedScopes := applyScopeFilter(signingContext, "", defaultSessionScopes)
	grantedScope := strings.Join(grantedScopes, " ")

	accessToken, err := e.config.Signer.SignScoped(signingContext, grantedScopes)
	if err != nil {
		return TokenSet{}, err
	}

	ts := TokenSet{AccessToken: accessToken, Scope: grantedScope, Subject: sub}

	// 4. Mint the session's refresh token. Without this the OIDC callback
	// produced an access token and nothing else, so the `<cookie>_refresh`
	// cookie both AutoExtendSession branches key on was never written and an
	// OIDC session died at jwt.tokenTTL regardless of refreshTokenTTL /
	// maxSessionAge. ClientID is empty because this is a browser cookie
	// session, which is what the middleware presents on redemption.
	// See kdex-tech/host-manager#189.
	if e.IsRefreshTokenEnabled() {
		ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod:           AuthMethodOIDC,
			IDPClaims:            idpClaims,
			Scope:                grantedScope,
			Subject:              sub,
			UpstreamRefreshToken: oidcTokens.UpstreamRefreshToken,
		})
		if err != nil {
			return TokenSet{Subject: sub}, fmt.Errorf("failed to create refresh token: %w", err)
		}
	}

	return ts, nil
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
//
// It also tears down the #169 grace records that can still replay this
// session, which deleting the refresh token alone does not cover. A grace
// record is keyed by the CONSUMED token id, so after a T1->T2 rotation the
// live record sits under T1 while the cookie holds T2: revoking T2 left
// anyone presenting T1 with the winner's access and ID tokens for the rest
// of the window. T2 is dead so no lineage continues, but logout had gained
// a replay window it did not have before the grace window existed. Both
// keys are therefore removed:
//
//   - tokenID itself, for a logout that presents an already-consumed token
//     (a stale cookie, or a client that raced its own rotation), and
//   - claims.PredecessorID, the key under which THIS token was published --
//     the T1 above.
//
// Grace deletion is best-effort: a failure there must not stop the actual
// revocation, which is what bounds the exposure to the grace window rather
// than the refresh-token TTL.
func (e *Exchanger) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	if !e.IsRefreshTokenEnabled() {
		return nil
	}
	// GetAndDelete rather than Delete: the record has to be read to learn
	// its predecessor, and reading it in the same atomic step keeps the
	// revocation single-shot under concurrent logouts.
	raw, found, _, err := e.refreshTokenCache.GetAndDelete(ctx, tokenID)

	// Mark the id revoked regardless of whether a record was present. When it
	// was NOT, the likely reason is that a concurrent redemption consumed it
	// microseconds ago -- and that redemption may still fail and try to restore
	// it (#172). Deleting alone cannot express "stay dead"; this can.
	// See restoreConsumedRefreshToken.
	if serr := e.refreshTokenCache.Set(
		context.WithoutCancel(ctx), refreshRevokeTombstoneKey(tokenID), "1",
		cache.WithTTL(refreshRevokeTombstoneTTL),
	); serr != nil {
		// Best effort: a missing tombstone degrades to the pre-tombstone
		// behaviour (a racing restore could resurrect the token), never to a
		// failed logout.
		logf.FromContext(ctx).V(1).Info("refresh revocation tombstone not written",
			"cause", serr.Error())
	}

	if e.refreshGraceCache == nil {
		return err
	}
	_ = e.refreshGraceCache.Delete(ctx, tokenID)
	if found {
		var claims RefreshTokenClaims
		if json.Unmarshal([]byte(raw), &claims) == nil && claims.PredecessorID != "" {
			_ = e.refreshGraceCache.Delete(ctx, claims.PredecessorID)
		}
	}
	return err
}

// refreshRevokeTombstoneTTL bounds how long a revocation tombstone is kept.
//
// A tombstone only has to outlive an IN-FLIGHT redemption: the #172 restore
// runs in that redemption's own deferred cleanup, so the window between
// consuming a record and restoring it is one request. Five minutes is far
// beyond any such request (the inbound write deadline is 60s by default) while
// keeping the entries short-lived — they exist only for tokens that were
// explicitly revoked.
const refreshRevokeTombstoneTTL = 5 * time.Minute

// refreshRevokeTombstoneKey namespaces a tombstone away from live refresh
// records in the same cache class. The prefix contains a character rand.Text()
// never emits, so a tombstone can never collide with a real token id.
func refreshRevokeTombstoneKey(tokenID string) string {
	return "revoked:" + tokenID
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

	// FAIL CLOSED before anything is minted. The credential source vouched for
	// this login; if it did so without naming a subject, that is an operator
	// misconfiguration and the login is refused rather than half-succeeding.
	//
	// The check is HERE, and not left to the signer, because this is the only
	// frame that still knows WHICH source answered -- the log can name the
	// thing to fix (`sp.Type()` is the subject Secret store, LDAP, or the
	// http lookup) instead of reporting a signature that did not happen. The
	// signer refuses too (sign.Signer.Project / SignProjected); that is the
	// invariant, this is the diagnosis.
	//
	// It is ErrServerError because it is one: no password the caller could
	// type would make a Secret grow a `sub` key. See
	// sign.ErrSubjectlessCredential for the two sources that produce this.
	if sub, serr := signingContext.GetSubject(); serr != nil || sub == "" {
		logf.FromContext(ctx).Error(sign.ErrSubjectlessCredential,
			"the credential source vouched for this login but named no subject; "+sign.SubjectlessRemedy,
			"username", username, "authMethod", string(authMethod))
		return TokenSet{Subject: username},
			fmt.Errorf("%w: %w", ErrServerError, sign.ErrSubjectlessCredential)
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
	grantedScopes := applyScopeFilter(signingContext, scope, defaultSessionScopes)
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
		// grant, not our infrastructure, so it is safe to SAY SO. The
		// library's own error text is NOT: the ErrGrantFailure allowlist
		// echoes an error's message verbatim to an unauthenticated
		// caller, and its stated invariant is that every such message is
		// an authored constant. go-jose's messages carry no input and no
		// key material today, but a library upgrade that starts quoting
		// the offending input would leak silently with no test failing.
		// The cause goes to the operator log instead, which is where the
		// #168 design puts richer causes. See kdex-tech/host-manager#168.
		logf.FromContext(ctx).V(1).Info("authorization code failed to parse", "cause", err.Error())
		return TokenSet{}, grantFailuref("failed to parse auth code")
	}

	// 2. Derive Key
	key := sha256.Sum256([]byte(e.config.OIDC.BlockKey))

	// 3. Decrypt
	decrypted, err := object.Decrypt(key[:])
	if err != nil {
		// Same reasoning, same treatment: a caller-presented ciphertext
		// that does not decrypt against our current key is an invalid
		// grant, but only the fixed description goes on the wire.
		logf.FromContext(ctx).V(1).Info("authorization code failed to decrypt", "cause", err.Error())
		return TokenSet{}, grantFailuref("failed to decrypt auth code")
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
// The results are NAMED so the #172 compensating restore can inspect the
// error this call is actually returning. Nothing else depends on the names.
func (e *Exchanger) RedeemRefreshToken(ctx context.Context, tokenID, clientID string) (_ TokenSet, err error) {
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
		// Before declaring the grant dead, check whether the record came BACK
		// while we were polling. #169 documents concurrent bursts of 4-5 as
		// routine; when the winner of such a burst fails with ErrServerError,
		// #172 restores the record -- but the losers are already past their own
		// GetAndDelete and see only a cleared marker. Telling them
		// invalid_grant makes standard OAuth clients discard a credential that
		// is demonstrably live, defeating that compensation for every caller
		// but one.
		//
		// A restored record means the failure was OURS and is retryable, so it
		// is classified as such rather than as a fact about the grant.
		if _, restored, _, gerr := e.refreshTokenCache.Get(ctx, tokenID); gerr == nil && restored {
			return TokenSet{}, fmt.Errorf(
				"%w: a concurrent redemption of this refresh token failed and was rolled back; retry",
				ErrServerError)
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

	// The record parsed, so it is genuinely ours and genuinely restorable.
	// GetAndDelete already consumed it -- that ordering is what makes
	// rotation single-use (#71) and is deliberately NOT reordered -- so an
	// infrastructure failure from here on would destroy a live session: the
	// caller gets a 500 (retryable), retries with the same token, and is
	// told 400 invalid_grant (re-authorize). One transient blip logs the
	// user out. Put the record back on exactly the ErrServerError paths.
	//
	// Armed only AFTER a successful unmarshal, which is what excludes the
	// unparseable-record case: restoring bytes that just failed to parse
	// guarantees the same failure on every future redemption for the rest
	// of the term, where dropping them costs one re-authorization and
	// self-heals. The three grant failures below are excluded by the
	// ErrServerError gate itself -- they are legitimate consumptions.
	//
	// Safe against #71 because no ErrServerError return exists downstream
	// of a successful createRefreshToken (publishToGrace failing is logged,
	// not returned), so a restored predecessor can never coexist with a
	// live successor. TestRedeemRefreshToken_SuccessfulRotationDoesNotRestore
	// fails if that ever stops being true.
	//
	// The restore runs BEFORE the marker is cleared so a concurrent loser
	// is never told "nothing is happening" about a token that is already
	// live again. See kdex-tech/host-manager#172.
	published := false
	defer func() {
		if errors.Is(err, ErrServerError) {
			e.restoreConsumedRefreshToken(ctx, tokenID, raw, claims)
		}
		if !published {
			e.clearGraceInFlight(ctx, tokenID)
		}
	}()

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
	if err := e.markGraceInFlight(ctx, tokenID, claims.ClientID); err != nil {
		// Optimization only: without the marker a concurrent loser fast-
		// bails to not-found instead of polling out the full budget. Never
		// a wrong answer, so this does not fail the redemption.
		logf.FromContext(ctx).V(1).Info("refresh-grace in-flight marker not written",
			"subject", claims.Subject, "cause", err.Error())
	}

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

	// Re-derive the IdP's view of this user rather than replaying the
	// login-time snapshot, when the session holds an upstream refresh token
	// to do it with. This is the only point at which an account disabled,
	// suspended, or stripped of its groups upstream can reach a session that
	// is already established. See kdex-tech/host-manager#190.
	idpClaims := claims.IDPClaims
	upstreamRefreshToken := claims.UpstreamRefreshToken
	if upstreamRefreshToken != "" {
		refreshed, rotatedUpstream, uerr := e.refreshUpstreamClaims(ctx, upstreamRefreshToken, claims.Subject)
		if errors.Is(uerr, errUpstreamGrantRevoked) {
			// The IdP says this grant is dead. Ending the session here is the
			// entire point of holding the upstream token, so this is
			// deliberately NOT the degrade path below: replaying the stored
			// claims would keep a revoked user signed in for the whole of
			// maxSessionAge, which is the exposure #190 set out to close.
			return grantFailed("the identity provider rejected this session: %v", uerr)
		} else if uerr != nil {
			// The IdP is unreachable, or answered something we cannot read.
			// Re-deriving the session is worth having only if a provider
			// outage does not log the whole tenant out at the next hourly
			// rotation, so fall back to the stored claim set -- exactly the
			// #189 behaviour.
			logf.FromContext(ctx).V(1).Info(
				"upstream claim refresh failed; replaying the stored claim set",
				"subject", claims.Subject, "cause", uerr.Error())
		} else {
			idpClaims = refreshed
			upstreamRefreshToken = rotatedUpstream
		}
	}

	// Mint fresh tokens — re-resolves roles/entitlements for freshness.
	//
	// No ErrServerError re-wrap here: mintTokensFromSubject marks its own
	// infrastructure failures, exactly as mintTokensFromCode does, so the
	// classification is a property of the function that knows what failed
	// rather than of this one caller. %w keeps the mark in the chain.
	ts, err := e.mintTokensFromSubject(claims.Subject, claims.ClientID, claims.Scope, claims.AuthMethod, idpClaims)
	if err != nil {
		return failed("failed to mint tokens from refresh: %w", err)
	}

	// Rotate: issue a new refresh token. PredecessorID records the token
	// this one replaced -- the key its grace record lives under -- so
	// RevokeRefreshToken can tear that record down too (see there).
	ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod:           claims.AuthMethod,
		ClientID:             claims.ClientID,
		IDPClaims:            idpClaims,
		OriginalIssuedAt:     claims.OriginalIssuedAt,
		PredecessorID:        tokenID,
		Scope:                claims.Scope,
		Subject:              claims.Subject,
		UpstreamRefreshToken: upstreamRefreshToken,
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
	//
	// `published` is gated on the write actually landing. If it did not,
	// the deferred cleanup clears the in-flight marker instead of leaving
	// a Pending record with no result behind it: a stranded marker makes
	// every concurrent loser commit to the full poll budget and still
	// return not-found, for the whole window, and disables the very
	// cleanup written for this case. The winner's own rotation succeeded,
	// so the redemption still returns success -- losing the replay is a
	// degraded #169, not a failed refresh.
	if perr := e.publishToGrace(ctx, tokenID, claims.ClientID, ts); perr != nil {
		logf.FromContext(ctx).V(1).Info("refresh-grace result not published; concurrent refreshes will not replay",
			"subject", claims.Subject, "cause", perr.Error())
	} else {
		published = true
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
	// RFC 6749 3.3: "The value of the scope parameter is expressed as a list of
	// space-delimited, case-sensitive strings. The strings are defined by the
	// AUTHORIZATION SERVER." A client SELECTS from the vocabulary the AS defines
	// and publishes as scopes_supported (RFC 8414 2); it cannot invent values.
	//
	// An earlier revision appended every unrecognised requested string to the
	// granted set. Because GetParsedEntitlements files the signed `scope` claim
	// into the "oauth2" scheme bucket, that let a client author its own
	// entitlement-shaped string -- e.g. "vector_stores:vs_victim:write" -- and
	// satisfy an oauth2-declared operation requirement its role bindings never
	// granted. Narrowing here is explicitly permitted by 3.3 ("MAY fully or
	// partially ignore the scope requested"); the granted set is returned to the
	// caller so the 3.3 MUST on reporting the actual scope is satisfiable.
	granted := []string{}
	for _, known := range SupportedScopes {
		if slices.Contains(requested, known) {
			granted = append(granted, known)
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
//
// Every failure below is OUR infrastructure — a role resolver that is down,
// a signer that is misconfigured — reached only after the caller has already
// validated the grant, so all three are marked ErrServerError exactly as the
// structurally identical sites in mintTokensFromCode are. This function owns
// that classification rather than leaning on its single caller re-wrapping
// it: the caller's re-wrap was correct but invisible from here, and a second
// caller would have silently reported an outage as invalid_grant. See
// kdex-tech/host-manager#168.
func (e *Exchanger) mintTokensFromSubject(subject, clientID, scope string, authMethod AuthMethod, idpClaims jwt.MapClaims) (TokenSet, error) {
	// As in mintTokensFromCode: subject is an input, so every failure below
	// can be attributed. See kdex-tech/host-manager#158.
	failed := func(format string, args ...any) (TokenSet, error) {
		return TokenSet{Subject: subject}, fmt.Errorf(format, args...)
	}

	roles, entitlements, backend, err := e.subjectSigningContext(subject)
	if err != nil {
		return failed("%w: failed to resolve roles: %v", ErrServerError, err)
	}

	signingContext := jwt.MapClaims{
		"auth_method": string(authMethod),
		"sub":         subject,
	}

	// Replay what the IdP asserted at login, then union its roles/entitlements
	// with the FRESHLY-resolved internal ones -- the same merge ExchangeToken
	// runs, so a rotated session is claim-identical to the one login minted
	// while internal grants stay live. Empty for every non-OIDC grant, which
	// leaves those paths exactly as they were.
	// See kdex-tech/host-manager#189.
	for k, v := range idpClaims {
		if _, reserved := reservedMintClaims[k]; reserved {
			continue
		}
		signingContext[k] = v
	}
	if authMethod == AuthMethodOIDC {
		// Derived, never carried: `idp` is in reservedMintClaims precisely so
		// a stored value cannot rebind the identity provider.
		signingContext["idp"] = "oidc"
	}

	signingContext["roles"] = mergeIDPList(signingContext["roles"], roles)
	signingContext["entitlements"] = mergeIDPList(signingContext["entitlements"], entitlements)

	mergeBackendClaims(signingContext, backend)

	grantedScopes := applyScopeFilter(signingContext, scope, nil)
	grantedScope := strings.Join(grantedScopes, " ")

	accessToken, err := e.config.Signer.SignScoped(signingContext, grantedScopes)
	if err != nil {
		return failed("%w: failed to sign access token: %v", ErrServerError, err)
	}

	var idToken string
	if slices.Contains(grantedScopes, "openid") {
		idCtx := make(jwt.MapClaims, len(signingContext))
		maps.Copy(idCtx, signingContext)
		idCtx["aud"] = clientID
		delete(idCtx, "scope")
		idToken, err = e.config.Signer.SignScoped(idCtx, grantedScopes)
		if err != nil {
			return failed("%w: failed to sign id token: %v", ErrServerError, err)
		}
	}

	return TokenSet{
		AccessToken: accessToken,
		IDToken:     idToken,
		Scope:       grantedScope,
		Subject:     subject,
	}, nil
}

// restoreConsumedRefreshToken puts a consumed refresh record back after the
// redemption failed for an infrastructure reason, so the caller's retry has
// something to succeed against instead of being told its credential is dead.
// See kdex-tech/host-manager#172.
//
// The TTL is the record's REMAINING lifetime, never the default. The
// refresh-token cache is created with TTL: refreshTokenTTL and
// createRefreshToken writes with no explicit option, so a plain Set here
// would silently renew the record for a fresh full term and carry it past
// its original expiry. (The embedded ExpiresAt check on redemption bounds
// the damage to a lingering cache entry rather than a usable token, but the
// entry should not linger either.)
//
// Written on a context detached from the caller's, for the same reason
// graceCacheSet is: the whole point is to compensate for a failed
// redemption, and a client that has already disconnected or timed out is
// precisely the case where the session most needs to survive.
//
// A failed restore degrades to the pre-#172 behaviour -- the session is lost
// -- and is logged rather than returned, so the failure that actually
// happened is what reaches the caller.
func (e *Exchanger) restoreConsumedRefreshToken(ctx context.Context, tokenID, raw string, claims RefreshTokenClaims) {
	if e.refreshTokenCache == nil {
		return
	}
	// A revocation that landed while this redemption held the consumed record
	// must win. RevokeRefreshToken revokes by DELETING, so once we have taken
	// the record there is nothing left for it to delete -- without this check
	// the restore below would silently undo an explicit logout and the session
	// would survive for the rest of its term.
	if _, revoked, _, rerr := e.refreshTokenCache.Get(
		context.WithoutCancel(ctx), refreshRevokeTombstoneKey(tokenID),
	); rerr == nil && revoked {
		logf.FromContext(ctx).V(1).Info(
			"refresh token not restored: it was revoked while the redemption was in flight",
			"subject", claims.Subject)
		return
	}

	remaining := time.Until(time.Unix(claims.ExpiresAt, 0))
	if remaining <= 0 {
		// Already expired: restoring it would only produce a record whose
		// next redemption rejects it anyway.
		return
	}
	if err := e.refreshTokenCache.Set(
		context.WithoutCancel(ctx), tokenID, raw, cache.WithTTL(remaining),
	); err != nil {
		logf.FromContext(ctx).V(1).Info(
			"refresh token not restored after an infrastructure failure; this session is lost and the client must re-authorize",
			"subject", claims.Subject, "cause", err.Error())
	}
}

// idpClaimSnapshot copies the claims an upstream IdP asserted, dropping the
// ones the mint owns authoritatively (reservedMintClaims: the JWT envelope,
// `sub`, and the auth-flow claims a forged value could hijack). What remains
// is stored on the session's refresh-token record so a rotation can reproduce
// the login-time claim set -- including custom claims a host's ClaimMappings
// reads as an INPUT, which nothing else in the refresh path knows about.
// See kdex-tech/host-manager#189.
func idpClaimSnapshot(signingContext jwt.MapClaims) jwt.MapClaims {
	snapshot := make(jwt.MapClaims, len(signingContext))
	for k, v := range signingContext {
		if _, reserved := reservedMintClaims[k]; reserved {
			continue
		}
		snapshot[k] = v
	}
	return snapshot
}

// mergeIDPList unions an IdP-asserted roles/entitlements claim with the list
// this host resolved for the same subject. The IdP value arrives as []string
// straight off a freshly-parsed ID token but as []any once it has round-
// tripped through the refresh record's JSON, so both shapes are handled --
// a missed []any would silently drop every IdP-asserted role at the first
// rotation, which is the exact class of failure #189 is about.
func mergeIDPList(idpValue any, internal []string) any {
	switch v := idpValue.(type) {
	case []string:
		return append(slices.Clone(v), internal...)
	case []any:
		merged := make([]string, 0, len(v)+len(internal))
		for _, item := range v {
			if s, ok := item.(string); ok {
				merged = append(merged, s)
			}
		}
		return append(merged, internal...)
	case string:
		return append([]string{v}, internal...)
	default:
		return internal
	}
}

// errUpstreamGrantRevoked marks the one upstream-refresh outcome that must
// END the session rather than degrade it: the IdP answering invalid_grant
// (consent withdrawn, account disabled, token revoked), or handing back an
// id_token for a different subject. Every other failure is the provider being
// unreachable, which must not log the whole tenant out.
// See kdex-tech/host-manager#190.
var errUpstreamGrantRevoked = errors.New("the upstream refresh grant is no longer valid")

// refreshUpstreamClaims spends the session's upstream refresh token to obtain
// a fresh id_token from the IdP, and returns the claim set it asserts NOW
// alongside the refresh token to carry forward. golang.org/x/oauth2 keeps the
// presented token when a provider does not rotate, so the returned value is
// always usable.
func (e *Exchanger) refreshUpstreamClaims(
	ctx context.Context, upstreamRefreshToken, expectSubject string,
) (jwt.MapClaims, string, error) {
	if e.oauth2Config == nil {
		return nil, "", fmt.Errorf("OIDC is not configured")
	}

	token, err := e.oauth2Config.TokenSource(
		ctx, &oauth2.Token{RefreshToken: upstreamRefreshToken},
	).Token()
	if err != nil {
		// RFC 6749 5.2: invalid_grant is the provider stating that THIS grant
		// is no longer usable. Every other failure (transport, 5xx, a
		// malformed body) is an outage and must degrade instead.
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) && retrieve.ErrorCode == "invalid_grant" {
			return nil, "", fmt.Errorf("%w: %v", errUpstreamGrantRevoked, retrieve.ErrorCode)
		}
		return nil, "", fmt.Errorf("upstream refresh failed: %w", err)
	}

	// Not every provider returns an id_token on the refresh grant. That is a
	// capability gap, not a revocation, so it degrades to the stored claims.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, "", fmt.Errorf("upstream refresh returned no id_token")
	}

	idToken, err := e.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("upstream refresh returned an unverifiable id_token: %w", err)
	}

	var refreshed jwt.MapClaims
	if err := idToken.Claims(&refreshed); err != nil {
		return nil, "", fmt.Errorf("upstream refresh id_token claims are unreadable: %w", err)
	}

	// A refreshed id_token naming a different subject would silently rebind
	// this session to another identity -- every downstream check (roles,
	// entitlements, audit) keys on `sub`. Treated as a revocation rather than
	// an outage because degrading is not a safe fallback here: it would mint
	// the session under the OLD subject while the IdP has just told us the
	// grant now belongs to someone else.
	if sub, _ := refreshed.GetSubject(); sub != expectSubject {
		return nil, "", fmt.Errorf(
			"%w: the refreshed id_token names a different subject", errUpstreamGrantRevoked)
	}

	return idpClaimSnapshot(refreshed), token.RefreshToken, nil
}

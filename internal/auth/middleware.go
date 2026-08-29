package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// CapUsesClaim marks a JWT as a bounded-use capability minted by mint_token
// (internal/host/mint_token.go). The inbound middleware decrements the
// jti-keyed use counter only for tokens carrying this claim; ordinary
// session/FAT tokens never carry it. Exported so both the minting side
// (internal/host) and the enforcing side (this package) share one source
// of truth for the marker's name.
const CapUsesClaim = "kdx_cap"

// looksLikePAT reports whether a bearer credential is a PASETO API token rather
// than a JWT. PASETO v4 public tokens start with "v4.public."; a host may
// replace that header on the wire with a brand tokenPrefix. JWTs start with
// "eyJ" (base64 of '{"') and are never PATs.
func looksLikePAT(token, tokenPrefix string) bool {
	if tokenPrefix != "" && strings.HasPrefix(token, tokenPrefix) {
		return true
	}
	return strings.HasPrefix(token, "v4.public.")
}

// LooksLikePAT is the exported wrapper around looksLikePAT so other packages
// (e.g. the host proxy bridge) can recognize a PASETO PAT presented on the
// Authorization: Bearer header.
func LooksLikePAT(token, tokenPrefix string) bool {
	return looksLikePAT(token, tokenPrefix)
}

// WithAPITokenIdentity is OPT-IN: it authenticates a host-audience PASETO PAT
// into an identity for the single route it wraps. Apply it only to endpoints
// that should treat an API key as the caller, and never to the mux as a whole —
// see the PAT block in WithAuthentication for what happens when a PAT identity
// leaks into the proxy bridge or into /-/oauth/authorize.
//
// It composes AFTER WithAuthentication: a request already carrying an identity
// (JWT or cookie) is left alone, so this only ever fills the gap the PAT
// passthrough leaves.
func (c *Config) WithAPITokenIdentity(exchanger *Exchanger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, alreadyLoggedIn := GetAuthContext(r.Context()); alreadyLoggedIn {
				next.ServeHTTP(w, r)
				return
			}
			authHeader := r.Header.Get("Authorization")
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" ||
				!looksLikePAT(parts[1], c.TokenPrefix()) {
				next.ServeHTTP(w, r)
				return
			}
			if ac, ok := c.hostPATIdentity(r.Context(), parts[1], exchanger); ok {
				r = r.WithContext(SetAuthContext(r.Context(), ac))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hostPATIdentity validates a PASETO PAT against the HOST's own audience and,
// on success, inflates it into an AuthContext. Used only by
// WithAPITokenIdentity. Reports false for every token that is
// not usable as a host identity -- wrong audience, malformed, expired, revoked,
// or an unresolvable subject -- and the caller then leaves the request
// anonymous. See kdex-tech/host-manager#175.
//
// ONLY c.Audience is accepted. A PAT minted for a function resource keeps its
// own audience and is rejected here by design: that binding belongs to the
// token, and treating a function-scoped credential as a general host identity
// would be a confused-deputy escalation (aa73843). Widening this to accept
// other audiences is a deliberate policy change, not a bug fix.
//
// The subject's roles/entitlements are resolved through the same resolver the
// JWT mint path uses, so a PASETO caller and a JWT caller present identical
// structured entitlements to the authorization checker.
func (c *Config) hostPATIdentity(ctx context.Context, token string, exchanger *Exchanger) (AuthContext, bool) {
	if c == nil || c.TokenManager == nil || exchanger == nil || c.Audience == "" {
		return nil, false
	}

	data, err := c.TokenManager.ValidateToken(ctx, token, c.Audience)
	if err != nil {
		// Expected for every resource-bound PAT on its way to the proxy
		// bridge, so this is V(1) rather than an error.
		logf.FromContext(ctx).V(1).Info(
			"api token is not valid for the host audience; leaving the request anonymous",
			"cause", err.Error())
		return nil, false
	}

	roles, ents, err := exchanger.ResolveInternalRolesAndEntitlements(data.Subject)
	if err != nil {
		logf.FromContext(ctx).Error(err, "failed to resolve api token subject", "subject", data.Subject)
		return nil, false
	}

	ac := AuthContext{
		"sub":          data.Subject,
		"roles":        roles,
		"entitlements": ents,
		// The token's static scope rides along under its own key; the
		// structured entitlements above are the authoritative authz model.
		"scp": data.Scope,
	}

	// Deliberately NOT PATBridgeClaim. That marker exists so a PAT can satisfy
	// a FUNCTION operation declaring only {oauth2: [...]}, by mirroring these
	// entitlements into the "oauth2" scheme bucket. Host-level endpoints have
	// no such requirement, and the ruling here is host-audience only -- so this
	// identity stays in the default (bearer) bucket and grants nothing beyond
	// what the subject actually holds.

	// Resolve the subject's data-driven backend claims fresh and merge them
	// non-destructively, matching the proxy bridge (#138).
	for k, v := range exchanger.ResolveSubjectClaims(data.Subject) {
		if _, exists := ac[k]; !exists {
			ac[k] = v
		}
	}

	// Fold those source claims into `entitlements` with the host's
	// ClaimMappings -- the same mapper the session-token signer applies, per
	// EnrichAuthContext's contract. The merge above lands each claim under its
	// OWN key, so without this the data-driven per-store grants stay invisible
	// to everything that reads `entitlements`. The function proxy repaired that
	// on its own path; nothing else did, so /-/check, the page security gate
	// and the navigation filter each evaluated a smaller set than the proxy
	// gate enforced -- the same credential answered "denied" by /-/check and
	// "allowed" by the gate, for the same resource, in the same minutes.
	//
	// Placed here rather than at each reader so the invariant holds for every
	// reader, including ones added later. Idempotent and attenuation-safe, so
	// the proxy's own enrichment (which additionally applies the FUNCTION's
	// ClaimMappings) still runs and still refines this.
	// See kdex-tech/host-manager#192.
	EnrichAuthContext(ac, c.ClaimMapper)

	return ac, true
}

// bearerChallenge builds the RFC 6750 §3 WWW-Authenticate value for a rejected
// bearer credential, adding RFC 9728's resource_metadata pointer when path
// belongs to one of this host's oauth2-protected resources.
//
// error_description is drawn from a fixed pair rather than rendered from err.
// The value lands inside an HTTP quoted-string, so nothing derived from a
// caller-supplied token may reach it — a parse error can carry attacker-chosen
// bytes, and a stray quote would let it break out of the header.
//
// The resource_metadata pointer is OPERATOR-supplied and gets the same
// discipline, through the same CheckedResourceMetadata every other emitter of
// that parameter uses: spec.api.basePath's CRD pattern is start-anchored only,
// so a quote-bearing basePath reaches this concatenation and would give the
// challenge a second resource_metadata parameter naming an attacker-run
// authorization server. This path is the more reachable of the two — it fires on
// every invalid or expired bearer to a protected path, not only on a policy
// denial. A rejected pointer costs the challenge its pointer and nothing else:
// error= and error_description= still identify the failure.
func (c *Config) bearerChallenge(ctx context.Context, path string, err error) string {
	desc := "the access token is invalid"
	if errors.Is(err, jwt.ErrTokenExpired) {
		desc = "the access token expired"
	}
	challenge := `Bearer error="invalid_token", error_description="` + desc + `"`
	if md := CheckedResourceMetadata(ctx, c.resourceMetadataURL(path)); md != "" {
		challenge += `, resource_metadata="` + md + `"`
	}
	return challenge
}

// resourceMetadataURL returns the RFC 9728 metadata URL of the oauth2-protected
// resource owning path, or "" when path belongs to none.
//
// Matching is segment-wise, so /api/v1/mcp owns itself and everything beneath
// it but never /api/v1/mcp-other. The longest matching basePath wins: map
// iteration order is randomized, so nested resources would otherwise resolve
// non-deterministically.
func (c *Config) resourceMetadataURL(path string) string {
	if c == nil {
		return ""
	}
	var best string
	var bestLen int
	for basePath, metadataURL := range c.OAuth2ResourceMetadata {
		if path != basePath && !strings.HasPrefix(path, basePath+"/") {
			continue
		}
		if len(basePath) > bestLen {
			best, bestLen = metadataURL, len(basePath)
		}
	}
	return best
}

// WithAuthentication creates a middleware that validates JWT tokens from the Authorization header.
// It injects the claims into the request context if the token is valid.
// If the Header is present but invalid, it returns 401 Unauthorized.
// If the Header is missing, it proceeds without claims (anonymous access).
//
//nolint:gocyclo
func (c *Config) WithAuthentication(exchanger *Exchanger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := logf.FromContext(r.Context())

			authHeader := r.Header.Get("Authorization")
			var tokenString string

			var authSource string
			if authHeader != "" {
				parts := strings.Split(authHeader, " ")
				if len(parts) != 2 {
					log.Info("Invalid Authorization header format")
					http.Error(w, "Invalid Authorization header format", http.StatusBadRequest)
					return
				}
				// We are ignoreing basic auth because it may be used for OAuth2 client_id and client_secret
				if strings.ToLower(parts[0]) == "bearer" {
					tokenString = parts[1]
					authSource = "header"
				}
			} else {
				// Check for cookie
				cookie, err := r.Cookie(c.CookieName)
				if err != nil {
					// Anonymous access
					next.ServeHTTP(w, r)
					return
				}
				tokenString = cookie.Value
				authSource = COOKIE
			}

			authContext := AuthContext{}

			if tokenString == "" {
				log.Info("No token found")
				next.ServeHTTP(w, r)
				return
			}

			// A PASETO PAT presented as `Authorization: Bearer <pat>` is NOT a
			// host-audience JWT and must not be run through jwt.ParseWithClaims
			// (which would 401 it). Pass it through anonymously; this applies
			// only to the header source — a session cookie always carries the
			// host's own JWT.
			//
			// This middleware wraps the ENTIRE mux, so anything it authenticates
			// becomes an identity at every host endpoint. A PAT must therefore
			// NOT be authenticated here, for two independent reasons found by
			// review of kdex-tech/host-manager#175:
			//
			//   - Downstream, the function proxy bridge is guarded on
			//     !alreadyLoggedIn. An identity established here makes it step
			//     aside, and with it the PATBridgeClaim marker that mirrors the
			//     caller's entitlements into the "oauth2" scheme bucket. Nothing
			//     else populates that bucket, so an oauth2-declared operation
			//     then fails closed — regressing aa73843, which exists to make a
			//     developer key work on exactly those functions.
			//
			//   - Upstream, /-/oauth/authorize gates purely on the presence of an
			//     auth context. A PAT identity here is redeemable for an
			//     authorization code and thus a full JWT + rotating refresh
			//     token, which escapes the PAT's own jti revocation and ignores
			//     its scope. /-/apitokens/mint likewise becomes PAT-reachable.
			//
			// Endpoints that genuinely want a PAT identity opt in explicitly via
			// WithAPITokenIdentity, so nothing inherits it by default.
			if authSource == "header" && looksLikePAT(tokenString, c.TokenPrefix()) {
				next.ServeHTTP(w, r)
				return
			}

			// Host middleware accepts ONLY the host's own audience.
			// Pre-#86 it also accepted c.FunctionURLs — any function's
			// FAT (minted in proxy.go with aud=fn.Status.URL) leaked
			// into the host as a valid identity token, since Project
			// copies the user's roles/entitlements/sub into the FAT.
			// A function that logged or proxied its inbound
			// Authorization header surrendered a token replayable
			// across the entire host surface (confused-deputy).
			// Function backends still validate aud==fn.Status.URL
			// themselves; the host doesn't need to.
			audiences := []string{c.Audience}

			token, err := jwt.ParseWithClaims(
				tokenString,
				&authContext,
				func(token *jwt.Token) (any, error) {
					return c.ActivePair.Private.Public(), nil
				},
				jwt.WithIssuer(c.Issuer),
				jwt.WithAudience(audiences...),
			)

			if (err != nil || !token.Valid) && authSource == COOKIE && c.AutoExtendSession && exchanger != nil && exchanger.IsRefreshTokenEnabled() {
				// Token is invalid (e.g. expired), try to refresh it
				refreshCookie, cerr := r.Cookie(c.CookieName + "_refresh")
				if cerr == nil && refreshCookie.Value != "" {
					ts, rerr := exchanger.RedeemRefreshToken(r.Context(), refreshCookie.Value, "")
					if rerr == nil {
						// Update cookies
						http.SetCookie(w, &http.Cookie{
							Name:     c.CookieName,
							Value:    ts.AccessToken,
							Path:     "/",
							HttpOnly: true,
							Secure:   kdexhttp.IsSecure(r),
							SameSite: http.SameSiteLaxMode,
						})
						if ts.RefreshToken != "" {
							http.SetCookie(w, &http.Cookie{
								Name:     c.CookieName + "_refresh",
								Value:    ts.RefreshToken,
								Path:     "/",
								HttpOnly: true,
								Secure:   kdexhttp.IsSecure(r),
								SameSite: http.SameSiteLaxMode,
							})
						}

						// Update authContext for the current request — must
						// parse the FRESHLY-MINTED access token (ts.AccessToken),
						// NOT the inbound expired tokenString. The assignment
						// uses `=` (not `:=`) to update the OUTER token/err so
						// the post-block error-handler at line ~125 sees the
						// refreshed state. Pre-fix this both (a) re-parsed
						// tokenString (still expired → still invalid) AND
						// (b) used `:=` which created shadowed inner vars, so
						// even fixing (a) alone wasn't enough: the outer
						// error-handler still cleared both cookies (Max-Age:-1)
						// and redirected to "/", defeating auto-extend entirely
						// at every JWT TTL boundary. See #100.
						token, err = jwt.ParseWithClaims(
							ts.AccessToken,
							&authContext,
							func(token *jwt.Token) (any, error) {
								return c.ActivePair.Private.Public(), nil
							},
							jwt.WithIssuer(exchanger.config.Issuer),
							jwt.WithAudience(audiences...),
						)
						if err == nil && token.Valid {
							log.Info("Token refreshed after expiry")
						}
					}
				}
			}

			if err != nil || !token.Valid {
				// NOT an error. With jwt.tokenTTL at an hour, every session
				// crosses expiry hourly by design, and both branches below
				// treat the rejection as an expected outcome. Logged at V(1)
				// for the same reason hostPATIdentity logs its rejected
				// credential there. Left at ERROR, one client stuck replaying
				// a dead token kept every error-severity alert on the
				// deployment permanently lit (~5,700 lines/day, measured).
				// See kdex-tech/host-manager#181.
				cause := "the token is not valid"
				if err != nil {
					cause = err.Error()
				}
				log.V(1).Info("token is not valid; rejecting the credential",
					"source", authSource, "cause", cause)

				if authSource == COOKIE {
					// Clear the cookie
					http.SetCookie(w, &http.Cookie{
						Name:     c.CookieName,
						Value:    "",
						Path:     "/",
						MaxAge:   -1,
						HttpOnly: true,
						Secure:   kdexhttp.IsSecure(r),
						SameSite: http.SameSiteLaxMode,
					})
					// Also clear refresh token if present
					http.SetCookie(w, &http.Cookie{
						Name:     c.CookieName + "_refresh",
						Value:    "",
						Path:     "/",
						MaxAge:   -1,
						HttpOnly: true,
						Secure:   kdexhttp.IsSecure(r),
						SameSite: http.SameSiteLaxMode,
					})

					// Treat an unparseable/expired cookie the same as NO cookie:
					// the stale cookies are cleared above, then continue
					// anonymously so the wrapped handler decides the right
					// response — /-/oauth/authorize -> /-/login?return=<authorize
					// URL>, a gated page -> its own login redirect, a public page
					// -> render. Previously this hard-redirected to "/", which for
					// the OAuth/MCP authorize endpoint dropped the in-flight
					// authorize request (client_id/redirect_uri/state/…) and
					// bounced the user to root instead of login. See #141.
					next.ServeHTTP(w, r)
					return
				}

				// RFC 6750 §3 requires a challenge on every 401 issued over the
				// Bearer scheme, and RFC 9728's resource_metadata is what tells
				// an OAuth2/MCP client to re-authorize rather than retry. The
				// proxy's oauth2 gate emits exactly this for an ANONYMOUS
				// caller (internal/host/proxy.go), but it is never reached from
				// here — so without this the expired-token caller got a bare
				// 401 and no way back. See kdex-tech/host-manager#180.
				w.Header().Set("WWW-Authenticate", c.bearerChallenge(r.Context(), r.URL.Path, err))
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			if authSource == COOKIE && c.AutoExtendSession && exchanger != nil && exchanger.IsRefreshTokenEnabled() {
				exp, err := authContext.GetExpirationTime()
				if err == nil && exp != nil && time.Until(exp.Time) < 10*time.Minute {
					// Try to refresh
					refreshCookie, err := r.Cookie(c.CookieName + "_refresh")
					if err == nil && refreshCookie.Value != "" {
						ts, err := exchanger.RedeemRefreshToken(r.Context(), refreshCookie.Value, "")
						if err == nil {
							// Update cookies
							http.SetCookie(w, &http.Cookie{
								Name:     c.CookieName,
								Value:    ts.AccessToken,
								Path:     "/",
								HttpOnly: true,
								Secure:   kdexhttp.IsSecure(r),
								SameSite: http.SameSiteLaxMode,
							})
							if ts.RefreshToken != "" {
								http.SetCookie(w, &http.Cookie{
									Name:     c.CookieName + "_refresh",
									Value:    ts.RefreshToken,
									Path:     "/",
									HttpOnly: true,
									Secure:   kdexhttp.IsSecure(r),
									SameSite: http.SameSiteLaxMode,
								})
							}

							// Update authContext for the current request — must
							// parse ts.AccessToken (the freshly-minted token),
							// NOT the inbound tokenString. The near-expiry path
							// is less visibly broken than the expired path
							// because tokenString here is still-valid (just
							// close to exp), so the re-parse "succeeds" against
							// the stale token and the outer error-handler
							// doesn't fire. But any updated claims from the
							// refresh (entitlement changes, role changes since
							// the original mint) get silently dropped from the
							// in-request authContext. See #100.
							newToken, err := jwt.ParseWithClaims(
								ts.AccessToken,
								&authContext,
								func(token *jwt.Token) (any, error) {
									return c.ActivePair.Private.Public(), nil
								},
								jwt.WithIssuer(exchanger.config.Issuer),
								jwt.WithAudience(audiences...),
							)
							if err == nil && newToken.Valid {
								log.Info("Token refreshed")
							}
						} else {
							log.Error(err, "Failed to refresh token")
						}
					}
				}
			}

			// Bounded-use capability tokens carry the CapUsesClaim marker and a
			// jti-keyed budget. Decrement atomically; reject (fail-closed) when the
			// counter is missing or exhausted. Ordinary tokens (no marker) are
			// untouched. See #280.
			if c.MintCapCache != nil {
				if marker, _ := authContext[CapUsesClaim].(bool); marker {
					jti, _ := authContext["jti"].(string)
					if jti == "" {
						http.Error(w, "invalid capability token", http.StatusUnauthorized)
						return
					}
					if _, ok, derr := c.MintCapCache.DecrementIfPositive(r.Context(), "uses:"+jti); derr != nil || !ok {
						http.Error(w, "capability exhausted", http.StatusUnauthorized)
						return
					}
				}
			}

			// Inject authContext into context
			ctx := SetAuthContext(r.Context(), authContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

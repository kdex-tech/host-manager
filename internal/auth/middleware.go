package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

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
				log.Error(err, "Failed to parse JWT")

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

					// Redirect to root
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}

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

			// Inject authContext into context
			ctx := SetAuthContext(r.Context(), authContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

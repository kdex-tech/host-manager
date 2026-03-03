package auth

import (
	"crypto"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// WithAuthentication creates a middleware that validates JWT tokens from the Authorization header.
// It injects the claims into the request context if the token is valid.
// If the Header is present but invalid, it returns 401 Unauthorized.
// If the Header is missing, it proceeds without claims (anonymous access).
//
//nolint:gocyclo
func WithAuthentication(publicKey crypto.PublicKey, cookieName string, exchanger *Exchanger, autoExtend bool) func(http.Handler) http.Handler {
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
				cookie, err := r.Cookie(cookieName)
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

			token, err := jwt.ParseWithClaims(tokenString, &authContext, func(token *jwt.Token) (any, error) {
				return publicKey, nil
			})

			if (err != nil || !token.Valid) && authSource == COOKIE && autoExtend && exchanger != nil && exchanger.IsRefreshTokenEnabled() {
				// Token is invalid (e.g. expired), try to refresh it
				refreshCookie, cerr := r.Cookie(cookieName + "_refresh")
				if cerr == nil && refreshCookie.Value != "" {
					ts, rerr := exchanger.RedeemRefreshToken(r.Context(), refreshCookie.Value, "")
					if rerr == nil {
						// Update cookies
						http.SetCookie(w, &http.Cookie{
							Name:     cookieName,
							Value:    ts.AccessToken,
							Path:     "/",
							HttpOnly: true,
							Secure:   r.URL.Scheme == HTTPS,
							SameSite: http.SameSiteLaxMode,
						})
						if ts.RefreshToken != "" {
							http.SetCookie(w, &http.Cookie{
								Name:     cookieName + "_refresh",
								Value:    ts.RefreshToken,
								Path:     "/",
								HttpOnly: true,
								Secure:   r.URL.Scheme == HTTPS,
								SameSite: http.SameSiteLaxMode,
							})
						}

						// Update authContext for the current request
						token, err = jwt.ParseWithClaims(ts.AccessToken, &authContext, func(token *jwt.Token) (any, error) {
							return publicKey, nil
						})
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
						Name:     cookieName,
						Value:    "",
						Path:     "/",
						MaxAge:   -1,
						HttpOnly: true,
						Secure:   r.URL.Scheme == HTTPS,
						SameSite: http.SameSiteLaxMode,
					})
					// Also clear refresh token if present
					http.SetCookie(w, &http.Cookie{
						Name:     cookieName + "_refresh",
						Value:    "",
						Path:     "/",
						MaxAge:   -1,
						HttpOnly: true,
						Secure:   r.URL.Scheme == HTTPS,
						SameSite: http.SameSiteLaxMode,
					})

					// Redirect to root
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}

				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			if autoExtend && exchanger != nil && exchanger.IsRefreshTokenEnabled() && authSource == COOKIE {
				exp, err := authContext.GetExpirationTime()
				if err == nil && exp != nil && time.Until(exp.Time) < 10*time.Minute {
					// Try to refresh
					refreshCookie, err := r.Cookie(cookieName + "_refresh")
					if err == nil && refreshCookie.Value != "" {
						ts, err := exchanger.RedeemRefreshToken(r.Context(), refreshCookie.Value, "")
						if err == nil {
							// Update cookies
							http.SetCookie(w, &http.Cookie{
								Name:     cookieName,
								Value:    ts.AccessToken,
								Path:     "/",
								HttpOnly: true,
								Secure:   r.URL.Scheme == HTTPS,
								SameSite: http.SameSiteLaxMode,
							})
							if ts.RefreshToken != "" {
								http.SetCookie(w, &http.Cookie{
									Name:     cookieName + "_refresh",
									Value:    ts.RefreshToken,
									Path:     "/",
									HttpOnly: true,
									Secure:   r.URL.Scheme == HTTPS,
									SameSite: http.SameSiteLaxMode,
								})
							}

							// Update authContext for the current request
							newToken, err := jwt.ParseWithClaims(ts.AccessToken, &authContext, func(token *jwt.Token) (any, error) {
								return publicKey, nil
							})
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

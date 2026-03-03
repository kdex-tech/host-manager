package auth

import (
	"crypto"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// WithAuthentication creates a middleware that validates JWT tokens from the Authorization header.
// It injects the claims into the request context if the token is valid.
// If the Header is present but invalid, it returns 401 Unauthorized.
// If the Header is missing, it proceeds without claims (anonymous access).
func WithAuthentication(publicKey crypto.PublicKey, cookieName string) func(http.Handler) http.Handler {
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
				authSource = "cookie"
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

			if err != nil || !token.Valid {
				log.Error(err, "Failed to parse JWT")

				if authSource == "cookie" {
					// Clear the cookie
					http.SetCookie(w, &http.Cookie{
						Name:   cookieName,
						Value:  "",
						Path:   "/",
						MaxAge: -1,
					})
					// Redirect to root
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}

				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// TODO: now that refresh tokens are supported, we should implement auto extension of login session by
			// checking if the token is close to expiration and if so, reissuing it.

			// Inject authContext into context
			ctx := SetAuthContext(r.Context(), authContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

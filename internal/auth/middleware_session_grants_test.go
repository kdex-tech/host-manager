package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func mintCookieToken(t *testing.T, cfg *Config, priv any, ents []string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice", "iss": cfg.Issuer, "aud": cfg.Audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "openid roles entitlements", "entitlements": ents,
	}).SignedString(priv)
	require.NoError(t, err)
	return tok
}

func TestCookieSessionReflectsMembershipBump(t *testing.T) {
	cfg, ex, p, priv := newGrantTestSetup(t)
	token := mintCookieToken(t, cfg, priv, []string{"vector_stores:old:read"})

	var seen AuthContext
	handler := cfg.WithAuthentication(ex)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = GetAuthContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func() int {
		r := httptest.NewRequest("GET", "/api/v1/files", nil)
		r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}

	// Grant, made visible by a generation bump.
	p.grants = []string{"vector_stores:joined:read"}
	ex.BumpGrantGeneration(context.Background())
	require.Equal(t, http.StatusNoContent, request())
	require.Contains(t, seen["entitlements"], "vector_stores:joined:read")

	// Revocation, via a bump.
	p.grants = nil
	ex.BumpGrantGeneration(context.Background())
	require.Equal(t, http.StatusNoContent, request())
	require.NotContains(t, seen["entitlements"], "vector_stores:joined:read")
}

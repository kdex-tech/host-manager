package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationRecordsTheCredentialSource(t *testing.T) {
	f := newOIDCFixture(t)
	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)
	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	var got string
	h := f.cfg.AddAuthentication(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = AuthSourceFromContext(r.Context())
	}), f.ex)

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: f.cfg.CookieName, Value: ts.AccessToken})
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, COOKIE, got)

	got = ""
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+ts.AccessToken)
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "header", got)
}

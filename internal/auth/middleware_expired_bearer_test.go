/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// expiredBearerConfig builds a Config whose signing key is `priv`, with one
// oauth2-protected resource registered at /api/v1/mcp.
func expiredBearerConfig(t *testing.T) (*Config, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	return &Config{
		Audience:   "https://dev.example.test",
		Issuer:     "https://dev.example.test",
		CookieName: "auth_token",
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		OAuth2ResourceMetadata: map[string]string{
			"/api/v1/mcp": "https://dev.example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		},
	}, priv
}

// mintExpiredToken hand-builds a token that is well-formed and correctly signed
// for this host — right issuer, right audience — and expired. Only the `exp`
// claim makes it invalid, so a rejection can be attributed to expiry alone.
func mintExpiredToken(t *testing.T, priv *ecdsa.PrivateKey, c *Config) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice",
		"aud": c.Audience,
		"iss": c.Issuer,
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

// TestWithAuthentication_ExpiredBearerEmitsChallenge pins kdex-tech/host-manager#180.
//
// An anonymous request to an oauth2-protected function already receives an RFC
// 9728 challenge (emitted by the proxy gate, internal/host/proxy.go). The same
// request carrying an EXPIRED bearer used to receive a bare `401 Invalid token`
// with no WWW-Authenticate at all, because this middleware short-circuits before
// the proxy is reached. That is a violation of RFC 6750 §3 on its own, and it
// denies an OAuth2/MCP client the only standards-defined signal that it must
// re-authorize rather than retry — which is exactly what left kd-inspector
// replaying a dead token every 30s indefinitely.
func TestWithAuthentication_ExpiredBearerEmitsChallenge(t *testing.T) {
	c, priv := expiredBearerConfig(t)
	expired := mintExpiredToken(t, priv, c)

	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
	handler := c.WithAuthentication(nil)(next)

	do := func(t *testing.T, path string) *httptest.ResponseRecorder {
		t.Helper()
		nextCalled = false
		req := httptest.NewRequest("POST", path, nil)
		req.Header.Set("Authorization", "Bearer "+expired)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("a protected resource gets the RFC 9728 resource_metadata pointer", func(t *testing.T) {
		rec := do(t, "/api/v1/mcp")

		assert.False(t, nextCalled, "an expired bearer must not reach the wrapped handler")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)

		challenge := rec.Header().Get("WWW-Authenticate")
		require.NotEmpty(t, challenge,
			"RFC 6750 §3: a 401 over the Bearer scheme MUST carry WWW-Authenticate")
		assert.Contains(t, challenge, `error="invalid_token"`)
		assert.Contains(t, challenge,
			`resource_metadata="https://dev.example.test/.well-known/oauth-protected-resource/api/v1/mcp"`,
			"the challenge must point at this resource's metadata, matching what the anonymous path emits")
	})

	t.Run("a sub-path of a protected resource resolves to the same pointer", func(t *testing.T) {
		rec := do(t, "/api/v1/mcp/messages")

		challenge := rec.Header().Get("WWW-Authenticate")
		assert.Contains(t, challenge,
			`resource_metadata="https://dev.example.test/.well-known/oauth-protected-resource/api/v1/mcp"`,
			"a request under the basePath belongs to the same protected resource")
	})

	t.Run("expiry is distinguished from a merely malformed token", func(t *testing.T) {
		rec := do(t, "/api/v1/mcp")
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"),
			`error_description="the access token expired"`)

		nextCalled = false
		req := httptest.NewRequest("POST", "/api/v1/mcp", nil)
		req.Header.Set("Authorization", "Bearer eyJhbGciOiJFUzI1NiJ9.garbage.garbage")
		garbled := httptest.NewRecorder()
		handler.ServeHTTP(garbled, req)

		assert.Equal(t, http.StatusUnauthorized, garbled.Code)
		assert.Contains(t, garbled.Header().Get("WWW-Authenticate"),
			`error_description="the access token is invalid"`)
	})

	t.Run("a path outside any protected resource still gets a conformant challenge", func(t *testing.T) {
		rec := do(t, "/-/apitokens/mint")

		challenge := rec.Header().Get("WWW-Authenticate")
		require.NotEmpty(t, challenge, "RFC 6750 applies to every Bearer 401, not just oauth2 resources")
		assert.Contains(t, challenge, `error="invalid_token"`)
		assert.NotContains(t, challenge, "resource_metadata",
			"a path that is not an oauth2-protected resource has no metadata document to point at")
	})

	t.Run("the cookie path is untouched", func(t *testing.T) {
		// #141: an expired cookie is cleared and the request continues
		// anonymously so the wrapped handler picks the response. That
		// behaviour must survive this change — a challenge here would be
		// wrong (the caller is a browser, not a bearer client) and a 401
		// would reintroduce the bug #141 fixed.
		nextCalled = false
		req := httptest.NewRequest("GET", "/api/v1/mcp", nil)
		req.AddCookie(&http.Cookie{Name: c.CookieName, Value: expired})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, nextCalled, "an expired cookie must still fall through anonymously")
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
			"the cookie path must not emit a bearer challenge")
	})
}

// TestWithAuthentication_ExpiredCredentialIsNotAnError pins
// kdex-tech/host-manager#181.
//
// An expired credential is the most routine event a token has — with
// jwt.tokenTTL at 1h every session crosses it hourly by design, and the
// middleware handles it as expected (clear cookies, continue anonymously). It
// was nonetheless logged at ERROR, so a single client stuck replaying a dead
// token produced ~5,700 ERROR lines a day and kept every error-severity alert
// on the deployment permanently lit.
//
// The sibling rejection path in this file already sets the precedent:
// hostPATIdentity logs its rejected credential at V(1) "rather than an error".
func TestWithAuthentication_ExpiredCredentialIsNotAnError(t *testing.T) {
	c, priv := expiredBearerConfig(t)
	expired := mintExpiredToken(t, priv, c)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := c.WithAuthentication(nil)(next)

	serve := func(t *testing.T, verbosity int) string {
		t.Helper()
		var logged strings.Builder
		logger := funcr.New(func(prefix, args string) {
			logged.WriteString(args)
			logged.WriteString("\n")
		}, funcr.Options{Verbosity: verbosity})

		req := httptest.NewRequest("POST", "/api/v1/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+expired)
		req = req.WithContext(logf.IntoContext(req.Context(), logger))

		handler.ServeHTTP(httptest.NewRecorder(), req)
		return logged.String()
	}

	t.Run("silent at the default verbosity", func(t *testing.T) {
		assert.Empty(t, serve(t, 0),
			"a rejected credential is a client condition, not a host error; "+
				"it must not reach an operator running at the default log level")
	})

	t.Run("still recorded at V(1) for debugging", func(t *testing.T) {
		logged := serve(t, 1)
		assert.Contains(t, logged, "token is not valid",
			"the rejection must remain visible under --named-log-level=server=1")
		assert.Contains(t, logged, "token is expired",
			"the underlying cause must be preserved as a field")
	})
}

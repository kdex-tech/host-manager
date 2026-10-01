/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithAuthentication_RequiresExp pins kdex-tech/host-manager#227: the gate
// must reject a host-signed token that does not expire. golang-jwt v5 treats
// `exp` as optional unless required, and reads `exp: 0` as absent, so both
// shapes were accepted as identities that never expire. Each token below is
// otherwise valid -- this host's key, issuer and audience -- so a rejection is
// attributable to `exp` alone.
func TestWithAuthentication_RequiresExp(t *testing.T) {
	c, priv := expiredBearerConfig(t)

	mint := func(t *testing.T, exp any, setExp bool) string {
		t.Helper()
		claims := jwt.MapClaims{
			"sub": "alice",
			"aud": c.Audience,
			"iss": c.Issuer,
			"iat": time.Now().Unix(),
		}
		if setExp {
			claims["exp"] = exp
		}
		signed, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(priv)
		require.NoError(t, err)
		return signed
	}

	tokens := []struct {
		name     string
		token    string
		accepted bool
	}{
		{"valid exp", mint(t, time.Now().Add(time.Hour).Unix(), true), true},
		{"no exp", mint(t, nil, false), false},
		{"exp 0", mint(t, 0, true), false},
	}

	for _, source := range []string{"header", COOKIE} {
		for _, tc := range tokens {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				var reached bool
				handler := c.WithAuthentication(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, reached = GetAuthContext(r.Context())
				}))

				req := httptest.NewRequest(http.MethodGet, "/", nil)
				if source == "header" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				} else {
					req.AddCookie(&http.Cookie{Name: c.CookieName, Value: tc.token})
				}
				handler.ServeHTTP(httptest.NewRecorder(), req)

				assert.Equal(t, tc.accepted, reached, "authenticated identity reached the handler")
			})
		}
	}
}

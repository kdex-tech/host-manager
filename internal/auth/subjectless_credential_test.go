/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// subjectlessStubProvider vouches for the credential and returns the identity
// claims WITHOUT a `sub`. This is not a contrived shape:
//
//   - secretLookup.FindInternal (roles.go) builds its claims from the Secret's
//     data keys minus `password`, and its matcher accepts a Secret that carries
//     only `email` -- `(hasSub && sub == subject) || (hasEmail && email ==
//     subject)`. An email-keyed credential Secret therefore resolves with no
//     `sub` key at all.
//   - httpLookup.FindInternal (lookup_http.go) returns the backend's `claims`
//     object verbatim, substituting an EMPTY MapClaims when the backend omits
//     it. `{"ok":true}` is a successful credential check with no subject.
//
// scopeProvider.FindInternal then adds only `roles` and `entitlements`, and
// LoginLocal's reserved-claim strip explicitly SKIPS `sub` -- it preserves
// whatever the lookup supplied and never derives one from `username`.
type subjectlessStubProvider struct{}

func (subjectlessStubProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"email": "nobody@example.test"}, nil
}

func (subjectlessStubProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func subjectlessExchanger(t *testing.T) (*Exchanger, *Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		CookieName: "auth_token",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "subjectless-credential-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, subjectlessStubProvider{})
	require.NoError(t, err)
	return ex, &cfg
}

// A subject-less credential is NOT a supported configuration. This is the
// MINT end of that ruling.
//
// The hinge is that jwt.MapClaims.GetSubject reports a MISSING `sub` as
// ("", nil) rather than as an error, so before this refusal existed
// sign.Signer.Project copied the empty string into the token it signed and
// nothing downstream objected: the host middleware validates only `iss` and
// `aud`, and `sub` is not a required claim in golang-jwt v5. The credential
// check SUCCEEDS here -- that is the point. What must not follow it is a
// token nobody can be attributed to.
func TestSubjectlessCredentialIsRefusedAtLogin(t *testing.T) {
	ex, _ := subjectlessExchanger(t)

	ts, err := ex.LoginLocal(context.Background(), "nobody@example.test", "pw", "", "", AuthMethodLocal)

	require.Error(t, err, "the credential check succeeded but named nobody; the login must fail closed")
	assert.ErrorIs(t, err, sign.ErrSubjectlessCredential)
	assert.ErrorIs(t, err, ErrServerError,
		"no password the caller could type makes a Secret grow a `sub` key -- this is a server fault")
	assert.Empty(t, ts.AccessToken, "no token may be minted for a credential that names nobody")
	assert.Empty(t, ts.RefreshToken)
}

// The signer is the invariant behind the login check: nothing this process
// signs can carry an empty subject, whichever call path reaches it. Project
// is the first chokepoint (where the empty subject is manufactured);
// SignProjected is the last (the direct callers in internal/host that hold a
// projection and never come back through Project).
func TestSignerRefusesToMintASubjectlessToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	for name, ctx := range map[string]jwt.MapClaims{
		"no sub claim": {"email": "nobody@example.test"},
		"empty sub":    {"sub": ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, perr := signer.Project(ctx)
			assert.ErrorIs(t, perr, sign.ErrSubjectlessCredential, "Project must refuse")

			_, serr := signer.Sign(ctx)
			assert.ErrorIs(t, serr, sign.ErrSubjectlessCredential, "Sign must refuse")

			// SignProjected is reached directly by internal/host/mint_token.go
			// and the FAT path in internal/host/proxy.go, the latter with a
			// CACHED projection, so it must refuse on its own account.
			_, sperr := signer.SignProjected(ctx)
			assert.ErrorIs(t, sperr, sign.ErrSubjectlessCredential, "SignProjected must refuse")
		})
	}
}

// The VALIDATION end of the same ruling, and the reason it is not enough to
// refuse at mint: a token minted before this branch, or by any other holder
// of the signing key, is still on the wire. WithAuthentication treats it as
// an invalid credential -- which for a bearer means 401 + challenge, and for
// a cookie means the cookie is cleared and the request continues anonymously.
func TestSubjectlessTokenIsRefusedAtValidation(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	c := &Config{
		Audience:   "https://dev.example.test",
		Issuer:     "https://dev.example.test",
		CookieName: "auth_token",
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
	}

	// Hand-signed with the host's own key so the ONLY thing wrong with it is
	// the subject: right issuer, right audience, unexpired, valid signature.
	mint := func(claims jwt.MapClaims) string {
		claims["aud"] = c.Audience
		claims["iss"] = c.Issuer
		claims["iat"] = time.Now().Add(-time.Minute).Unix()
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		signed, serr := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(priv)
		require.NoError(t, serr)
		return signed
	}

	for name, claims := range map[string]jwt.MapClaims{
		"no sub claim": {},
		"empty sub":    {"sub": ""},
	} {
		t.Run(name+"/bearer", func(t *testing.T) {
			var reached bool
			handler := c.WithAuthentication(nil)(http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) { reached = true }))

			req := httptest.NewRequest("GET", "/api/v1/mcp", nil)
			req.Header.Set("Authorization", "Bearer "+mint(claims))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.False(t, reached, "a credential that names nobody must not reach the handler")
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"),
				"RFC 6750 §3: a 401 over the Bearer scheme MUST carry a challenge")
		})

		t.Run(name+"/cookie", func(t *testing.T) {
			var got AuthContext
			var reached bool
			handler := c.WithAuthentication(nil)(http.HandlerFunc(
				func(_ http.ResponseWriter, r *http.Request) {
					reached = true
					got, _ = GetAuthContext(r.Context())
				}))

			req := httptest.NewRequest("GET", "/some-page", nil)
			req.AddCookie(&http.Cookie{Name: c.CookieName, Value: mint(claims)})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Same footing as any other invalid cookie: cleared, then the
			// request continues ANONYMOUSLY so the wrapped handler decides
			// (a gated page redirects to login, a public page renders).
			assert.True(t, reached, "an invalid cookie continues anonymously; it does not 401")
			assert.Nil(t, got, "no auth context may be injected for a credential that names nobody")
			assert.Contains(t, rec.Header().Get("Set-Cookie"), "Max-Age=0",
				"the unusable cookie must be cleared, as for any other invalid token")
		})
	}
}

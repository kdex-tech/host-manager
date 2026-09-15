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
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientCredsStubIdentityProvider struct {
	roles []string
	ents  []string
}

func (s clientCredsStubIdentityProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	// Mirror the real scopeProvider.FindInternal: the returned identity already
	// carries roles + entitlements resolved from RoleBindings.
	return jwt.MapClaims{
		"sub":          subject,
		"roles":        s.roles,
		"entitlements": s.ents,
	}, nil
}

func (s clientCredsStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return s.roles, s.ents, nil
}

func newClientCredsExchanger(t *testing.T, allowedScopes []string, idp InternalIdentityProvider) *Exchanger {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		// TokenTTL feeds sign.NewSigner for any per-call signer built off this
		// config (e.g. LoginClientResource's resource-audience signer); the
		// host-audience Signer above is pre-built and does not consult it.
		TokenTTL: time.Hour,
		Clients: map[string]AuthClient{
			"sim-launcher": {
				ClientID:          "sim-launcher",
				ClientSecret:      "s3cret",
				AllowedGrantTypes: []string{"client_credentials"},
				AllowedScopes:     allowedScopes,
			},
			"eum-blobsqlite": {
				ClientID:          "eum-blobsqlite",
				ClientSecret:      "s3cret",
				AllowedGrantTypes: []string{"client_credentials"},
				AllowedScopes:     allowedScopes,
			},
		},
	}

	cm, err := cache.NewCacheManager("", "client-creds-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, idp, nil)
	require.NoError(t, err)
	return ex
}

// claimString returns a string claim from a decoded (unverified) token.
func claimString(t *testing.T, token, claim string) string {
	t.Helper()
	claims := decodeUnverified(t, token)
	v, _ := claims[claim].(string)
	return v
}

// audOf returns the `aud` claim as a []string regardless of whether the JWT
// library round-trips it as a JSON array of strings ([]any under
// jwt.MapClaims) or (per RFC 7519 §4.1.3) a bare string.
func audOf(t *testing.T, token string) []string {
	t.Helper()
	claims := decodeUnverified(t, token)
	switch aud := claims["aud"].(type) {
	case []any:
		out := make([]string, 0, len(aud))
		for _, a := range aud {
			s, _ := a.(string)
			out = append(out, s)
		}
		return out
	case string:
		return []string{aud}
	default:
		return nil
	}
}

// claimJSON returns a claim re-marshaled to JSON so two claims (e.g. `roles`,
// `entitlements`) can be compared for deep equality regardless of the exact
// dynamic type ParseUnverified produced for each.
func claimJSON(t *testing.T, token, claim string) string {
	t.Helper()
	claims := decodeUnverified(t, token)
	b, err := json.Marshal(claims[claim])
	require.NoError(t, err)
	return string(b)
}

// TestLoginClient_IncludesResolvedEntitlements pins the fix for
// kdex-tech/host-manager#105. Pre-fix LoginClient signed an access token with
// only {sub, azp, auth_method, grant_type, scope} — it never resolved the
// client's roles/entitlements, so every client_credentials token reached the
// proxy identity gate with empty entitlements and 404'd on secured paths.
func TestLoginClient_IncludesResolvedEntitlements(t *testing.T) {
	idp := clientCredsStubIdentityProvider{
		roles: []string{"sim-runner"},
		ents:  []string{"functions:vector_stores:write"},
	}

	t.Run("no scope requested: defaults to roles+entitlements", func(t *testing.T) {
		ex := newClientCredsExchanger(t, nil, idp)
		ts, err := ex.LoginClient(context.Background(), "sim-launcher", "s3cret", "")
		require.NoError(t, err)
		require.NotEmpty(t, ts.AccessToken)

		claims := decodeUnverified(t, ts.AccessToken)
		assert.Equal(t, "sim-launcher", claims["sub"])

		ents, hasEnt := claims["entitlements"].([]any)
		require.True(t, hasEnt, "entitlements claim must be present on a client_credentials token (#105)")
		assert.Contains(t, ents, "functions:vector_stores:write")

		roles, hasRoles := claims["roles"].([]any)
		require.True(t, hasRoles, "roles claim must be present on a client_credentials token (#105)")
		assert.Contains(t, roles, "sim-runner")
	})

	t.Run("scope=entitlements: entitlements present, roles absent", func(t *testing.T) {
		ex := newClientCredsExchanger(t, []string{"entitlements"}, idp)
		ts, err := ex.LoginClient(context.Background(), "sim-launcher", "s3cret", "entitlements")
		require.NoError(t, err)

		claims := decodeUnverified(t, ts.AccessToken)
		_, hasEnt := claims["entitlements"]
		_, hasRoles := claims["roles"]
		assert.True(t, hasEnt, "entitlements must be present when its scope is requested")
		assert.False(t, hasRoles, "roles must be absent when only entitlements scope is requested")
	})
}

// TestAllGrantTypes_CarryEntitlements is the cross-grant guard for #105: every
// grant type the token endpoint dispatches must mint an access token carrying
// the subject's resolved entitlements, so no path can regress to the
// client_credentials gap. The token endpoint (oauth2.go) routes:
//   - password           -> LoginLocal
//   - client_credentials -> LoginClient
//   - authorization_code -> RedeemAuthorizationCode -> mintTokensFromCode
//   - refresh_token      -> RedeemRefreshToken -> mintTokensFromSubject
func TestAllGrantTypes_CarryEntitlements(t *testing.T) {
	idp := clientCredsStubIdentityProvider{
		roles: []string{"sim-runner"},
		ents:  []string{"functions:vector_stores:write"},
	}
	ex := newClientCredsExchanger(t, nil, idp)

	assertEntitlements := func(t *testing.T, grantType, token string) {
		t.Helper()
		require.NotEmpty(t, token, "%s: empty access token", grantType)
		claims := decodeUnverified(t, token)
		ents, ok := claims["entitlements"].([]any)
		require.Truef(t, ok, "%s: entitlements claim must be present (#105)", grantType)
		assert.Containsf(t, ents, "functions:vector_stores:write",
			"%s: token must carry the subject's resolved entitlements", grantType)
	}

	t.Run("password", func(t *testing.T) {
		ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "sim-launcher", AuthMethodOAuth2)
		require.NoError(t, err)
		assertEntitlements(t, "password", ts.AccessToken)
	})

	t.Run("client_credentials", func(t *testing.T) {
		ts, err := ex.LoginClient(context.Background(), "sim-launcher", "s3cret", "")
		require.NoError(t, err)
		assertEntitlements(t, "client_credentials", ts.AccessToken)
	})

	t.Run("authorization_code", func(t *testing.T) {
		ts, err := ex.mintTokensFromCode(context.Background(), AuthorizationCodeClaims{
			Subject:    "alice",
			ClientID:   "sim-launcher",
			Scope:      "entitlements",
			AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		assertEntitlements(t, "authorization_code", ts.AccessToken)
	})

	t.Run("refresh_token", func(t *testing.T) {
		ts, _, err := ex.mintTokensFromSubject("alice", "sim-launcher", "entitlements", AuthMethodOAuth2, nil)
		require.NoError(t, err)
		assertEntitlements(t, "refresh_token", ts.AccessToken)
	})
}

// TestLoginClientResource_MintsTargetAudienceWithSameAuthority pins the new
// client_credentials resource-audience mint: a confidential client that
// already authenticates for a host-audience token via LoginClient can obtain
// the SAME subject/authority signed for a peer resource's audience instead,
// with no RFC 8693 exchange round trip.
func TestLoginClientResource_MintsTargetAudienceWithSameAuthority(t *testing.T) {
	g := NewWithT(t)
	idp := clientCredsStubIdentityProvider{
		roles: []string{"sim-runner"},
		ents:  []string{"functions:vector_stores:write"},
	}
	e := newClientCredsExchanger(t, nil, idp)
	const target = "https://host.example/db/v1" // any non-host audience string

	host, err := e.LoginClient(context.Background(), "eum-blobsqlite", "s3cret", "")
	g.Expect(err).ToNot(HaveOccurred())
	res, err := e.LoginClientResource(context.Background(), "eum-blobsqlite", "s3cret", "", target)
	g.Expect(err).ToNot(HaveOccurred())

	// Same subject + authority, different audience.
	g.Expect(claimString(t, res.AccessToken, "sub")).To(Equal("eum-blobsqlite"))
	g.Expect(audOf(t, res.AccessToken)).To(ConsistOf(target))
	g.Expect(audOf(t, host.AccessToken)).ToNot(ConsistOf(target)) // host token is host-aud
	g.Expect(claimJSON(t, res.AccessToken, "entitlements")).To(Equal(claimJSON(t, host.AccessToken, "entitlements")))
	g.Expect(claimJSON(t, res.AccessToken, "roles")).To(Equal(claimJSON(t, host.AccessToken, "roles")))

	// Bad secret still rejected on the resource path.
	_, err = e.LoginClientResource(context.Background(), "eum-blobsqlite", "wrong", "", target)
	g.Expect(err).To(HaveOccurred())
}

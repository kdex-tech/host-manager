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
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
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

// TestSubjectlessTokenIsReachableFromLocalLogin settles the reachability
// question the denial contract's subject-less handling depends on: YES, a
// validated credential can produce an auth context with an empty subject.
//
// The hinge is that jwt.MapClaims.GetSubject reports a MISSING `sub` as
// ("", nil) rather than as an error, so sign.Signer.Project copies the empty
// string into the token it signs and nothing downstream objects: the host
// middleware validates only `iss` and `aud`, and `sub` is not a required claim
// in golang-jwt v5.
//
// Every gate that treats the resulting caller as anonymous -- denial.Classify,
// and the page gate's login-redirect bound -- is guarding a live case, not a
// hypothetical one.
func TestSubjectlessTokenIsReachableFromLocalLogin(t *testing.T) {
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
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "subjectless-credential-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, subjectlessStubProvider{})
	require.NoError(t, err)

	ts, err := ex.LoginLocal(context.Background(), "nobody@example.test", "pw", "", "", AuthMethodLocal)
	require.NoError(t, err, "the credential check SUCCEEDED; this is a valid login")
	require.NotEmpty(t, ts.AccessToken)

	// Parse it exactly as WithAuthentication does: issuer + audience, nothing
	// about the subject.
	authContext := AuthContext{}
	token, err := jwt.ParseWithClaims(ts.AccessToken, &authContext,
		func(*jwt.Token) (any, error) { return cfg.ActivePair.Private.Public(), nil },
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
	)
	require.NoError(t, err, "the host's own middleware accepts this token")
	require.True(t, token.Valid)

	sub, err := authContext.GetSubject()
	require.NoError(t, err)
	if sub != "" {
		t.Fatalf("sub = %q; this test exists because a validated credential CAN name nobody, "+
			"and the gates' subject-less handling would be guarding nothing if it could not", sub)
	}
}

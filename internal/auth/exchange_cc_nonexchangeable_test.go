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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ccPivotStubIdentityProvider satisfies InternalIdentityProvider for this
// suite. It only needs to answer for "eum-blobsqlite" (the client identity),
// mirroring the shape clientCredsStubIdentityProvider uses elsewhere in this
// package.
type ccPivotStubIdentityProvider struct{}

func (ccPivotStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}

func (ccPivotStubIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return []string{"db-client"}, []string{"functions:/db/v1:call"}, nil
}

// newCCPivotExchanger builds an Exchanger wired for BOTH client_credentials
// (M2M: Clients + ActivePair) and RFC 8693 exchange (Audience set, so
// ExchangeSubjectToken's FAT audience gate has a host audience to compare
// against). "eum-blobsqlite" is the confidential client, allowlisted (by the
// caller, outside this package) for only the db resource -- that allowlist
// enforcement itself lives in the token handler, not here; this fixture only
// needs a client that CAN mint a resource-audience token via
// LoginClientResource, exactly as the token handler would after checking
// allowed-resources.
func newCCPivotExchanger(t *testing.T) (*Exchanger, crypto.Signer) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	hostSigner, err := sign.NewSigner("https://host.example", time.Hour, "https://host.example", &cs, "kid-1", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:   "https://host.example",
		Audience: "https://host.example",
		Signer:   *hostSigner,
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     "kid-1",
			Private:   cs,
		},
		TokenTTL: time.Hour,
		Clients: map[string]AuthClient{
			"eum-blobsqlite": {
				ClientID:          "eum-blobsqlite",
				ClientSecret:      "s3cret",
				AllowedGrantTypes: []string{"client_credentials"},
			},
		},
	}

	cm, err := cache.NewCacheManager("", "cc-pivot-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, ccPivotStubIdentityProvider{}, nil)
	require.NoError(t, err)
	return ex, cs
}

// TestExchangeSubjectToken_RejectsClientCredentialsMintedToken pins the fix
// for the allowed-resources pivot: a client allowlisted (by the token
// handler) for only one resource must not be able to mint a
// client_credentials + `resource` token addressed to that resource (T1,
// which LoginClientResource mints exactly as the real handler would after
// its own allowlist check) and then present T1 as a subject_token to
// ExchangeSubjectToken to obtain a token for a DIFFERENT, never-allowlisted
// audience (T2). ExchangeSubjectToken is clientless and has no
// allowed-resources of its own to consult, so it must instead reject any
// subject_token stamped with a client_credentials `grant_type` outright.
//
// Before the fix this test is RED: T1 passes every existing FAT gate (it has
// no kdx_cap marker, and its aud is a single non-host value), so
// ExchangeSubjectToken happily re-signs it for the "other" audience -- the
// exact pivot the allowlist was supposed to prevent.
func TestExchangeSubjectToken_RejectsClientCredentialsMintedToken(t *testing.T) {
	e, _ := newCCPivotExchanger(t)
	ctx := context.Background()

	const dbAudience = "https://fn-db.ns.svc.cluster.local"
	const otherAudience = "https://fn-other.ns.svc.cluster.local"

	// T1: the client_credentials + resource mint, addressed to the ONE
	// resource "eum-blobsqlite" is allowlisted for. This is exactly what
	// LoginClientResource produces -- the same call the token handler makes
	// after checking allowed-resources.
	t1, err := e.LoginClientResource(ctx, "eum-blobsqlite", "s3cret", "", dbAudience)
	require.NoError(t, err)
	require.NotEmpty(t, t1.AccessToken)
	require.Equal(t, []string{dbAudience}, audOf(t, t1.AccessToken))

	// The pivot: present T1 as a subject_token, asking to exchange it for a
	// DIFFERENT audience the client was never allowlisted for.
	t2, err := e.ExchangeSubjectToken(t1.AccessToken, otherAudience)

	require.Error(t, err, "a client_credentials-minted token must not be exchangeable")
	assert.Contains(t, err.Error(), "client_credentials",
		"the rejection should name why: the subject_token was minted via client_credentials")
	assert.Empty(t, t2.AccessToken, "no token addressed to the un-allowlisted audience may be produced")
	if len(t2.AccessToken) > 0 {
		assert.NotContains(t, audOf(t, t2.AccessToken), otherAudience)
	}
}

// TestExchangeSubjectToken_RejectsClientCredentialsHostAudienceToken is a
// smaller companion covering the plain (non-resource) client_credentials
// mint via LoginClient: it too carries grant_type=client_credentials, and
// while its host audience already fails the separate #206 aud gate, this
// pins that the NEW grant_type gate independently rejects it (defense in
// depth -- the two gates check different things and neither should be load
// bearing alone for this case).
func TestExchangeSubjectToken_RejectsClientCredentialsHostAudienceToken(t *testing.T) {
	e, _ := newCCPivotExchanger(t)
	ctx := context.Background()

	host, err := e.LoginClient(ctx, "eum-blobsqlite", "s3cret", "")
	require.NoError(t, err)
	require.NotEmpty(t, host.AccessToken)

	claims := decodeUnverified(t, host.AccessToken)
	require.Equal(t, "client_credentials", claims["grant_type"])

	ts, err := e.ExchangeSubjectToken(host.AccessToken, "https://fn-other.ns.svc.cluster.local")
	require.Error(t, err)
	assert.Empty(t, ts.AccessToken)
}

// TestExchangeSubjectToken_GenuineFATHasNoGrantTypeClaim documents the
// invariant the fix relies on: a genuine FAT -- minted by sign.Signer.Sign
// directly, as every proxy FAT and every ExchangeSubjectToken output is --
// carries no `grant_type` claim at all, so the new gate cannot false-positive
// on it. The full happy-path exchange (mint, re-resolved entitlements, `act`
// claim) is already covered by
// TestExchangeSubjectToken_MintsForTargetAudienceWithReResolvedEntitlements
// in exchange_tokenexchange_test.go and is NOT duplicated here.
func TestExchangeSubjectToken_GenuineFATHasNoGrantTypeClaim(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	fatSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Hour, "https://host.example", &cs, "kid-1", nil)
	require.NoError(t, err)
	fat, err := fatSigner.Sign(jwt.MapClaims{"sub": "alice"})
	require.NoError(t, err)

	claims := decodeUnverified(t, fat)
	_, hasGrantType := claims["grant_type"]
	assert.False(t, hasGrantType, "a genuine FAT must carry no grant_type claim")
}

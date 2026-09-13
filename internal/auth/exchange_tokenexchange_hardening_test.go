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
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// texHardeningProvider resolves "alice" to a role entitlement AND delivers a
// backend Lookup claim (vs_entitlements) so a test can prove the exchanged token
// carries BOTH the role-resolved grant and a ClaimMappings-folded backend grant.
type texHardeningProvider struct{}

func (texHardeningProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (texHardeningProvider) FindInternalRolesAndEntitlements(sub string) ([]string, []string, error) {
	if sub != "alice" {
		return nil, nil, nil
	}
	return []string{"internal-reader"}, []string{"functions:/v1/internal:read"}, nil
}
func (texHardeningProvider) ResolveClaims(sub string) jwt.MapClaims {
	if sub != "alice" {
		return nil
	}
	return jwt.MapClaims{"vs_entitlements": []string{"vector_stores:vs1:read"}}
}

// newTexHardeningExchanger builds an Exchanger with an explicit host audience and
// (optionally) a ClaimMappings mapper, wired to texHardeningProvider.
func newTexHardeningExchanger(t *testing.T, cs *crypto.Signer, kid, issuer, hostAud string, mapper *dmapper.Mapper) *Exchanger {
	t.Helper()
	cfg := Config{
		Issuer:      issuer,
		Audience:    hostAud,
		ActivePair:  &keys.KeyPair{ActiveKey: true, KeyId: kid, Private: *cs},
		TokenTTL:    time.Hour,
		ClaimMapper: mapper,
	}
	ex, err := NewExchanger(context.Background(), cfg, nil, texHardeningProvider{}, nil)
	require.NoError(t, err)
	return ex
}

// rawJWT signs an arbitrary claim set directly (bypassing sign.Signer.Project's
// allowlist), so a test can present a token carrying claims the signer would not
// itself emit -- e.g. the kdx_cap capability marker.
func rawJWT(t *testing.T, cs *crypto.Signer, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(*cs)
	require.NoError(t, err)
	return signed
}

// TestExchangeSubjectToken_RejectsCapabilityToken pins SEC-1/DI-1: a bounded-use
// capability (kdx_cap) must NOT be exchangeable, or its attenuation + single-use
// bounds are voided by re-inflation to the subject's full authority.
func TestExchangeSubjectToken_RejectsCapabilityToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	e := newTexHardeningExchanger(t, &cs, "kid-1", "https://host.example", "https://host.example", nil)

	// A capability token: function-audience, host-signed, but marked kdx_cap.
	cap := rawJWT(t, &cs, "kid-1", jwt.MapClaims{
		"sub":          "alice",
		"aud":          []string{"https://fn-a.ns.svc.cluster.local"},
		"iss":          "https://host.example",
		"exp":          time.Now().Add(time.Hour).Unix(),
		"iat":          time.Now().Unix(),
		CapUsesClaim:   true,
		"entitlements": []string{"vector_stores:vs1:read"},
	})

	ts, err := e.ExchangeSubjectToken(cap, "https://fn-b.ns.svc.cluster.local")
	require.Error(t, err, "an attenuated capability token must not be exchangeable")
	assert.Empty(t, ts.AccessToken)
}

// TestExchangeSubjectToken_RejectsHostAudienceToken pins SEC-1/DI-1: a
// host-audience token (a browser session, or a token downscoped without the
// entitlements scope) is not a FAT and must not be exchanged (re-inflated).
func TestExchangeSubjectToken_RejectsHostAudienceToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	e := newTexHardeningExchanger(t, &cs, "kid-1", "https://host.example", "https://host.example", nil)

	session := rawJWT(t, &cs, "kid-1", jwt.MapClaims{
		"sub": "alice",
		"aud": []string{"https://host.example"}, // the host audience, not a function
		"iss": "https://host.example",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	ts, err := e.ExchangeSubjectToken(session, "https://fn-b.ns.svc.cluster.local")
	require.Error(t, err, "a host-audience session token is not a FAT and must not be exchangeable")
	assert.Empty(t, ts.AccessToken)
}

// TestExchangeSubjectToken_RejectsAudiencelessAndMultiAudTokens pins RR-3: the
// FAT gate must be POSITIVE (exactly one, non-host audience) and fail closed, so
// a token with no `aud` (or multiple) cannot slip past a "contains host audience"
// check into full re-resolution.
func TestExchangeSubjectToken_RejectsAudiencelessAndMultiAudTokens(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	e := newTexHardeningExchanger(t, &cs, "kid-1", "https://host.example", "https://host.example", nil)

	t.Run("no audience", func(t *testing.T) {
		noAud := rawJWT(t, &cs, "kid-1", jwt.MapClaims{
			"sub": "alice",
			"iss": "https://host.example",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		ts, err := e.ExchangeSubjectToken(noAud, "https://fn-b.ns.svc.cluster.local")
		require.Error(t, err, "an audience-less token is not a FAT and must not be exchangeable")
		assert.Empty(t, ts.AccessToken)
	})

	t.Run("multiple audiences", func(t *testing.T) {
		multiAud := rawJWT(t, &cs, "kid-1", jwt.MapClaims{
			"sub": "alice",
			"aud": []string{"https://fn-a.ns.svc.cluster.local", "https://host.example"},
			"iss": "https://host.example",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		ts, err := e.ExchangeSubjectToken(multiAud, "https://fn-b.ns.svc.cluster.local")
		require.Error(t, err, "a multi-audience token is not a single-function FAT")
		assert.Empty(t, ts.AccessToken)
	})
}

// TestExchangeSubjectToken_IncludesBackendAndMapperGrants pins M1 (DI-2): the
// exchanged token must carry the same backend-Lookup / ClaimMappings grants a
// normal FAT mint would, not just role-binding entitlements.
func TestExchangeSubjectToken_IncludesBackendAndMapperGrants(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	// Host mapper folds the backend vs_entitlements into entitlements, as a real
	// deployment's spec.auth.claimMappings does.
	mapper, err := dmapper.NewMapper([]dmapper.MappingRule{{
		SourceExpression: "(has(self.entitlements) ? self.entitlements : []) + " +
			"(has(self.vs_entitlements) ? self.vs_entitlements : [])",
		TargetPropPath: "entitlements",
	}})
	require.NoError(t, err)

	e := newTexHardeningExchanger(t, &cs, "kid-1", "https://host.example", "https://host.example", mapper)

	// A genuine FAT: function audience, host-signed.
	fatSigner, err := sign.NewSigner("https://fn-a.ns.svc.cluster.local", time.Hour, "https://host.example", &cs, "kid-1", nil)
	require.NoError(t, err)
	fat, err := fatSigner.Sign(jwt.MapClaims{"sub": "alice"})
	require.NoError(t, err)

	ts, err := e.ExchangeSubjectToken(fat, "https://fn-b.ns.svc.cluster.local")
	require.NoError(t, err)

	claims := parseClaims(t, ts.AccessToken, &cs)
	assert.Contains(t, claims["entitlements"], "functions:/v1/internal:read", "role entitlement must be present")
	assert.Contains(t, claims["entitlements"], "vector_stores:vs1:read", "backend/mapper grant must be folded in (M1)")
}

// TestMergeBackendClaims_SkipsActReservedClaim pins L1 (SEC-2): `act` is the
// delegation-actor claim the mint sets authoritatively (token-exchange). It must
// be in reservedMintClaims so a data-driven backend Lookup response (or a
// ClaimMappings rule) can never stamp an `act` actor onto a token.
func TestMergeBackendClaims_SkipsActReservedClaim(t *testing.T) {
	sc := jwt.MapClaims{"sub": "alice"}
	backend := jwt.MapClaims{
		"act":             map[string]any{"sub": "spoofed-actor"},
		"vs_entitlements": []string{"vector_stores:vs1:read"},
	}
	mergeBackendClaims(sc, backend)

	if _, ok := sc["act"]; ok {
		t.Fatalf("mergeBackendClaims must not let a backend/mapper claim set the reserved 'act' actor claim")
	}
	if _, ok := sc["vs_entitlements"]; !ok {
		t.Fatalf("mergeBackendClaims must still merge non-reserved backend claims")
	}
}

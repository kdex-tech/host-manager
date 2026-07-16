/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// testAuthChecker mirrors HostHandler.authChecker so a test can inject a custom
// checker (e.g. a recording one) into apitokenBridgeFixture.
type testAuthChecker interface {
	CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error)
	CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error)
	BindRequirements(entitlements.ParsedRequirements, entitlements.Binding) (entitlements.ParsedRequirements, error)
	GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements
	ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements
	VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error)
}

// recordingAuthChecker captures ac["entitlements"] at gate time — the SAME set
// the mint_token `held` read consumes — so a test can assert the proxy enriched
// the authContext BEFORE it was read. The gate stays permissive.
type recordingAuthChecker struct {
	mockAuthChecker
	seen []string
}

func (c *recordingAuthChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	if ac, ok := auth.GetAuthContext(ctx); ok {
		c.seen = stringSliceFromClaim(ac["entitlements"])
	}
	return c.mockAuthChecker.GetParsedEntitlements(ctx)
}

// enrichmentClaimMapping is a host claimMapping rule that folds an arbitrary
// backend-supplied source claim (extra_grants) into entitlements. The claim name
// is deliberately generic — no claim is special-cased in code; ClaimMappings are
// the generic enrichment mechanism.
func enrichmentClaimMapping() []dmapper.MappingRule {
	return []dmapper.MappingRule{
		{
			Required:         false,
			SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.extra_grants) ? self.extra_grants : [])`,
			TargetPropPath:   "entitlements",
		},
	}
}

// TestProxy_PATBridge_EnrichesFATFromResolvedClaim pins kdex-tech/host-manager#138:
// the PAT/OAuth token bridge resolves the subject's data-driven backend claims
// FRESH at request time and surfaces them onto the authContext, so the host
// ClaimMappings fold them into the FAT's entitlements. Without this, an
// OAuth-DCR / dev-API-key caller can't reach resources granted by such a claim.
func TestProxy_PATBridge_EnrichesFATFromResolvedClaim(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	// NB: the enrichment rule lives on the HOST (fixture's authConfig.ClaimMappings),
	// NOT the function — matching production. The FAT signer applies the host rule.
	idp := stubInternalIdentityProvider{
		roles:    []string{"api-role"},
		ents:     []string{"functions:read"},
		resolved: jwt.MapClaims{"extra_grants": []any{"resource:r1:all"}},
	}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	serialized := jwtClaimsToString(t, claims)
	assert.Contains(t, serialized, "resource:r1:all",
		"FAT must carry the freshly-resolved grant via ClaimMappings (#138)")
	assert.Contains(t, serialized, "functions:read",
		"FAT must still carry the subject's role entitlements")
}

// TestProxy_PATBridge_DoesNotReinflateAttenuatedToken pins the mint_token
// constraint: a request already authenticated — e.g. a downscoped mint_token
// capability JWT, which WithAuthentication validates as a host-JWT and whose
// attenuated entitlements populate the authContext — skips the PAT bridge
// entirely. Its entitlements must NEVER be re-resolved or augmented with the
// subject's broader backend grants, or attenuation is silently defeated.
func TestProxy_PATBridge_DoesNotReinflateAttenuatedToken(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{
		roles:    []string{"api-role"},
		ents:     []string{"functions:read"},
		resolved: jwt.MapClaims{"extra_grants": []any{"resource:r1:all"}}, // broad
	}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	// Already authenticated with an EXPLICIT attenuated entitlement set and no
	// source claim — the bridge (and its fresh resolve) must not run, and the
	// enrichment is a no-op (no source claim to fold).
	attenuatedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "api-bob",
		"entitlements": []any{"resource:r1:read"},
	})
	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil).WithContext(attenuatedCtx)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	serialized := jwtClaimsToString(t, claims)
	assert.Contains(t, serialized, "resource:r1:read",
		"the attenuated grant must survive unchanged")
	assert.NotContains(t, serialized, "resource:r1:all",
		"an already-authenticated token must NOT be re-inflated — enrichment finds no source claim")
}

// TestProxy_PATBridge_EnrichmentAccumulatesHostAndFunctionMappings pins
// kdex-tech/host-manager#142: the proxy enriches the authContext with the SAME
// host + fn.Spec.ClaimMappings mapper the FAT uses, BEFORE the identity gate and
// the mint_token `held` read it. BOTH the host mapping and the function mapping
// contribute to entitlements (dmapper >= v0.1.2 chains rules, so additive rules
// on the same target accumulate instead of last-wins), and `held` equals the
// FAT's entitlements. Had the enrichment used host-only ClaimMappings, the
// function grant would be absent from `held` (present only in the FAT).
func TestProxy_PATBridge_EnrichmentAccumulatesHostAndFunctionMappings(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	// A FUNCTION-specific claimMapping folding a DIFFERENT source claim than the
	// host rule; both must contribute to entitlements at the enrichment point.
	fn.Spec.ClaimMappings = []dmapper.MappingRule{{
		SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.fn_grants) ? self.fn_grants : [])`,
		TargetPropPath:   "entitlements",
	}}
	idp := stubInternalIdentityProvider{
		roles: []string{"api-role"},
		ents:  []string{"functions:read"},
		resolved: jwt.MapClaims{
			"extra_grants": []any{"resource:host-mapped:all"}, // folded by the HOST rule
			"fn_grants":    []any{"resource:fn-mapped:all"},   // folded by the FUNCTION rule
		},
	}
	rec := &recordingAuthChecker{}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp, rec)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// `held` (the enriched authContext the gate/mint_token read) accumulates BOTH
	// the host mapping and the function mapping — the enrichment uses host+fn and
	// the mapper chains additive rules.
	assert.Contains(t, rec.seen, "resource:host-mapped:all",
		"the HOST claimMapping must contribute to held (#142)")
	assert.Contains(t, rec.seen, "resource:fn-mapped:all",
		"the FUNCTION claimMapping must ALSO contribute to held — host+fn, not host-only (#142)")
	assert.Contains(t, rec.seen, "functions:read", "the subject's role entitlements remain")

	// `held` equals the FAT's entitlements — same combined mapper on both paths.
	fatEnts := stringSliceFromClaim(decodeFAT(t, *fatHeader)["entitlements"])
	assert.ElementsMatch(t, fatEnts, rec.seen,
		"held (enriched authContext) must equal the FAT entitlements")
}

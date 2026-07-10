/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vsEntitlementsClaimMapping is the real host's claimMapping rule that merges a
// backend-supplied vs_entitlements claim into entitlements at FAT-mint time.
func vsEntitlementsClaimMapping() []dmapper.MappingRule {
	return []dmapper.MappingRule{
		{
			Required:         false,
			SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.vs_entitlements) ? self.vs_entitlements : [])`,
			TargetPropPath:   "entitlements",
		},
	}
}

// TestProxy_PATBridge_FreshResolvesVSEntitlements pins kdex-tech/host-manager#138:
// the PAT/OAuth token bridge resolves the subject's data-driven backend grants
// (vs_entitlements) FRESH at request time and surfaces them into the authContext,
// so the function's ClaimMappings merge them into the FAT. Without this, MCP
// (OAuth DCR) and dev-API-key callers can't reach their own per-vector-store
// resources.
func TestProxy_PATBridge_FreshResolvesVSEntitlements(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	fn.Spec.ClaimMappings = vsEntitlementsClaimMapping()
	idp := stubInternalIdentityProvider{
		roles:    []string{"api-role"},
		ents:     []string{"functions:read"},
		resolved: jwt.MapClaims{"vs_entitlements": []any{"vector_stores:vs_bob:all"}},
	}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	serialized := jwtClaimsToString(t, claims)
	assert.Contains(t, serialized, "vector_stores:vs_bob:all",
		"FAT must carry the freshly-resolved per-VS grant via ClaimMappings (#138)")
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
	fn.Spec.ClaimMappings = vsEntitlementsClaimMapping()
	idp := stubInternalIdentityProvider{
		roles:    []string{"api-role"},
		ents:     []string{"functions:read"},
		resolved: jwt.MapClaims{"vs_entitlements": []any{"vector_stores:vs_bob:all"}}, // broad
	}
	handler, tm, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	// Already authenticated with an EXPLICIT attenuated entitlement set and no
	// vs_entitlements — the bridge (and its fresh resolve) must not run.
	attenuatedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "api-bob",
		"entitlements": []any{"vector_stores:vs_bob:read"},
	})
	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "s", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/v1/api", nil).WithContext(attenuatedCtx)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	claims := decodeFAT(t, *fatHeader)
	serialized := jwtClaimsToString(t, claims)
	assert.Contains(t, serialized, "vector_stores:vs_bob:read",
		"the attenuated grant must survive unchanged")
	assert.NotContains(t, serialized, "vector_stores:vs_bob:all",
		"bridge must be skipped for an already-authenticated token — the broad grant must NOT re-inflate a downscoped mint_token")
}

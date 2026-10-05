package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestProxy_FATCarriesHostExtensionGrant pins that an extension's rule, composed
// after the host's (EffectiveAuth), reaches the FAT alongside the role grants.
func TestProxy_FATCarriesHostExtensionGrant(t *testing.T) {
	spec := kdexv1alpha1.KDexInternalHostSpec{
		KDexHostSpec: kdexv1alpha1.KDexHostSpec{Auth: &kdexv1alpha1.Auth{}},
		Extensions: []kdexv1alpha1.InternalHostExtension{{Name: "x", ClaimMappings: []dmapper.MappingRule{{
			SourceExpression: "has(self.extra_grants) ? self.extra_grants : []", TargetPropPath: "entitlements",
		}}}},
	}
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"},
		resolved: jwt.MapClaims{"extra_grants": []any{"resource:r1:all"}}}
	handler, tm, fatHeader, _ := apitokenBridgeFixtureWith(t, fn, idp, spec.EffectiveAuth().ClaimMappings)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	serialized := jwtClaimsToString(t, decodeFAT(t, *fatHeader))
	assert.Contains(t, serialized, "resource:r1:all", "the extension rule reaches the FAT")
	assert.Contains(t, serialized, "functions:read", "without restating, the role grants stay")
}

// TestProxy_FATProjectedWithNoMappings pins that a host with no claimMappings
// and no extensions still mints a FAT (rather than forwarding the raw session
// token) — the knowdrive-site prod outage concern, so removing the last
// extension can never bring it back.
func TestProxy_FATProjectedWithNoMappings(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, tm, fatHeader, _ := apitokenBridgeFixtureWith(t, fn, idp, nil)

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotEmpty(t, *fatHeader, "a FAT must be minted even with zero mappings")
	claims := decodeFAT(t, *fatHeader)
	assert.Equal(t, "api-bob", claims["sub"])
}

package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// patEnrichIdentityProvider resolves a STATIC role grant plus a data-driven
// claim, mirroring the shape a real deployment has: KDexRoleBindings supply
// `vector_stores:vs_static:read`, while the per-login Lookup supplies the
// subject's actual per-store grants under its own custom claim, which the
// host's ClaimMappings then fold into `entitlements`.
type patEnrichIdentityProvider struct{}

func (patEnrichIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}

func (patEnrichIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return []string{"reader"}, []string{"vector_stores:vs_static:read"}, nil
}

// ResolveClaims is the optional password-less subject->backend-claims interface
// Exchanger.ResolveSubjectClaims type-asserts.
func (patEnrichIdentityProvider) ResolveClaims(string) jwt.MapClaims {
	return jwt.MapClaims{"vs_entitlements": []string{"vector_stores:vs_target:write"}}
}

// TestHostPAT_EntitlementsAreClaimMappingEnriched pins kdex-tech/host-manager#192.
//
// #175 made a host-audience PAT an identity, resolving the subject's STATIC
// KDexRoleBinding entitlements onto the context. But hostPATIdentity merges
// ResolveSubjectClaims under their OWN keys -- so a data-driven claim like
// `vs_entitlements` sits there unfolded, and the host's ClaimMappings, which
// are the only thing that folds it into `entitlements`, were applied at exactly
// one place in the tree: the function proxy (proxy.go).
//
// Every non-proxied reader of the caller's entitlements therefore saw a
// DIFFERENT, smaller set than the proxy gate enforced against -- /-/check
// (which reports what the caller holds), the page security gate, and the
// navigation filter. The reported symptom was POST /-/check answering "you hold
// neither read nor write on this store" for a credential that, seconds earlier
// and against the same store, had been allowed both a read and a write by the
// proxy gate.
//
// EnrichAuthContext's own contract states the rule this restores: callers MUST
// pass the same mapper the token signer uses for that context -- host
// ClaimMappings for a session identity.
func TestHostPAT_EntitlementsAreClaimMappingEnriched(t *testing.T) {
	cm, err := cache.NewCacheManager("", "pat-enrich-test", nil)
	require.NoError(t, err)

	tm, err := apitoken.NewTokenManager(
		"test-issuer",
		apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}),
	)
	require.NoError(t, err)

	rules := []dmapper.MappingRule{{
		Required: false,
		SourceExpression: "(has(self.entitlements) ? self.entitlements : []) + " +
			"(has(self.vs_entitlements) ? self.vs_entitlements : [])",
		TargetPropPath: "entitlements",
	}}
	mapper, err := dmapper.NewMapper(rules)
	require.NoError(t, err)

	cfg := Config{
		Issuer:        "test-issuer",
		Audience:      patHostAudience,
		CookieName:    "auth_token",
		TokenManager:  tm,
		ClaimMappings: rules,
		ClaimMapper:   mapper,
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, patEnrichIdentityProvider{})
	require.NoError(t, err)

	var seen AuthContext
	observed := &seen
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ac, ok := GetAuthContext(r.Context()); ok {
			*observed = ac
		}
		w.WriteHeader(http.StatusOK)
	})
	h := cfg.WithAPITokenIdentity(ex)(cfg.WithAuthentication(ex)(sink))

	pat, err := tm.MintStatelessKey(patHostAudience, "alice@example.com", "read", "", time.Hour)
	require.NoError(t, err)

	rec := doPATRequest(t, h, pat)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, *observed, "a host-audience PAT must reach the handler as an identity")

	ents, err := observed.GetEntitlements()
	require.NoError(t, err)

	assert.Contains(t, ents, "vector_stores:vs_static:read",
		"the subject's static KDexRoleBinding grants must still be present")
	assert.Contains(t, ents, "vector_stores:vs_target:write",
		"the host's ClaimMappings must have folded the data-driven per-store grant "+
			"into entitlements, or every non-proxied reader (/-/check, the page gate, "+
			"the navigation filter) evaluates a smaller set than the proxy enforces (#192)")
}

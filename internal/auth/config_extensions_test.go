package auth

import (
	"testing"
	"time"

	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// TestBuild_ComposesHostExtensions pins that host-manager builds its auth
// config from the internal host's EffectiveAuth: host claimMappings then
// extension claimMappings, anonymousEntitlements unioned, and the mapper the
// signer and EnrichAuthContext use runs the extension's rule. The source claim
// (extra_grants) is an arbitrary example.
func TestBuild_ComposesHostExtensions(t *testing.T) {
	hostRule := dmapper.MappingRule{SourceExpression: "has(self.host_grants) ? self.host_grants : []", TargetPropPath: "entitlements"}
	extRule := dmapper.MappingRule{SourceExpression: "has(self.extra_grants) ? self.extra_grants : []", TargetPropPath: "entitlements"}
	spec := v1alpha1.KDexInternalHostSpec{
		KDexHostSpec: v1alpha1.KDexHostSpec{Auth: &v1alpha1.Auth{
			ClaimMappings:         []dmapper.MappingRule{hostRule},
			AnonymousEntitlements: []string{"pages:/home:read"},
		}},
		Extensions: []v1alpha1.InternalHostExtension{{
			Name: "eum", ClaimMappings: []dmapper.MappingRule{extRule},
			AnonymousEntitlements: []string{"pages:/home:read", "functions:/eum/public:read"},
		}},
	}

	cacheManager, _ := cache.NewCacheManager("", "ext", new(1*time.Hour))
	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithAudience("audience").WithIssuer("issuer").WithDevMode(true).WithCacheManager(cacheManager).
		Build(spec.EffectiveAuth())
	require.NoError(t, err)

	assert.Equal(t, []dmapper.MappingRule{hostRule, extRule}, cfg.ClaimMappings)
	assert.Equal(t, []string{"pages:/home:read", "functions:/eum/public:read"}, cfg.AnonymousEntitlements)

	ac := AuthContext{"entitlements": []any{"static:a"}, "extra_grants": []any{"resource:r1:all"}}
	EnrichAuthContext(ac, cfg.ClaimMapper)
	assert.Equal(t, []string{"static:a", "resource:r1:all"}, claimStrings(ac["entitlements"]),
		"the extension rule accumulates onto the static grants without restating them")
}

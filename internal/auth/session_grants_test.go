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
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/require"
)

func newGenTestExchanger(t *testing.T) *Exchanger {
	t.Helper()
	cm, err := cache.NewCacheManager("", "grant-gen-test", nil)
	require.NoError(t, err)
	ex, err := NewExchanger(context.Background(), Config{}, cm, autoExtendStubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

func TestGrantGenerationRoundTrip(t *testing.T) {
	ex := newGenTestExchanger(t)
	ctx := context.Background()

	// Absent generation is the empty sentinel.
	require.Equal(t, "", ex.grantGeneration(ctx))

	ex.BumpGrantGeneration(ctx)
	first := ex.grantGeneration(ctx)
	require.NotEqual(t, "", first)

	// A nil exchanger / nil cache must be safe and return the sentinel.
	var nilEx *Exchanger
	require.Equal(t, "", nilEx.grantGeneration(ctx))
	nilEx.BumpGrantGeneration(ctx) // must not panic
}

// changingGrantProvider is a stub whose live membership answer can be changed
// between requests to model a grant/revocation. ResolveClaims models the
// backend Lookup delivering vs_entitlements.
type changingGrantProvider struct {
	roles  []string
	ents   []string
	grants []string
	err    error
}

func (p *changingGrantProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (p *changingGrantProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return p.roles, p.ents, p.err
}
func (p *changingGrantProvider) ResolveClaims(string) jwt.MapClaims {
	// Always return the key (empty when no grants) so the claim-mapping
	// expression has a present source in every state — a member with no backend
	// grants is a normal case the host mapper already tolerates.
	grants := p.grants
	if grants == nil {
		grants = []string{}
	}
	return jwt.MapClaims{"vs_entitlements": grants}
}

func newGrantTestSetup(t *testing.T) (*Config, *Exchanger, *changingGrantProvider, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)

	// The signer's mapper folds the backend vs_entitlements into entitlements,
	// matching how a session token is minted.
	mapper, err := dmapper.NewMapper([]dmapper.MappingRule{
		{SourceExpression: "self.entitlements + self.vs_entitlements", TargetPropPath: "entitlements"},
	})
	require.NoError(t, err)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", mapper)
	require.NoError(t, err)

	cfg := &Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		CookieName: "auth_token",
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Signer:     *signer,
	}
	cm, err := cache.NewCacheManager("", "grant-test", nil)
	require.NoError(t, err)
	p := &changingGrantProvider{}
	ex, err := NewExchanger(context.Background(), *cfg, cm, p)
	require.NoError(t, err)
	return cfg, ex, p, priv
}

func TestRefreshSessionGrantsSeesMembershipChanges(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	ctx := context.Background()
	ac := func() AuthContext {
		return AuthContext{
			"sub": "alice", "scope": "openid roles entitlements",
			"entitlements": []any{"vector_stores:old:read"},
		}
	}

	// Live membership says the subject has no entitlements: the frozen
	// old:read is replaced by live truth (revocation).
	a := ac()
	cfg.refreshSessionGrants(a, ex)
	require.NotContains(t, a["entitlements"], "vector_stores:old:read")

	// A grant, made visible by a generation bump (models the tenancy mutation).
	p.grants = []string{"vector_stores:joined:read"}
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:joined:read")

	// A revocation, again via a bump.
	p.grants = nil
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(a, ex)
	require.NotContains(t, a["entitlements"], "vector_stores:joined:read")

	// Resolver error → fail open: the frozen token's claims are left intact.
	p.err = context.DeadlineExceeded
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:old:read")
}

func TestRefreshSessionGrantsPreservesScopeAndCapability(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:joined:read"}

	// Capability token: never re-resolved.
	capAc := AuthContext{"sub": "alice", "scope": "entitlements", CapUsesClaim: true,
		"entitlements": []any{"limited"}}
	cfg.refreshSessionGrants(capAc, ex)
	require.Equal(t, []any{"limited"}, capAc["entitlements"])

	// Token not scoped for entitlements: the refresh must not add them.
	noScopeAc := AuthContext{"sub": "alice", "scope": "openid",
		"entitlements": []any{"old"}}
	cfg.refreshSessionGrants(noScopeAc, ex)
	require.NotContains(t, noScopeAc, "entitlements")
}

func TestRefreshSessionGrantsCoalescesWithinGeneration(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:a:read"}

	a := AuthContext{"sub": "bob", "scope": "entitlements", "entitlements": []any{}}
	cfg.refreshSessionGrants(a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:a:read")

	// Change membership WITHOUT a generation bump: the cached grant is served,
	// proving one resolve per subject per generation (fleet-safety).
	p.grants = []string{"vector_stores:b:read"}
	b := AuthContext{"sub": "bob", "scope": "entitlements", "entitlements": []any{}}
	cfg.refreshSessionGrants(b, ex)
	require.Contains(t, b["entitlements"], "vector_stores:a:read")
	require.NotContains(t, b["entitlements"], "vector_stores:b:read")
}

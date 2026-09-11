package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"sync"
	"sync/atomic"
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
	ex, err := NewExchanger(context.Background(), Config{}, cm, autoExtendStubIdentityProvider{}, nil)
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
// between requests to model a grant/revocation. ResolveClaimsWithError models the
// backend Lookup delivering vs_entitlements, and lookupErr models a backend
// Lookup outage (SEC-S3 fail-open path).
type changingGrantProvider struct {
	roles     []string
	ents      []string
	grants    []string
	err       error
	lookupErr error
}

func (p *changingGrantProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (p *changingGrantProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return p.roles, p.ents, p.err
}

// ResolveClaimsWithError is the freshness-critical path refreshSessionGrants
// takes; lookupErr models a backend Lookup being unavailable.
func (p *changingGrantProvider) ResolveClaimsWithError(string) (jwt.MapClaims, error) {
	// Always return the key (empty when no grants) so the claim-mapping
	// expression has a present source in every state — a member with no backend
	// grants is a normal case the host mapper already tolerates.
	grants := p.grants
	if grants == nil {
		grants = []string{}
	}
	return jwt.MapClaims{"vs_entitlements": grants}, p.lookupErr
}

// ResolveClaims keeps the no-error bridge shape so the PAT-path assertions still
// match; it delegates and drops the error.
func (p *changingGrantProvider) ResolveClaims(subject string) jwt.MapClaims {
	claims, _ := p.ResolveClaimsWithError(subject)
	return claims
}

// countingGrantProvider is a changingGrantProvider variant whose resolve
// methods atomically count invocations and sleep briefly, so a test can prove
// concurrent callers collapse into a single live resolve (singleflight, #203)
// rather than mutating the shared changingGrantProvider stub used elsewhere.
type countingGrantProvider struct {
	changingGrantProvider
	calls atomic.Int64
	delay time.Duration
}

func (p *countingGrantProvider) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	p.calls.Add(1)
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	return p.changingGrantProvider.FindInternalRolesAndEntitlements(subject)
}

// buildGrantTestConfig builds the shared session-signing Config used by every
// grant-refresh test, keyed off a fresh EC key pair.
func buildGrantTestConfig(t *testing.T) (*Config, *ecdsa.PrivateKey) {
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
	return cfg, priv
}

func newGrantTestSetup(t *testing.T) (*Config, *Exchanger, *changingGrantProvider, *ecdsa.PrivateKey) {
	t.Helper()
	cfg, priv := buildGrantTestConfig(t)
	cm, err := cache.NewCacheManager("", "grant-test", nil)
	require.NoError(t, err)
	p := &changingGrantProvider{}
	ex, err := NewExchanger(context.Background(), *cfg, cm, p, nil)
	require.NoError(t, err)
	return cfg, ex, p, priv
}

// newCountingGrantTestSetup is newGrantTestSetup with a countingGrantProvider,
// for tests that need to observe how many times the live resolve ran.
func newCountingGrantTestSetup(t *testing.T, delay time.Duration) (*Config, *Exchanger, *countingGrantProvider) {
	t.Helper()
	cfg, _ := buildGrantTestConfig(t)
	cm, err := cache.NewCacheManager("", "grant-coalesce-test", nil)
	require.NoError(t, err)
	p := &countingGrantProvider{delay: delay}
	ex, err := NewExchanger(context.Background(), *cfg, cm, p, nil)
	require.NoError(t, err)
	return cfg, ex, p
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
	cfg.refreshSessionGrants(context.Background(), a, ex)
	require.NotContains(t, a["entitlements"], "vector_stores:old:read")

	// A grant, made visible by a generation bump (models the tenancy mutation).
	p.grants = []string{"vector_stores:joined:read"}
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(context.Background(), a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:joined:read")

	// A revocation, again via a bump.
	p.grants = nil
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(context.Background(), a, ex)
	require.NotContains(t, a["entitlements"], "vector_stores:joined:read")

	// Resolver error → fail open: the frozen token's claims are left intact.
	p.err = context.DeadlineExceeded
	ex.BumpGrantGeneration(ctx)
	a = ac()
	cfg.refreshSessionGrants(context.Background(), a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:old:read")
}

func TestRefreshSessionGrantsPreservesScopeAndCapability(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:joined:read"}

	// Capability token: never re-resolved.
	capAc := AuthContext{"sub": "alice", "scope": "entitlements", CapUsesClaim: true,
		"entitlements": []any{"limited"}}
	cfg.refreshSessionGrants(context.Background(), capAc, ex)
	require.Equal(t, []any{"limited"}, capAc["entitlements"])

	// Token not scoped for entitlements: the refresh must not add them.
	noScopeAc := AuthContext{"sub": "alice", "scope": "openid",
		"entitlements": []any{"old"}}
	cfg.refreshSessionGrants(context.Background(), noScopeAc, ex)
	require.NotContains(t, noScopeAc, "entitlements")
}

func TestRefreshSessionGrantsCoalescesWithinGeneration(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:a:read"}

	a := AuthContext{"sub": "bob", "scope": "entitlements", "entitlements": []any{}}
	cfg.refreshSessionGrants(context.Background(), a, ex)
	require.Contains(t, a["entitlements"], "vector_stores:a:read")

	// Change membership WITHOUT a generation bump: the cached grant is served,
	// proving one resolve per subject per generation (fleet-safety).
	p.grants = []string{"vector_stores:b:read"}
	b := AuthContext{"sub": "bob", "scope": "entitlements", "entitlements": []any{}}
	cfg.refreshSessionGrants(context.Background(), b, ex)
	require.Contains(t, b["entitlements"], "vector_stores:a:read")
	require.NotContains(t, b["entitlements"], "vector_stores:b:read")
}

// TestRefreshSessionGrantsSingleflightCoalescesConcurrentMisses proves the
// #203 review fix: a burst of parallel requests for the same subject, all
// missing the cache at once (e.g. right after a generation bump), collapses
// into exactly one live resolve instead of firing one per request.
func TestRefreshSessionGrantsSingleflightCoalescesConcurrentMisses(t *testing.T) {
	cfg, ex, p := newCountingGrantTestSetup(t, 20*time.Millisecond)
	p.grants = []string{"vector_stores:a:read"}

	const n = 20
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	release := make(chan struct{})
	results := make([]AuthContext, n)

	ready.Add(n)
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			ac := AuthContext{"sub": "carol", "scope": "entitlements", "entitlements": []any{}}
			results[i] = ac
			ready.Done()
			<-release // all goroutines fire together, guaranteeing overlap in Do
			cfg.refreshSessionGrants(context.Background(), ac, ex)
		}(i)
	}
	ready.Wait()
	close(release)
	wg.Wait()

	require.Equal(t, int64(1), p.calls.Load(), "concurrent misses for one subject must coalesce to a single live resolve")
	for _, ac := range results {
		require.Contains(t, ac["entitlements"], "vector_stores:a:read")
	}
}

// TestRefreshSessionGrantsFailsOpenOnLookupOutage proves SEC-S3: when the backend
// Lookup is unavailable, the refresh fails OPEN to the frozen token rather than
// stripping the subject's membership grants (which a nil-vs-outage confusion would
// have done, fail-closed).
func TestRefreshSessionGrantsFailsOpenOnLookupOutage(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:joined:read"}
	p.lookupErr = context.DeadlineExceeded // the backend Lookup cannot answer

	ac := AuthContext{
		"sub": "erin", "scope": "openid roles entitlements",
		"entitlements": []any{"vector_stores:frozen:read"},
	}
	cfg.refreshSessionGrants(context.Background(), ac, ex)

	// Fail open: the frozen entitlements are intact, not stripped to the (empty
	// on outage) live set.
	require.Contains(t, ac["entitlements"], "vector_stores:frozen:read")
}

// backendOverrideProvider is a hostile/misconfigured provider whose backend
// Lookup response tries to rebind identity (sub) and clobber the internally
// resolved roles. It exists to prove the DI-F1/#140 guard.
type backendOverrideProvider struct {
	roles []string
	ents  []string
}

func (p *backendOverrideProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (p *backendOverrideProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return p.roles, p.ents, nil
}
func (p *backendOverrideProvider) ResolveClaimsWithError(string) (jwt.MapClaims, error) {
	return jwt.MapClaims{
		"sub":             "attacker",
		"roles":           []string{"role-backend"},
		"vs_entitlements": []string{"ent-backend"},
	}, nil
}
func (p *backendOverrideProvider) ResolveClaims(subject string) jwt.MapClaims {
	c, _ := p.ResolveClaimsWithError(subject)
	return c
}

// TestRefreshSessionGrantsBackendCannotOverrideIdentity proves DI-F1/#140: a
// backend Lookup response that includes sub/roles must NOT rebind the authoritative
// subject or override the internally-resolved roles. Its non-reserved claims (here
// vs_entitlements) still flow through the mapper — that is the feature.
func TestRefreshSessionGrantsBackendCannotOverrideIdentity(t *testing.T) {
	cfg, _ := buildGrantTestConfig(t)
	cm, err := cache.NewCacheManager("", "grant-di-f1", nil)
	require.NoError(t, err)
	p := &backendOverrideProvider{roles: []string{"role-internal"}}
	ex, err := NewExchanger(context.Background(), *cfg, cm, p, nil)
	require.NoError(t, err)

	ac := AuthContext{
		"sub": "frank", "scope": "openid roles entitlements",
		"roles": []any{}, "entitlements": []any{},
	}
	cfg.refreshSessionGrants(context.Background(), ac, ex)

	// Internally-resolved roles win; the backend's roles do not override them.
	require.Contains(t, ac["roles"], "role-internal")
	require.NotContains(t, ac["roles"], "role-backend")
	// The backend's data-driven claim still flows through the mapper.
	require.Contains(t, ac["entitlements"], "ent-backend")
}

// TestRefreshSessionGrantsHandlesNonStringScope proves DI-F3: an ac whose `scope`
// is a []any (as a decoded JWT array claim can be) is understood via GetScopes and
// the scoped claim is overlaid — not silently stripped as a bare `.(string)` assert
// would have done.
func TestRefreshSessionGrantsHandlesNonStringScope(t *testing.T) {
	cfg, ex, p, _ := newGrantTestSetup(t)
	p.grants = []string{"vector_stores:joined:read"}

	ac := AuthContext{
		"sub": "grace", "scope": []any{"openid", "entitlements"},
		"entitlements": []any{},
	}
	cfg.refreshSessionGrants(context.Background(), ac, ex)
	require.Contains(t, ac["entitlements"], "vector_stores:joined:read")
}

// TestRefreshSessionGrantsDeAliasesCoalescedSlices proves DI-F4/SEC-S6: two callers
// coalesced onto one in-memory projected map each receive their OWN slice header,
// so one caller mutating its overlaid claim cannot corrupt another's.
func TestRefreshSessionGrantsDeAliasesCoalescedSlices(t *testing.T) {
	cfg, ex, p := newCountingGrantTestSetup(t, 20*time.Millisecond)
	p.grants = []string{"vector_stores:a:read"}

	const n = 2
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	release := make(chan struct{})
	results := make([]AuthContext, n)

	ready.Add(n)
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			ac := AuthContext{"sub": "heidi", "scope": "entitlements", "entitlements": []any{}}
			results[i] = ac
			ready.Done()
			<-release
			cfg.refreshSessionGrants(context.Background(), ac, ex)
		}(i)
	}
	ready.Wait()
	close(release)
	wg.Wait()

	// The two callers coalesced onto a single live resolve (shared projected map).
	require.Equal(t, int64(1), p.calls.Load())
	for _, ac := range results {
		require.Contains(t, ac["entitlements"], "vector_stores:a:read")
	}
	// Their overlaid entitlements must NOT share a backing array.
	pa := reflect.ValueOf(results[0]["entitlements"]).Pointer()
	pb := reflect.ValueOf(results[1]["entitlements"]).Pointer()
	require.NotEqual(t, pa, pb, "coalesced callers must each own their slice header")
}

// TestBumpGrantGenerationProducesUniqueTokens proves DI-F2/SEC-S4: successive bumps
// yield distinct, non-empty generation tokens (a per-process nonce + monotonic
// counter, not a wall-clock stamp), and the no-nonce fallback still advances.
func TestBumpGrantGenerationProducesUniqueTokens(t *testing.T) {
	ex := newGenTestExchanger(t)
	ctx := context.Background()

	ex.BumpGrantGeneration(ctx)
	g1 := ex.grantGeneration(ctx)
	ex.BumpGrantGeneration(ctx)
	g2 := ex.grantGeneration(ctx)
	require.NotEmpty(t, g1)
	require.NotEmpty(t, g2)
	require.NotEqual(t, g1, g2)

	// Fallback branch: an Exchanger with a cache but no nonce (not built by
	// NewExchanger) still produces non-empty, advancing tokens.
	cm, err := cache.NewCacheManager("", "gen-fallback", nil)
	require.NoError(t, err)
	bare := &Exchanger{grantGenCache: newUncycledCache(cm, "session-grant-gen", grantGenTTL)}
	require.Equal(t, "", bare.grantGenNonce)
	bare.BumpGrantGeneration(ctx)
	f1 := bare.grantGeneration(ctx)
	bare.BumpGrantGeneration(ctx)
	f2 := bare.grantGeneration(ctx)
	require.NotEmpty(t, f1)
	require.NotEqual(t, f1, f2)
}

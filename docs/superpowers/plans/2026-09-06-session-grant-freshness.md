# Session-Grant Freshness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a browser (cookie) session reflect a membership/role grant or revocation on its **next** request, without a re-login, kept fleet-safe by a shared grant cache invalidated by a coarse generation epoch.

**Architecture:** On a cookie request, after the JWT validates, `refreshSessionGrants` re-resolves the subject's roles/entitlements (in-memory) plus a fresh backend Lookup, re-runs `claimMappings` via `Signer.Project`, and overlays the result — but only for claims the token was scoped for, and never for capability tokens. Results are memoized in a shared (Valkey) grant cache keyed by `generation|subject`; a proxy `ModifyResponse` hook bumps the shared generation on any 2xx write to a KDexFunction annotated as a grants source, so the next request of every subject re-resolves. Resolve failures fail open to the frozen token.

**Tech Stack:** Go, `internal/auth` (middleware + exchanger), `internal/host` (reverse proxy), `internal/cache` (Valkey/in-memory shared cache), `golang-jwt/jwt/v5`, kdex-crds `KDexFunction`.

**Spec:** `docs/superpowers/specs/2026-09-06-session-grant-freshness-design.md`

## Global Constraints

- **Capability/PAT tokens are never re-resolved.** `authContext[CapUsesClaim]` (`"kdx_cap"`) present ⇒ `refreshSessionGrants` is a no-op. Attenuated tokens are never re-inflated.
- **The refresh only narrows.** A claim is overlaid only if the token's `scope` already carried it; identity, `scope`, `exp` are never modified.
- **Fail open.** A resolve failure never 503s and never strips grants; it leaves the frozen token's claims in place.
- **Shared state.** The grant cache and the generation key live in the Valkey-backed shared cache (`Uncycled: true`) so invalidation is fleet-wide.
- **host-manager only.** No kdex-crds schema change. The grants-source signal is a `KDexFunction` annotation, `kdex.dev/invalidates-grants-on-write: "true"`.
- Go **1.26.0**. Run `make test` in the module (not just `go build`).

---

### Task 1: Exchanger grant cache + generation primitives

**Files:**
- Modify: `internal/auth/exchange.go` (struct `Exchanger` ~40-68; `NewExchanger` ~175-203; add consts near line 73)
- Create: `internal/auth/session_grants.go`
- Test: `internal/auth/session_grants_test.go`

**Interfaces:**
- Consumes: `cache.CacheManager.GetCache`, `cache.CacheOptions`, `cache.Cache` (`internal/cache/cache.go`); `Exchanger.sp` (`InternalIdentityProvider`).
- Produces:
  - `Exchanger` gains fields `grantCache cache.Cache`, `grantGenCache cache.Cache`.
  - `func (e *Exchanger) grantGeneration(ctx context.Context) string`
  - `func (e *Exchanger) BumpGrantGeneration(ctx context.Context)`
  - `func (e *Exchanger) resolveClaimsDirect(subject string) jwt.MapClaims`
  - consts `sessionGrantTTL = 60 * time.Second`, `grantGenTTL = 24 * time.Hour`, `grantGenKey = "current"`.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/session_grants_test.go`:

```go
package auth

import (
	"context"
	"testing"

	"github.com/kdex-tech/host-manager/internal/cache"
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestGrantGenerationRoundTrip -v`
Expected: FAIL to compile — `grantGeneration`, `BumpGrantGeneration` undefined.

- [ ] **Step 3: Add the struct fields + wiring**

In `internal/auth/exchange.go`, add to the `Exchanger` struct (after `subjectResolveCache`):

```go
	// grantCache memoizes projected browser-session grants (#203), keyed by
	// "<generation>|<subject>". grantGenCache holds the current generation
	// token; a membership mutation bumps it so stale-generation entries are
	// naturally missed. Both are shared (Valkey) so invalidation is fleet-wide.
	grantCache    cache.Cache
	grantGenCache cache.Cache
```

Add consts near `subjectResolveCacheTTL` (line 73):

```go
const (
	sessionGrantTTL = 60 * time.Second
	grantGenTTL     = 24 * time.Hour
	grantGenKey     = "current"
)
```

In `NewExchanger`, inside the `if cacheManager != nil {` block (after the `subject-resolve` cache is created), add:

```go
		// Browser-session grant cache + its generation key. See #203.
		sgTTL := sessionGrantTTL
		ex.grantCache = cacheManager.GetCache("session-grants", cache.CacheOptions{
			TTL:      &sgTTL,
			Uncycled: true,
		})
		ggTTL := grantGenTTL
		ex.grantGenCache = cacheManager.GetCache("session-grant-gen", cache.CacheOptions{
			TTL:      &ggTTL,
			Uncycled: true,
		})
```

- [ ] **Step 4: Add the generation + direct-resolve helpers**

Create `internal/auth/session_grants.go`:

```go
package auth

import (
	"context"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// grantGeneration returns the current shared grant-generation token, or "" when
// no membership mutation has been observed yet (the stable sentinel).
func (e *Exchanger) grantGeneration(ctx context.Context) string {
	if e == nil || e.grantGenCache == nil {
		return ""
	}
	if raw, found, _, err := e.grantGenCache.Get(ctx, grantGenKey); err == nil && found {
		return raw
	}
	return ""
}

// BumpGrantGeneration advances the shared grant generation so every cached
// browser-session grant becomes stale and is re-resolved on the next request.
// Called from the proxy when a membership mutation succeeds (#203).
func (e *Exchanger) BumpGrantGeneration(ctx context.Context) {
	if e == nil || e.grantGenCache == nil {
		return
	}
	gen := strconv.FormatInt(time.Now().UnixNano(), 10)
	_ = e.grantGenCache.Set(ctx, grantGenKey, gen)
}

// resolveClaimsDirect resolves a subject's backend Lookup claims fresh, bypassing
// the 60s subjectResolveCache. The grant cache is the coalescing layer for the
// cookie path, so this must reach a live Lookup (else a revocation would lag).
func (e *Exchanger) resolveClaimsDirect(subject string) jwt.MapClaims {
	if e == nil || e.sp == nil || subject == "" {
		return nil
	}
	resolver, ok := e.sp.(interface {
		ResolveClaims(string) jwt.MapClaims
	})
	if !ok {
		return nil
	}
	return resolver.ResolveClaims(subject)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/auth/ -run TestGrantGenerationRoundTrip -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/auth/exchange.go internal/auth/session_grants.go internal/auth/session_grants_test.go
git commit -m "feat(auth): shared grant cache + generation primitives (#203)"
```

---

### Task 2: `refreshSessionGrants` + scope-gated overlay

**Files:**
- Modify: `internal/auth/session_grants.go`
- Test: `internal/auth/session_grants_test.go`

**Interfaces:**
- Consumes: `Exchanger.grantGeneration`, `Exchanger.grantCache`, `Exchanger.ResolveInternalRolesAndEntitlements` (exchange.go:296), `Exchanger.resolveClaimsDirect`, `Config.Signer.Project` (sign.go:142, returns `(jwt.MapClaims, error)`), `AuthContext.GetSubject` (context.go:73), `CapUsesClaim` (middleware.go:22).
- Produces:
  - `func (c *Config) refreshSessionGrants(ac AuthContext, e *Exchanger)`
  - `func overlayScopedClaims(ac AuthContext, projected jwt.MapClaims, scope string)`

- [ ] **Step 1: Write the failing tests**

Append to `internal/auth/session_grants_test.go` (add imports `crypto`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `time`, `github.com/golang-jwt/jwt/v5`, `github.com/kdex-tech/host-manager/internal/keys`, `github.com/kdex-tech/host-manager/internal/sign`, `github.com/kdex-tech/dmapper`):

```go
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/ -run TestRefreshSessionGrants -v`
Expected: FAIL to compile — `refreshSessionGrants` undefined.

- [ ] **Step 3: Implement `refreshSessionGrants` + `overlayScopedClaims`**

Append to `internal/auth/session_grants.go` (add imports `encoding/json`, `slices`, `strings`):

```go
// refreshSessionGrants re-resolves a browser session's roles/entitlements against
// live membership and overlays them onto ac, so a grant or revocation takes
// effect on the next request without a re-login (#203). Capability tokens are
// skipped; resolve failures fail open to the frozen token; only claims the token
// was scoped for are overlaid. Results are coalesced in the shared grant cache,
// keyed by generation so a membership mutation (which bumps the generation)
// forces a fresh resolve.
func (c *Config) refreshSessionGrants(ac AuthContext, e *Exchanger) {
	if ac == nil || e == nil {
		return
	}
	if marker, _ := ac[CapUsesClaim].(bool); marker {
		return // never re-inflate an attenuated capability token
	}
	subject, err := ac.GetSubject()
	if err != nil || subject == "" {
		return
	}
	scope, _ := ac["scope"].(string)

	ctx := context.Background()
	gen := e.grantGeneration(ctx)
	key := gen + "|" + subject

	// Fast path: current-generation cache hit.
	if e.grantCache != nil {
		if raw, found, _, gerr := e.grantCache.Get(ctx, key); gerr == nil && found && raw != "" {
			var projected jwt.MapClaims
			if json.Unmarshal([]byte(raw), &projected) == nil {
				overlayScopedClaims(ac, projected, scope)
				return
			}
		}
	}

	// Miss / stale generation: resolve fresh against live membership.
	roles, ents, rerr := e.ResolveInternalRolesAndEntitlements(subject)
	if rerr != nil {
		return // fail open — leave ac as the frozen token carried it
	}
	backend := e.resolveClaimsDirect(subject)

	// Mirror the mint-time signing context (subjectSigningContext): roles and
	// entitlements are always present (empty when none) so the claim-mapping runs
	// the same way it does at mint. Backend Lookup claims are merged in. Note:
	// like the Dev-validated reference, this re-derives from internal roles +
	// backend Lookup and does NOT re-fetch idp-frozen claims (out of scope —
	// knowdrive derives entitlements from internal roles + backend membership).
	if roles == nil {
		roles = []string{}
	}
	if ents == nil {
		ents = []string{}
	}
	signingContext := jwt.MapClaims{"sub": subject, "roles": roles, "entitlements": ents}
	for k, v := range backend {
		signingContext[k] = v
	}

	projected, perr := c.Signer.Project(signingContext)
	if perr != nil {
		return // fail open
	}
	if e.grantCache != nil {
		if payload, merr := json.Marshal(projected); merr == nil {
			_ = e.grantCache.Set(ctx, key, string(payload))
		}
	}
	overlayScopedClaims(ac, projected, scope)
}

// overlayScopedClaims replaces roles/entitlements on ac with the freshly
// projected values, but only for a claim the token's scope already carried, so
// the refresh can only narrow to what the token was scoped for, never widen it.
func overlayScopedClaims(ac AuthContext, projected jwt.MapClaims, scope string) {
	scopes := strings.Fields(scope)
	for _, claim := range []string{"roles", "entitlements"} {
		delete(ac, claim)
		if slices.Contains(scopes, claim) {
			if v, ok := projected[claim]; ok {
				ac[claim] = v
			}
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run TestRefreshSessionGrants -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/session_grants.go internal/auth/session_grants_test.go
git commit -m "feat(auth): refreshSessionGrants with scope-gated fail-open overlay (#203)"
```

---

### Task 3: Wire the refresh into the cookie path

**Files:**
- Modify: `internal/auth/middleware.go` (insertion point ~line 505, after the auto-extend block, before the `if c.MintCapCache != nil` block at ~511)
- Test: `internal/auth/middleware_session_grants_test.go`

**Interfaces:**
- Consumes: `Config.refreshSessionGrants` (Task 2), `COOKIE` const (types.go:4), the `exchanger` param + `authContext` var + `authSource` var in `WithAuthentication`.
- Produces: no new symbols; behavior change only.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/middleware_session_grants_test.go`:

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func mintCookieToken(t *testing.T, cfg *Config, priv any, ents []string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "alice", "iss": cfg.Issuer, "aud": cfg.Audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "openid roles entitlements", "entitlements": ents,
	}).SignedString(priv)
	require.NoError(t, err)
	return tok
}

func TestCookieSessionReflectsMembershipBump(t *testing.T) {
	cfg, ex, p, priv := newGrantTestSetup(t)
	token := mintCookieToken(t, cfg, priv, []string{"vector_stores:old:read"})

	var seen AuthContext
	handler := cfg.WithAuthentication(ex)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = GetAuthContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	request := func() int {
		r := httptest.NewRequest("GET", "/api/v1/files", nil)
		r.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: token})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}

	// Grant, made visible by a generation bump.
	p.grants = []string{"vector_stores:joined:read"}
	ex.BumpGrantGeneration(context.Background())
	require.Equal(t, http.StatusNoContent, request())
	require.Contains(t, seen["entitlements"], "vector_stores:joined:read")

	// Revocation, via a bump.
	p.grants = nil
	ex.BumpGrantGeneration(context.Background())
	require.Equal(t, http.StatusNoContent, request())
	require.NotContains(t, seen["entitlements"], "vector_stores:joined:read")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestCookieSessionReflectsMembershipBump -v`
Expected: FAIL — `seen["entitlements"]` still carries the frozen `old:read` (the refresh is not wired in yet), so the `Contains` assertion fails.

- [ ] **Step 3: Insert the refresh call**

In `internal/auth/middleware.go`, immediately after the auto-extend `if authSource == COOKIE && c.AutoExtendSession ... { ... }` block closes (~line 505) and before the `if c.MintCapCache != nil {` block:

```go
			// Refresh browser-session grants against live membership so a grant
			// or revocation takes effect on the next request without a re-login
			// (#203). Fails open to the frozen token; capability tokens skipped.
			if authSource == COOKIE && exchanger != nil {
				c.refreshSessionGrants(authContext, exchanger)
			}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run TestCookieSessionReflectsMembershipBump -v`
Expected: PASS.

- [ ] **Step 5: Run the full auth package to catch regressions**

Run: `go test ./internal/auth/...`
Expected: PASS (in particular `middleware_capuses_test.go`, which calls `WithAuthentication(nil)` — the `exchanger != nil` guard keeps it a no-op).

- [ ] **Step 6: Commit**

```bash
git add internal/auth/middleware.go internal/auth/middleware_session_grants_test.go
git commit -m "feat(auth): refresh cookie-session grants in WithAuthentication (#203)"
```

---

### Task 4: Proxy invalidation hook

**Files:**
- Modify: `internal/host/proxy.go` (add the annotation const + `shouldInvalidateGrants` helper; call it in the `ModifyResponse` closure ~276-312)
- Test: `internal/host/proxy_grant_invalidation_test.go`

**Interfaces:**
- Consumes: `hh.authExchanger` (`*auth.Exchanger`, field on `HostHandler`), `Exchanger.BumpGrantGeneration` (Task 1), `fn *kdexv1alpha1.KDexFunction` (captured in `reverseProxyHandler`), `resp.Request.Method`, `resp.StatusCode`.
- Produces:
  - const `AnnotationInvalidatesGrantsOnWrite = "kdex.dev/invalidates-grants-on-write"`
  - `func shouldInvalidateGrants(fn *kdexv1alpha1.KDexFunction, method string, status int) bool`

- [ ] **Step 1: Write the failing test**

Create `internal/host/proxy_grant_invalidation_test.go`:

```go
package host

import (
	"net/http"
	"testing"

	kdexv1alpha1 "github.com/kdex-tech/kdex-crds/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fnWithAnnotation(v string) *kdexv1alpha1.KDexFunction {
	f := &kdexv1alpha1.KDexFunction{}
	if v != "" {
		f.ObjectMeta = metav1.ObjectMeta{Annotations: map[string]string{
			AnnotationInvalidatesGrantsOnWrite: v,
		}}
	}
	return f
}

func TestShouldInvalidateGrants(t *testing.T) {
	cases := []struct {
		name   string
		fn     *kdexv1alpha1.KDexFunction
		method string
		status int
		want   bool
	}{
		{"annotated 2xx DELETE", fnWithAnnotation("true"), http.MethodDelete, 204, true},
		{"annotated 2xx POST", fnWithAnnotation("true"), http.MethodPost, 201, true},
		{"annotated GET", fnWithAnnotation("true"), http.MethodGet, 200, false},
		{"annotated HEAD", fnWithAnnotation("true"), http.MethodHead, 200, false},
		{"annotated POST 4xx", fnWithAnnotation("true"), http.MethodPost, 403, false},
		{"annotated POST 5xx", fnWithAnnotation("true"), http.MethodPost, 500, false},
		{"not annotated POST", fnWithAnnotation(""), http.MethodPost, 201, false},
		{"annotation false", fnWithAnnotation("false"), http.MethodPost, 201, false},
		{"nil fn", nil, http.MethodPost, 201, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldInvalidateGrants(tc.fn, tc.method, tc.status); got != tc.want {
				t.Fatalf("shouldInvalidateGrants = %v, want %v", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/host/ -run TestShouldInvalidateGrants -v`
Expected: FAIL to compile — `AnnotationInvalidatesGrantsOnWrite`, `shouldInvalidateGrants` undefined.

- [ ] **Step 3: Add the const + helper**

In `internal/host/proxy.go` (near the top-level consts):

```go
// AnnotationInvalidatesGrantsOnWrite marks a KDexFunction whose successful
// writes mutate membership/role state; host-manager bumps the shared grant
// generation on such a response so browser sessions re-resolve (#203).
const AnnotationInvalidatesGrantsOnWrite = "kdex.dev/invalidates-grants-on-write"

// shouldInvalidateGrants reports whether a proxied response should bump the
// grant generation: a 2xx, state-changing method on a grants-source function.
func shouldInvalidateGrants(fn *kdexv1alpha1.KDexFunction, method string, status int) bool {
	if fn == nil || fn.Annotations[AnnotationInvalidatesGrantsOnWrite] != "true" {
		return false
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return status >= 200 && status < 300
}
```

- [ ] **Step 4: Call the helper in `ModifyResponse`**

In the `ModifyResponse` closure in `reverseProxyHandler`, just before `return nil`:

```go
			// #203: a successful membership mutation on a grants-source function
			// bumps the shared grant generation so browser sessions re-resolve
			// on their next request. Coarse: any 2xx write invalidates all
			// cached grants (membership mutations are rare).
			if hh.authExchanger != nil &&
				shouldInvalidateGrants(fn, resp.Request.Method, resp.StatusCode) {
				hh.authExchanger.BumpGrantGeneration(resp.Request.Context())
			}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/host/ -run TestShouldInvalidateGrants -v`
Expected: PASS (all rows).

- [ ] **Step 6: Commit**

```bash
git add internal/host/proxy.go internal/host/proxy_grant_invalidation_test.go
git commit -m "feat(host): bump grant generation on proxied membership mutations (#203)"
```

---

### Task 5: Module verification + enablement note

**Files:**
- Modify: `docs/superpowers/plans/2026-09-06-session-grant-freshness.md` (check off completed tasks)
- Reference only (a **knowdrive-site** change, applied by that repo): `k8s/dev/function_tenancy_service.yaml`

- [ ] **Step 1: Run the full module test + lint**

Run: `make test` (in `kdex-host-manager`)
Expected: PASS — envtest + `go test ./...` green.

Run (from the workspace root): `make lint`
Expected: format + lint clean across modules.

- [ ] **Step 2: Record the enablement step (no host-manager code)**

The feature is inert until the tenancy `KDexFunction` is annotated as a grants
source. Until then, browser sessions still gain the **≤60s** backstop TTL
freshness (a large improvement over the ~1h mint-freeze); the annotation makes it
**immediate**. In **knowdrive-site** `k8s/dev/function_tenancy_service.yaml`, add:

```yaml
metadata:
  annotations:
    kdex.dev/invalidates-grants-on-write: "true"
```

This is a knowdrive-site manifest change (that repo owns its Dev/prod rollout); it
requires **no** host-manager or kdex-crds release. The end-to-end #145/#146
acceptance sequence (`read 200 → remove 204 → read 403 → invite 201 → accept 204
→ same-cookie read 200 → viewer write 403`) is validated against the running site,
not in host-manager unit tests.

- [ ] **Step 3: Commit the plan check-offs**

```bash
git add docs/superpowers/plans/2026-09-06-session-grant-freshness.md
git commit -m "docs: mark session-grant-freshness plan complete (#203)"
```

---

## Notes for the implementer

- **Do not** route the cookie grant refresh through the existing `subjectResolveCache` (60s) — its staleness would defeat immediate revocation. The cookie path uses `resolveClaimsDirect` (fresh Lookup) with the gen-keyed `grantCache` as its coalescing layer. Leave `ResolveSubjectClaims` (the PAT/bridge path) untouched.
- **`Config.Signer` is a value** (`config.go:104`); `c.Signer.Project(...)` works because the field is addressable and `Project` has a pointer receiver.
- **`Project` drops unlisted claims** (allowlist at `sign.go:174`), so pass roles/entitlements/backend claims in the `signingContext`; the mapper folds `vs_entitlements` into `entitlements`.
- **`exchanger` and `hh.authExchanger` can be nil** in tests — both call sites guard on non-nil.
- The generation token is a `UnixNano` string; concurrent bumps are last-writer-wins, which only ever over-invalidates (safe).
- **Active-active correctness is not unit-tested** — the in-memory `CacheManager` is per-process, so a genuine two-replica test needs Valkey (integration). It follows from the shared-cache design: both replicas call `GetCache` against the same Valkey and share the key namespace, so a bump on one is seen by all.
- **idp-frozen claims are not re-fetched** (see the `refreshSessionGrants` comment). If a future host folds idp-provided entitlements into the session token, that path would need separate handling; knowdrive does not.

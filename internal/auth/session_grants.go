package auth

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"slices"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
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
//
// The token is a per-process random nonce plus a monotonic counter, NOT a
// wall-clock stamp: the value is used as an equality/cache-key token and must be
// unique across the 60s TTL window regardless of clock behaviour, so a backward
// clock step can never reproduce a still-cached generation value (DI-F2/SEC-S4).
func (e *Exchanger) BumpGrantGeneration(ctx context.Context) {
	if e == nil || e.grantGenCache == nil {
		return
	}
	gen := e.grantGenNonce + "-" + strconv.FormatUint(e.grantGenSeq.Add(1), 10)
	if e.grantGenNonce == "" {
		// An Exchanger built without NewExchanger (e.g. &Exchanger{} in a test)
		// has no nonce; fall back to a wall-clock seed so the token is still
		// non-empty and advances on every call.
		gen = strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(e.grantGenSeq.Add(1), 10)
	}
	_ = e.grantGenCache.Set(ctx, grantGenKey, gen)
}

// resolveClaimsRaw resolves a subject's backend Lookup claims live via the
// provider with no cache — the shared core of the cached ResolveSubjectClaims and
// the freshness-critical resolveSubjectClaimsDirect. A non-nil error means a
// configured Lookup was unavailable and the result cannot be trusted as complete;
// an authorization-path caller must fail open. Providers that only implement the
// no-error ResolveClaims (test stubs) never error here.
func (e *Exchanger) resolveClaimsRaw(subject string) (jwt.MapClaims, error) {
	if e == nil || e.sp == nil || subject == "" {
		return nil, nil
	}
	if resolver, ok := e.sp.(interface {
		ResolveClaimsWithError(string) (jwt.MapClaims, error)
	}); ok {
		return resolver.ResolveClaimsWithError(subject)
	}
	if resolver, ok := e.sp.(interface {
		ResolveClaims(string) jwt.MapClaims
	}); ok {
		return resolver.ResolveClaims(subject), nil
	}
	return nil, nil
}

// resolveSubjectClaimsDirect resolves backend Lookup claims fresh, bypassing the
// 60s subjectResolveCache (the grant cache is the coalescing layer for the cookie
// path, so this must reach a live Lookup or a revocation would lag). It surfaces a
// Lookup-unavailable error so refreshSessionGrants fails open on an outage (#203).
func (e *Exchanger) resolveSubjectClaimsDirect(subject string) (jwt.MapClaims, error) {
	return e.resolveClaimsRaw(subject)
}

// refreshSessionGrants re-resolves a browser session's roles/entitlements against
// live membership and overlays them onto ac, so a grant or revocation takes
// effect on the next request without a re-login (#203). Capability tokens are
// skipped; resolve failures fail open to the frozen token; only claims the token
// was scoped for are overlaid. Results are coalesced in the shared grant cache,
// keyed by generation so a membership mutation (which bumps the generation)
// forces a fresh resolve. On a cache miss the resolve itself is additionally
// coalesced in-process via a singleflight.Group keyed the same way, so a
// parallel fan-out of requests for one subject (e.g. a page load right after a
// generation bump) fires exactly one live resolve instead of one per request.
func (c *Config) refreshSessionGrants(reqCtx context.Context, ac AuthContext, e *Exchanger) {
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
	scopes, _ := ac.GetScopes()

	// Bound every shared-cache (Valkey) call so a slow shared cache can't hang
	// the whole cookie surface (PERF-F2). A Get/Set error under the timed-out ctx
	// falls through to the existing fail-open paths (a gen/Get error → resolve; a
	// resolve under the timed-out ctx → fail open to the frozen token). The
	// backend HTTP Lookup keeps its own (2s) timeout; bounding that is out of
	// scope here.
	ctx, cancel := context.WithTimeout(reqCtx, grantResolveTimeout)
	defer cancel()

	gen := e.grantGeneration(ctx)
	key := gen + "|" + subject

	// Fast path: current-generation cache hit.
	if e.grantCache != nil {
		if raw, found, _, gerr := e.grantCache.Get(ctx, key); gerr == nil && found && raw != "" {
			var projected jwt.MapClaims
			if json.Unmarshal([]byte(raw), &projected) == nil {
				overlayScopedClaims(ac, projected, scopes)
				return
			}
		}
	}

	// Miss / stale generation: resolve fresh against live membership. Coalesced
	// per "<generation>|<subject>" so a parallel fan-out of requests from one
	// subject (e.g. right after a generation bump) collapses to a single live
	// resolve; each caller still overlays onto its own ac/scope below.
	result, rerr, _ := e.grantGroup.Do(key, func() (any, error) {
		roles, ents, rerr := e.ResolveInternalRolesAndEntitlements(subject)
		if rerr != nil {
			return nil, rerr // fail open — leave ac as the frozen token carried it
		}
		backend, berr := e.resolveSubjectClaimsDirect(subject)
		if berr != nil {
			return nil, berr // fail open on a backend Lookup outage (SEC-S3)
		}

		if roles == nil {
			roles = []string{}
		}
		if ents == nil {
			ents = []string{}
		}
		// Seed the signing context from the frozen token's own claims so the
		// claim-mapping sees the same input shape it saw at mint (email, idp, and
		// any other minted claim). Then override the freshly-resolved authoritative
		// claims and merge backend Lookup claims through the same guarded helper the
		// mint path uses: mergeBackendClaims skips reservedMintClaims (incl. sub) and
		// never overwrites an existing key, so a backend Lookup response can neither
		// rebind identity (#140) nor bypass the internal role resolver, and
		// re-projection stays faithful to mint for non-membership-only mappers
		// (#203 quad DI-F1 / SEC-S1).
		signingContext := jwt.MapClaims{}
		for k, v := range ac {
			signingContext[k] = v
		}
		signingContext["sub"] = subject
		signingContext["roles"] = roles
		signingContext["entitlements"] = ents
		mergeBackendClaims(signingContext, backend)

		projected, perr := c.Signer.Project(signingContext)
		if perr != nil {
			return nil, perr // fail open
		}
		if e.grantCache != nil {
			if payload, merr := json.Marshal(projected); merr == nil {
				_ = e.grantCache.Set(ctx, key, string(payload), cache.WithTTL(jitteredGrantTTL()))
			}
		}
		return projected, nil
	})
	if rerr != nil {
		return // fail open — leave ac as the frozen token carried it
	}
	projected, ok := result.(jwt.MapClaims)
	if !ok {
		return // fail open
	}
	overlayScopedClaims(ac, projected, scopes)
}

// overlayScopedClaims replaces roles/entitlements on ac with the freshly
// projected values, but only for a claim the token's scope already carried, so
// the refresh can only narrow to what the token was scoped for, never widen it.
//
// It intentionally overlays ONLY roles/entitlements — the only claims the refresh
// re-derives. The other scope-controlled families (email, profile) stay exactly
// as the frozen token carried them; those were already scope-confined at mint by
// sign.confineByScope (sign.go:345), so re-confining them here would be redundant
// and re-deriving them is out of scope for this feature. If a future scope-
// controlled family is added to confineByScope, it must be considered here too
// (#203 DRY-1).
func overlayScopedClaims(ac AuthContext, projected jwt.MapClaims, scopes []string) {
	for _, claim := range []string{"roles", "entitlements"} {
		delete(ac, claim)
		if slices.Contains(scopes, claim) {
			if v, ok := projected[claim]; ok {
				ac[claim] = cloneClaimValue(v)
			}
		}
	}
}

// cloneClaimValue returns a shallow copy of a slice claim value so callers that
// share one projected map (singleflight coalescing) each own their slice header
// (#203 quad DI-F4/SEC-S6).
func cloneClaimValue(v any) any {
	switch s := v.(type) {
	case []string:
		return slices.Clone(s)
	case []any:
		return slices.Clone(s)
	default:
		return v
	}
}

// jitteredGrantTTL returns sessionGrantTTL with ±15% jitter so grant-cache entries
// written together expire spread out, avoiding a synchronised-expiry stampede
// (#203 quad PERF-F3).
func jitteredGrantTTL() time.Duration {
	delta := (rand.Float64()*2 - 1) * 0.15
	return time.Duration(float64(sessionGrantTTL) * (1 + delta))
}

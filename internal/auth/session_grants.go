package auth

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
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

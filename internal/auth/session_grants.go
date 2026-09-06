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

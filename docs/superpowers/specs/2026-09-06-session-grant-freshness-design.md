# Design: fleet-safe immediate session-grant freshness

- **Date:** 2026-09-06
- **Issue:** host-manager #203
- **Scope:** `internal/auth` (cookie authentication + grant resolution) and one
  hook in `internal/host` (proxy response path). **host-manager only** — no
  kdex-crds schema change, no tenancy-service code change.
- **Origin:** the KnowDrive-Site product promise *"save here → resume in another
  AI client → bring a teammate"* (KDSocials). GitLab knowdrive-site **#145**
  (revoke) and **#146** (accept-without-relogin), Dev-validated against a running
  host-manager overlay (`fix/continuity-session-grants`, off upstream v0.9.0
  `157343f`). This issue integrates that behavior upstream in a fleet-safe form.

## Problem

Browser (cookie) session authorization is **frozen at mint**. On a cookie
request, `WithAuthentication` ([internal/auth/middleware.go:214](../../../internal/auth/middleware.go))
reads `roles`/`entitlements` straight from the signed JWT and never re-resolves
them; the claims only change when a **new access token is minted** (proactive
refresh <10 min before `exp`, else at the hourly `tokenTTL`). So a membership or
role change — grant **or** revocation — does not take effect until the token
rotates, lagging **up to ~1 hour**.

> Note: the ~60s figure in the issue report describes the `subjectResolveCache`
> ([exchange.go:65,73](../../../internal/auth/exchange.go)), which sits on the
> **PAT/proxy-bridge** path — *not* the cookie path. For a cookie session the
> real staleness bound is token rotation, which is larger.

The revocation direction is the security concern: a user removed from a resource
(e.g. a vector-store membership) keeps passing entitlement checks until the token
rotates. The grant direction is a UX defect: "accept an invitation inline, then
open the now-shared resource" 403s the just-joined user on the next request.

The membership source of truth is the **tenancy-service** (invite/accept/remove);
it surfaces to host-manager through the HTTP **Lookup `resolve-url`**
([lookup_http.go:91](../../../internal/auth/lookup_http.go)) — a live,
authoritative, password-less endpoint. host-manager already knows how to call it
(`ResolveClaims` → `ResolveSubjectClaims`); it simply freezes the result at mint
for cookie sessions instead of re-consulting it.

## Requirements

**Functional (the #145/#146 acceptance sequence, same browser cookie, no re-login):**

```
read 200 → remove 204 → read 403 → invite 201 → accept 204 → same-cookie read 200 → viewer write 403
```

- A membership/role **grant** takes effect on the subject's **next** browser
  request.
- A membership/role **revocation** takes effect on the subject's **next** browser
  request.
- Role granularity is preserved (a viewer can read but not write).
- No re-login, no new token minted between the mutation and the next request.

**Non-functional:**

- **Fleet-safe.** No unbounded per-request dependency: a page's request fan-out
  must not become an N+1 of live resolves, and a tenancy/Lookup blip must not
  degrade every browser page.
- **Attenuation-preserving.** An attenuated capability/PAT token (`kdx_cap`) is
  **never** re-inflated; the refresh only ever narrows to what the token was
  already scoped for, never widens it.
- **Active-active correct.** host-manager runs multiple replicas; freshness must
  hold across all of them.

## Architecture

Three parts in `internal/auth` plus one hook in the `internal/host` proxy.

```
                         ┌─────────────────────────────────────────┐
  cookie request ───────▶│ WithAuthentication (COOKIE, !kdx_cap)    │
                         │  1. parse+validate JWT (identity/scope)  │
                         │  2. refreshSessionGrants(authContext):   │
                         │       gen := grantGeneration()           │
                         │       hit,cur := grantCache.Get(sub,gen) │
                         │       └ stale/miss → resolve fresh ──────┼──▶ FindInternalRolesAndEntitlements
                         │                       + Lookup(fresh)    │    + ResolveClaims (bypassing the
                         │                       + Signer.Project   │      60s cache for this generation)
                         │       overlay only token-scoped claims   │
                         └─────────────────────────────────────────┘
                                        ▲ shared (Valkey)
  tenancy mutation ──▶ proxy ──2xx,non-GET,grants-source──▶ bump grantGeneration()
```

### 1. Shared grant cache (Valkey-backed)

A cache class (via `CacheManager.GetCache`, [cache/cache.go](../../../internal/cache/cache.go))
keyed by **subject**, valued with the projected grants JSON
(`{roles, entitlements}` after `claimMappings`). It is Valkey-backed in
production ([internal/cache/valkey.go](../../../internal/cache/valkey.go)), so an
entry written or invalidated by any replica is visible to all replicas at once —
this is what makes the active-active guarantee hold.

- **Generation tag.** Each entry records the **grant-generation** it was resolved
  under. A read is a *current* hit only when the entry's generation equals the
  current generation; otherwise it is treated as a miss and re-resolved.
- **Backstop TTL** ~60s (aligned with `subjectResolveCacheTTL`, configurable).
  This bounds staleness for changes host-manager never observes on the proxy path
  (a direct DB edit, an admin tool) — defense in depth, not the primary freshness
  mechanism.

### 2. Cookie fast path — `refreshSessionGrants`

Invoked from `WithAuthentication` in the `authSource == COOKIE`
([types.go:4](../../../internal/auth/types.go)) branch, **after** the token is
validated and **only** when `authContext[CapUsesClaim]` is absent
(`kdx_cap`, [middleware.go:22](../../../internal/auth/middleware.go)) — capability
and PAT tokens are left exactly as parsed.

```
func (c *Config) refreshSessionGrants(ac AuthContext, e *Exchanger) error {
    if isCapability(ac) { return nil }          // never re-inflate an attenuated token
    subject := ac.GetSubject()
    gen := e.grantGeneration()                  // shared counter (Valkey)
    if grants, current := e.grantCache.Get(subject, gen); current {
        overlayScopedClaims(ac, grants)         // hit — no live resolve
        return nil
    }
    roles, ents, err := e.ResolveInternalRolesAndEntitlements(subject)   // in-memory snapshot
    backend, err2 := e.resolveSubjectClaimsFresh(subject, gen)           // fresh Lookup for this gen
    if err != nil || err2 != nil {
        return errResolve                       // caller fails OPEN (see Failure policy)
    }
    projected := c.Signer.Project(merge(subject, roles, ents, backend))  // re-runs claimMappings
    e.grantCache.Set(subject, gen, projected)
    overlayScopedClaims(ac, projected)
    return nil
}
```

- **`overlayScopedClaims`** deletes `roles`/`entitlements` from the AuthContext,
  then re-adds each **only if the token's `scope` contained it** — mirroring the
  existing enrichment contract. Grants are therefore only ever *narrowed to* what
  the token was scoped for, never widened, and identity/`scope`/`exp` are
  untouched.
- **`resolveSubjectClaimsFresh`** is `ResolveSubjectClaims`
  ([exchange.go:303](../../../internal/auth/exchange.go)) made
  generation-aware: an entry in the underlying 60s `subjectResolveCache` is a hit
  only when its generation matches the current one. This is the **critical
  correctness point** — the changed membership lives behind the Lookup's own 60s
  cache, so the generation must reach through to a fresh Lookup call, or a
  revocation would still lag ≤60s.

### 3. Coarse epoch invalidation (the immediacy mechanism)

A single **grant-generation** counter in the shared cache. host-manager bumps it
from a **proxy response hook** ([internal/host/proxy.go](../../../internal/host/proxy.go),
on the response path): when a proxied request

1. targets a function annotated as a **grants source** (see below),
2. uses a **non-GET** method, and
3. returned a **2xx**,

the generation is incremented. Every cached grant entry (and every
generation-tagged `subjectResolveCache` entry) is thereby made stale fleet-wide,
so the **next** request from any subject re-resolves against live tenancy state.

This is deliberately **coarse**: one mutation invalidates *all* subjects rather
than computing which subject a mutation affected. It is chosen because:

- It covers both directions with no per-route knowledge. In the tenancy service
  (`knowdrive-site` `functions/tenancy-service/cmd/tenant.go`), `AcceptInvitation`
  (`POST /tenant/v1/invitations/{id}`) is a **self**-mutation, but `RemoveMember`
  (`DELETE /tenant/v1/stores/{id}/members/{userId}`) and `UpdateMemberRole`
  (`PATCH …/members/{userId}`) are **manager** mutations on a *different* subject
  named only in the URL path. A per-subject bust would have to parse each route's
  payload; a coarse bump does not.
- Membership mutations are **rare** (human-initiated invites/removes/role
  changes) relative to page loads, so the post-bump re-resolve burst is bounded
  and infrequent — and each re-resolve is itself cheap (in-memory roles + one
  in-cluster Lookup + a sub-millisecond ES256 `Project`).

**Grants-source signal.** The proxy learns which function's writes bump the
generation from a **KDexFunction annotation** — `kdex.dev/invalidates-grants-on-write: "true"`.
This needs **no kdex-crds schema change** (annotations are not part of the CRD
schema), so it introduces no nexus-manager/host-manager release-all-actors
choreography. knowdrive-site adds the single annotation to its tenancy
`function_tenancy_service.yaml`. (A first-class `spec` field is the alternative
but would require a CRD change and a dual nexus+host release for no functional
gain — rejected as YAGNI.)

## Failure policy — fail-open to last-known-good

When `refreshSessionGrants` cannot resolve (a tenancy/Lookup blip), the request
serves the **last-known-good** grants: the cached entry if one exists (even
stale-generation), else the **frozen token's own claims** (leaving the AuthContext
as parsed). It never 503s and never strips grants on a resolver error.

Rationale: today the system *always* trusts the frozen token, so fail-open is no
worse than current behavior in the revoke direction during an outage, and it
avoids turning tenancy/Lookup availability into a hard per-request dependency for
every browser page (the reporter's 503-storm concern). The revocation-during-
outage window is bounded by the outage itself and, absent an outage, by the ~60s
backstop TTL; the common-case revoke remains immediate via the epoch bump.

## Invariants

1. **Capability/PAT tokens are never re-resolved.** `kdx_cap` present ⇒
   `refreshSessionGrants` is a no-op. An attenuated token is never re-inflated.
2. **The refresh only narrows.** `overlayScopedClaims` re-adds a claim only if the
   token's `scope` already carried it; identity, `scope`, and `exp` are never
   modified.
3. **Generation reaches the Lookup.** A generation bump forces a fresh Lookup, not
   just a fresh projection.
4. **Shared state.** The generation counter and grant cache live in the shared
   (Valkey) cache, so invalidation is fleet-wide.

## Testing

**Integration — the acceptance sequence (headline):** drive the full #145/#146
sequence against the middleware with a stub tenancy/Lookup provider and a stub
proxy that emits the grants-source mutations:
`read 200 → remove 204 → read 403 → invite 201 → accept 204 → same-cookie read 200 → viewer write 403`,
all on one cookie, asserting the epoch bump makes each read reflect the prior
mutation with no new token.

**Unit:**

- `TestSessionGrantsSameCookieSeesMembershipChanges` (from #203, **adapted for
  fail-open**): a changing-grant provider is reflected on the next request in both
  directions; and on `provider.err`, the request **serves last-known-good**
  (not the reference issue's `503`, which was the fail-*closed* behavior we
  rejected).
- `TestSessionGrantsPreserveScopeAndCapability` (from #203, unchanged intent): a
  capability token is left untouched; a session token gains only scoped claims.
- Generation reaches the Lookup: a bump forces a fresh `ResolveClaims` even within
  the 60s `subjectResolveCache` window.
- Fleet-safety: within one generation, N cookie requests for one subject cause
  **one** live resolve (cache coalescing).
- Active-active: a generation bump written on replica A is observed by replica B
  (shared-cache test).

## Out of scope / follow-ups

- **Per-subject precise invalidation.** If membership-mutation volume ever makes
  the coarse re-resolve burst material, a per-route affected-subject map is the
  optimization — deferred until measured.
- **Tenancy-service-driven invalidation** (a push/version from the tenancy
  service) — not needed; the coarse proxy-observed bump plus the backstop TTL
  meets the requirement host-manager-side.
- **Non-cookie paths** (header bearer, PAT bridge) are unchanged; they already
  re-resolve per request via `EnrichAuthContext`.

## Key references

- `internal/auth/middleware.go` — `WithAuthentication`, `CapUsesClaim`, COOKIE
  branch.
- `internal/auth/exchange.go` — `Exchanger`, `subjectResolveCache`
  (`subjectResolveCacheTTL`), `ResolveSubjectClaims`,
  `ResolveInternalRolesAndEntitlements`, `mergeBackendClaims`.
- `internal/auth/roles.go` — `InternalIdentityProvider`,
  `FindInternalRolesAndEntitlements`, `ResolveClaims`.
- `internal/auth/lookup_http.go` — `httpLookup.ResolveClaims` (the `resolve-url`
  contract).
- `internal/sign/sign.go` — `Signer.Project` (cacheable projection) /
  `SignProjected` (per-token ES256).
- `internal/cache/{cache,memory,valkey}.go` — shared cache, generation primitive.
- `internal/host/proxy.go` — proxy response path (invalidation hook).
- knowdrive-site tenancy: `functions/tenancy-service/cmd/tenant.go`
  (`AcceptInvitation`, `RemoveMember`, `UpdateMemberRole`);
  `k8s/dev/function_tenancy_service.yaml` (grants-source annotation);
  `patches/host-manager` (the Dev overlay this integrates).
- Upstream base: host-manager v0.9.0 `157343f`.

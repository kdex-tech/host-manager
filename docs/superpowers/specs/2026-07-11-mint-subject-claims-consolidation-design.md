# Pre-attenuation subject-claims merge + auth mint-path consolidation

- **Issue:** kdex-tech/host-manager#140
- **Date:** 2026-07-11
- **Status:** approved

## Problem

OAuth/MCP access tokens are minted **without** the subject's data-driven backend
claims (today's instance: `vs_entitlements`), so an OAuth-authenticated caller
(e.g. the claude.ai MCP connector) cannot satisfy any operation whose `security`
requires a `vector_stores:*:<verb>` scope. REST service-backed writes
(`POST /api/v1/ingest`, `/files`, `/uploads`, …) are denied at the function
authz gate even though the subject owns the store.

### Root cause

The resolve→merge for data-driven backend claims happens only at scattered
downstream points — password login's `FindInternal` credential Lookup, and the
`#138` per-request proxy bridge on the `!alreadyLoggedIn` path. The **primary
OAuth token mint** (`mintTokensFromCode`) and the **refresh mint**
(`mintTokensFromSubject`) build their signing context from
`FindInternalRolesAndEntitlements` (static roles/entitlements) only and **never
call `ResolveSubjectClaims`**. An OAuth access-token JWT authenticates via
`WithAuthentication` (`alreadyLoggedIn == true`), so the proxy bridge is
bypassed. The token — and everything attenuated from it (FAT projection,
`mint_token`, scope down-scoping) — never carries the grant.

Because attenuation can only ever *narrow* a held token, the merge must land in
the signing context of the **primary mint, pre-attenuation** — not at a
per-request bridge.

### Systemic cause

`exchange.go` has five primary mint paths with three near-identical, copy-pasted
scope-gate blocks and three different subject-context resolvers. This divergence
already produced #80 (code path disagreed with refresh path) and now #140
(code/refresh diverge from login on backend claims). The copy-paste *is* the
edge-case surface.

## Goals

1. Fix #140: OAuth/MCP + refreshed tokens carry the subject's data-driven backend
   claims, pre-attenuation.
2. Reduce the number of distinct code paths through auth mint, as a precaution
   against unhandled edge cases (senior-engineering review goal).
3. Hold only to the assumption that **ClaimMappings may transform the auth
   context in any way its design permits** — no logic may special-case
   `vs_entitlements` or assume it is the only mapper effect.
4. Replace the hand-rolled entitlements dedup in the Minter with the canonical,
   attenuation-safe `entitlements.Compact` (lossless Dominates-based reduction).

## Non-goals

- Folding OIDC `ExchangeToken` (append semantics) or `LoginClient`
  (client `AllowedScopes` enforcement) into the shared confinement — they are
  genuinely different; noted as follow-ups, not silently changed.
- Versioned/immutable module URLs, freshness-model changes, or any change to the
  `#138` proxy bridge.

## Design

### Component 1 — generic backend-claim merge

`subjectSigningContext(subject) → (roles, entitlements []string, backend jwt.MapClaims, err error)`
wraps `FindInternalRolesAndEntitlements(subject)` **and**
`ResolveSubjectClaims(subject)`. `mintTokensFromCode` and `mintTokensFromSubject`
call it and merge **all** of `backend` (whatever keys it holds) non-conflictingly
into `signingContext`. The subsequent `Signer.Project` runs the host
ClaimMappings over the enriched context. This code never names `vs_entitlements`
— it is one instance of a mapper input.

`LoginLocal` already receives the same backend claims for free from
`FindInternal`'s credential Lookup, so it does not use this resolver.

### Component 2 — scope-confinement moves post-mapper, into the Minter

Stripping scope-denied claims **before** `Project` runs the mapper is unsound:
the mapper runs after and can reintroduce any claim. So confinement moves to
**after** the mapper.

New `Signer.SignScoped(ctx jwt.MapClaims, grantedScopes []string) (string, error)`:

1. `projected := Project(ctx)`  (allowlist copy → mapper → Compact)
2. Confine `projected`: for each scope-controlled claim family absent from
   `grantedScopes`, delete it — `email`→`email`, `profile`→`profileClaims`,
   `entitlements`→`entitlements`, `roles`→`roles`. (`openid` governs id_token
   issuance, not a claim strip.)
3. `SignProjected(projected)`

Because confinement operates on the mapper's output, it holds regardless of what
ClaimMappings injected — no source-claim enumeration.

`applyScopeFilter(ctx, requestedScope, defaultScopes) → grantedScopes []string`
shrinks to pure scope **computation**: it determines granted scopes (fixed order
`openid email profile entitlements roles`, then pass-through of other requested
scopes), sets `ctx["scope"]`, and returns the granted list. It no longer mutates
claims. `defaultScopes` is per-path (`LoginLocal` → the 5-scope default set;
code/refresh → `nil`, preserving "empty scope = nothing granted").

The three copy-pasted strip blocks in `LoginLocal`, `mintTokensFromCode`,
`mintTokensFromSubject` collapse into `applyScopeFilter` (compute) +
`SignScoped` (confine). Their id_tokens also mint via `SignScoped`, so
confinement applies consistently.

**Bounded blast radius:** `FAT` projection (`proxy.go`), `mint_token`
(`mint_token.go`), OIDC `ExchangeToken`, and `LoginClient` keep raw
`Project`/`SignProjected`/`Sign` — unchanged.

### Component 3 — Compact replaces dedupeStringSlice

In `Project`, `projected["entitlements"] = dedupeStringSlice(ent)` becomes
`entitlements.Compact(...)` (coercing `[]any` mapper output to `[]string`).
`Compact` removes strictly-dominated entries and equivalent-form duplicates,
lossless and defined purely via `Dominates` (cannot drift from attenuation).
Runs in `Project`, so every minted token (FAT, session, `mint_token`) benefits.

Requires bumping `github.com/kdex-tech/entitlements/go` `v0.2.1 → v0.3.0`.

## Invariant matrix

### Attenuation (most critical)

- **ATT-1 · Primary-mint-only.** Backend claims are merged only at the three
  primary mints, upstream of every attenuation stage. The `#138` bridge stays
  `!alreadyLoggedIn`-only; `Project` (FAT), `mint_token`, and scope down-scoping
  are untouched. No attenuated derivative gains a new resolve/inflate path.
  *Pin:* existing `TestProxy_PATBridge_DoesNotReinflateAttenuatedToken` green +
  a downscoped `mint_token` JWT that dropped a grant cannot regain it.
- **ATT-2 · `mint_token` held-check unchanged.** Mints only entitlements present
  in the caller's token; the fix changes what the primary token legitimately
  holds, not the check. *Pin:* `mint_token(vector_stores:X:all)` succeeds **iff**
  the caller's OAuth token carries it.
- **ATT-3 · Compact is attenuation-safe.** Lossless, `Dominates`-defined.
  *Pin:* Dominates round-trip — every requested check satisfied by the pre-Compact
  set is satisfied by the post-Compact set and vice versa.

### Amplification prevention

- **AMP-1 · Authority reflects reality, fail-safe.** `ResolveSubjectClaims`
  returns exactly the backend's answer for that subject; nil on error/unwired →
  role-only, never more. *Pin:* empty resolver → no extra grant; erroring
  resolver → role-only, no crash.
- **AMP-2 · Scope-denied strip is generic & post-mapper.** Any claim the mapper
  injects into a scope-controlled family is stripped when its scope was not
  granted. *Pin (per path):* entitlements scope denied → neither `entitlements`
  nor any mapper-injected entitlement survives, even with a mapper rule that
  targets `entitlements` from an arbitrary source claim.
- **AMP-3 · No refresh scope re-expansion.** `mintTokensFromSubject` uses the
  refresh token's stored scope; fresh resolve is bounded by that scope's gate.
  *Pin:* refresh whose original grant lacked `entitlements` → no grant reappears.
- **AMP-4 · Subject is authoritative.** `subject` comes from verified
  code/refresh claims, never client input. Structural.
- **AMP-5 · Consolidation introduces no widening.** Per-path `defaultScopes`
  preserves empty-scope behavior. *Pin:* empty-scope code mint → no `entitlements`.
- **AMP-6 · id_token consistency.** id_tokens mint via `SignScoped`, so stripped
  claims never leak into them. *Pin:* entitlements denied → id_token lacks
  `entitlements`.

## Affected code

| Path | Function | Change |
|---|---|---|
| Password login | `LoginLocal` | `applyScopeFilter` + `SignScoped` (closes its latent post-mapper leak) |
| OAuth auth-code | `mintTokensFromCode` | `subjectSigningContext` + merge + `applyScopeFilter` + `SignScoped` |
| Refresh | `mintTokensFromSubject` | same as code path |
| Minter | `sign.Project` | `Compact` replaces `dedupeStringSlice` |
| Minter | `sign.Signer` | new `SignScoped`; `confineByScope` helper |
| — | OIDC `ExchangeToken`, `LoginClient`, FAT, `mint_token` | unchanged |
| go.mod | — | `entitlements/go` `v0.2.1 → v0.3.0` |

## Testing (TDD)

1. **RED first:** OAuth code mint → token `entitlements` contains the resolved
   backend grant (the bug).
2. Refresh mint preserves it across re-mint.
3. AMP-2 per path: entitlements scope denied → no `entitlements` survives, using
   a mapper rule with a **non-`vs_entitlements`** source claim (proves generality).
4. AMP-5: empty-scope code mint → no `entitlements` (unchanged).
5. AMP-6: entitlements denied → id_token lacks `entitlements`.
6. AMP-1: nil/erroring resolver → role-only, no crash.
7. ATT-1: existing proxy attenuation test green; downscoped `mint_token` cannot
   regain a dropped grant.
8. ATT-3: `Compact` Dominates round-trip on a dominated set.
9. `LoginLocal` regression: default-scope behavior unchanged.

## Review hardening (2026-07-11, post-implementation)

A senior security review (two independent passes) confirmed the invariants above
hold, but found one **Medium** scope-confinement regression the consolidation
introduced: `applyScopeFilter` folded a context-supplied `scope` claim into the
*granted* set, and `granted` drives `confineByScope` — so a `scope` claim coming
from the authoritative user store (`ResolveClaims` for code/refresh via
`mergeBackendClaims`; `FindInternal` for login) could materialize
`entitlements`/`roles`/`email` the OAuth client never requested (authz flips
deny→allow). Not exploitable with today's `vs_entitlements`-only backend, but a
latent hole.

**Resolution — reserved-claim boundary.** The authoritative user store may
supplement any claim (`roles`, `entitlements`, `email`, `vs_entitlements`,
custom) — that is the feature — EXCEPT a reserved set the mint/signer own:

- auth-flow / identity: `scope`, `scp`, `sub`, `grant_type`, `auth_method`, `idp`
- server mint-time: `iat`, `exp`, `jti`, `iss`, `aud`, `nbf`

Enforced by `reservedMintClaims` in `internal/auth/exchange.go`:
- `mergeBackendClaims` skips reserved keys (code/refresh backend supplement).
- `LoginLocal` strips reserved keys (except `sub`, the resolved identity) from the
  `FindInternal` result.
- `applyScopeFilter` sets `scope` authoritatively (overwrites/clears any context
  value) rather than merging it — closing the hijack for every path.

**AMP-7 (new invariant):** the user store cannot set reserved claims; a
backend-supplied `scope` cannot widen confinement, and `sub`/`idp`/`grant_type`/
`exp` cannot be injected/rebound. Pinned by
`TestMint_UserStoreCannotHijackReservedClaims` (per-path) + a "feature not
castrated" case proving non-reserved supplements still flow.

**Deferred (documented, not fixed here):** ClaimMappings *rule* output writing to
reserved claims (operator-trusted config; also relied on by the `exp=-1`
expired-token test technique — needs a separate mechanism); `confineByScope` not
gating `scp`/`idp`/`grant_type` (now moot for the user-store vector, remains for
host rules); `LoginClient`/OIDC `ExchangeToken` still on raw `Sign`.

## Risks

- Moving confinement post-mapper changes behavior only in the previously-leaky
  case (scope denied + mapper injects) — a hardening. Verify no existing test
  asserted the leaky behavior.
- `Compact` runs for all tokens incl. `mint_token`/FAT; must preserve `Project`
  determinism (first-seen order) so the FAT cache key is stable — `Compact`
  preserves original strings and first-seen order.

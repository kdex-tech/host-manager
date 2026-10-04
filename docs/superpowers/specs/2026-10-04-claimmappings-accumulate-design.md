# claimMappings: list targets accumulate by default (host-manager#229)

**Status:** approved design, 2026-10-04
**Repos:** kdex-dmapper → kdex-crds → kdex-host-manager, kdex-nexus-manager → infra (fleet repin)

## Problem

A `claimMappings` rule writes its result over its target. Since dmapper#1 (v0.1.2) each rule
*sees* earlier rules' output in `self`, but the write is still a replacement. host-manager then
`maps.Copy`s the mapper output over the context (`sign.Signer.Project`, `auth.EnrichAuthContext`).

So a rule targeting `entitlements` that does not restate `self.entitlements` silently strips every
static (KDexRoleBinding) grant from every token the host signs. From #229, with signing context
`entitlements: [static:a]`, `eum_entitlements: [eum:b]`:

| Rules (all target `entitlements`) | Today | After |
|---|---|---|
| A: `self.eum_entitlements` | `[eum:b]` (static lost) | `[static:a eum:b]` |
| B: `self.entitlements + self.eum_entitlements` | `[static:a eum:b]` | `[static:a eum:b]` |
| C: `self.entitlements`, then `self.eum_entitlements` | `[eum:b]` (static lost) | `[static:a eum:b]` |

## Intent and success criteria

- The natural way to write "also add these grants" (A, C) keeps the existing grants.
- Every rule live in the fleet today produces a byte-identical claim set. Surveyed 2026-10-04: all
  7 live rules (knowdrive-site chart default + dev/prod hosts; infra smg/spike2/public tenants) are
  of the form `(has(self.entitlements) ? self.entitlements : []) + <extra>`; none narrows a list.
- A rule that must narrow a list (a filter) can still do so, explicitly.
- host-manager code stays claim-agnostic: no claim name is special-cased to get this behaviour.

## Design

### 1. dmapper merge semantics (v0.2.0)

`MappingRule` gains one optional field:

```go
// MergeStrategy controls how a rule's result combines with a value already
// present at its targetPropPath.
// +kubebuilder:validation:Enum=Accumulate;Replace
type MergeStrategy string

const (
	MergeAccumulate MergeStrategy = "Accumulate"
	MergeReplace    MergeStrategy = "Replace"
)

// merge controls how the rule's result combines with a value already at
// targetPropPath. Accumulate (the default when empty): when both the existing
// value and the result are lists, the result is the existing list followed by
// the result's items not already present (order-preserving set-union), so
// restating self.<target> is harmless and idempotent. Any other shape pair
// (scalar, map, list vs non-list) replaces. Replace: the result always
// replaces — use it for a rule that filters or narrows a list.
// +kubebuilder:validation:Optional
Merge MergeStrategy `json:"merge,omitempty"`
```

Rules:

- **"Existing"** is the value at `targetPropPath` in the chained `self` at the time the rule runs
  (so it includes earlier rules' output) — the same view dmapper#1 gave rules for reading.
- **Only list-onto-list accumulates.** `[]string` and `[]any` are both lists. Maps and scalars
  replace, as today (deep map merge is a separate design; nothing needs it — YAGNI).
- **Union, not concat.** host-manager runs the mapper twice over the same context
  (`EnrichAuthContext`, then `Project` over the enriched result). Concat would double every list
  on the second run; `entitlements.Compact` would mask that for `entitlements` only. Union makes
  re-execution idempotent for any claim.
- **Equality** is `reflect.DeepEqual` per element. **Shape:** the merged result is `[]string` when
  every element is a string, else `[]any`. Inputs arrive as `[]any` (JWT-decoded) and `[]string`
  (CEL conversion), mixed.
- **An unknown `merge` value** passed programmatically (bypassing CRD validation) fails
  `NewMapper` with an error, never a silent fallback.
- Both the returned result and the chained `self` receive the merged value.
- `Required` semantics are unchanged.

README gains a "Merge semantics" section with the A/B/C table and a `Replace` filter example.
Version: **v0.2.0** — default behaviour changes; pre-1.0 minor.

### 2. kdex-crds

- Bump `github.com/kdex-tech/dmapper` v0.1.1 → v0.2.0; `make manifests` adds `merge` (enum) to
  `KDexHost.spec.auth.claimMappings[]` and `KDexFunction.spec.claimMappings[]`.
- Rewrite both field descriptions: rules apply in order; each sees earlier rules' output in `self`;
  a list target accumulates (union) by default; set `merge: Replace` to narrow/filter.
- Propagate with `./updateCrdUsage.sh -t` (bumps crds patch tag, pins nexus + host-manager).

### 3. kdex-host-manager (v0.20.0)

- Bump dmapper to v0.2.0 (direct dependency) alongside the crds pin.
- No production code change expected: `Project` and `EnrichAuthContext` copy mapper output over
  the context, and that output now already contains the existing list. Verify, don't assume.
- Regression tests in `internal/sign` (generic, arbitrary example source claim — no real claim
  name special-cased):
  - #229 rows A and C keep the static grant; row B unchanged.
  - A `merge: Replace` filter rule narrows the list.
  - Running the mapper twice (enrich, then project) yields no duplicates and no growth.
- Release **minor** (v0.20.0): token contents change for any host with an A/C-shaped rule.

### 4. kdex-nexus-manager

Receives the crds bump via `updateCrdUsage.sh`; released too, because a CRD change has to ship
in every component that reads the CRDs, even when the schema change is backward compatible.

### 5. Fleet

infra repins crds + nexus + host-manager together (never host-manager alone); the deploy is the
user's manual click.

## Error handling

- CEL evaluation errors and path conflicts behave as today (skip unless `Required`).
- Unknown `merge` value → `NewMapper` error (CRD enum prevents it on cluster).

## Risk

A rule anywhere that relied on replacement to *narrow* a list would start leaving extra items in.
None found in kdex, knowdrive-site or infra. Release notes name the `merge: Replace` opt-out.

## Follow-ups (not blockers)

- kdex-kcnas skill, all 3 copies: document accumulate + `Replace`.
- eum `chart/templates/host_auth_patch.yaml`: its comment says the leading `self.entitlements`
  term is load-bearing — no longer true; the rule still works unchanged.
- infra `TestTenantClaimMappingsKeepStaticEntitlements`: becomes defence-in-depth; keep it.

## Out of scope

- Deep merge of map targets.
- Any change to which claims are reserved (`reservedMintClaims`) or to `entitlements.Compact`.

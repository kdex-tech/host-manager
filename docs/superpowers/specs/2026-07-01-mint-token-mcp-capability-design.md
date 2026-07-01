# `mint_token` — connector-authed minting of short-lived, bounded-use, attenuated entitlement capabilities

- **Date:** 2026-07-01
- **Tracking issue:** recoursellm-group/multi-modal-store#280 (framework work lives here in kdex-host-manager)
- **Status:** design approved, ready for implementation plan

## Summary

Add an MCP tool — `mint_token` — that lets an MCP connector, riding its ambient
auth, mint a **short-lived, bounded-use, attenuated capability**: a token
carrying an explicit subset of the caller's own entitlements. A local,
credential-less process (an off-context uploader/downloader, a whole-directory
sync) can then use that token against the knowdb / host-manager REST surface —
with no baked-in secret and no pre-installed authenticated CLI.

```
mint_token({ entitlements: string[], ttl_seconds?, uses? })
  -> { token, expires_at, entitlements, uses_remaining }
```

The tool is owned end-to-end by host-manager (the Authorization Server). It is
surfaced on the host's existing OAuth2-protected MCP resource by augmenting that
resource's JSON-RPC stream. **knowdb requires no changes.**

## Why this is the hack-free shape

Three facts about the existing system determine the design. Each was verified
against source, not assumed.

### Fact 1 — a host-audience JWT's `entitlements` claim is trusted verbatim

On the header path, `WithAuthentication` validates an inbound
`Authorization: Bearer <jwt>` against the host's own audience and populates
`authContext` **directly from the token claims**
(`internal/auth/middleware.go` — `jwt.ParseWithClaims(tokenString, &authContext, …)`).
The `entitlements` claim is used as-is; it is **not** re-resolved from
`KDexRoleBinding`s. (Only the PASETO-PAT bridge in `internal/host/proxy.go`
re-resolves from role bindings.)

Consequence: a token whose `entitlements` claim has been *narrowed* at mint time
is enforced as narrowed, end-to-end, with **zero new enforcement code** — the
existing proxy identity gate, the per-function FAT re-mint
(`sign.Signer.Project` copies `entitlements`), and knowdb's
`auth::entitlements::is_allowed` all already verify the forwarded
`entitlements`. This is the linchpin: **the minted token must be a host-audience
JWT.**

### Fact 2 — the connector authenticates only to the MCP resource

Via RFC 7591 Dynamic Client Registration + RFC 8707 resource-bound OAuth2, the
MCP connector holds a **PASETO PAT whose audience is the MCP resource URI**
(`internal/auth/oauth2.go:writeResourcePATResponse`,
`internal/auth/exchange.go:MintResourcePAT`), with entitlements *intentionally
not baked in*. That token authenticates **only** at the MCP resource
(`/api/v1/mcp`). A separate host-audience endpoint (`/-/token/mint`, `/-/mcp`)
would reject it.

Consequence: the mint capability must be reachable **through the same
`/api/v1/mcp` resource** the connector already uses. A separate AS endpoint is a
dead end without a second resource registration.

### Fact 3 — only host-manager can mint

host-manager holds the signing key, and by the time a `tools/call` reaches the
proxy the PAT bridge has already resolved the caller's **held** entitlements into
`authContext`. knowdb has neither the key nor a host-audience credential, and
should stay purely data-plane.

**Therefore:** the Authorization Server augments its own OAuth2-protected MCP
resource with one AS-owned tool. This is not a generic proxy accidentally
learning JSON-RPC — it is the AS exposing a token-minting capability on a
resource it already guards, which is the architecturally correct home.

## Architecture

### Component: MCP JSON-RPC augmentation (host-manager, on the opt-in MCP function route)

Only two JSON-RPC methods are touched. Everything else — every knowdb tool call,
the long-lived SSE `GET` stream, `initialize`, `prompts/*`, `resources/*` — is
opaque passthrough, preserving the verified streaming behavior in
`knowdrive-site/k8s/dev/function_knowdb_mcp.yaml`.

- **`tools/list`** → forward to knowdb, buffer the `application/json` result,
  splice the `mint_token` descriptor into the returned tool array. (Extends the
  spirit of the existing `ModifyResponse` transform in `proxy.go`, which already
  rewrites responses — here it splices one array element on one method for one
  opt-in function.)
- **`tools/call` with `name == "mint_token"`** → handled locally by host-manager;
  **never forwarded** to knowdb.

JSON-RPC batching: a batch request is inspected; a `mint_token` entry is handled
locally, the remaining entries are forwarded to knowdb, and the two result sets
are merged back into one JSON-RPC batch response preserving `id` correlation.

Interception fires only when the function is (a) oauth2-protected (already
detected via `oauth2ProtectedResources()`) **and** (b) the host enables the
feature (see Policy). Otherwise the route is untouched.

### Component: `mint_token` handler (host-manager)

By the time the call arrives, the PAT bridge has populated `authContext` with the
caller's resolved held set. Steps:

1. **Parse** `entitlements: string[]`. Reject any entry that is not well-formed
   per the kdex-entitlements grammar (`<resource>:<resourceName>:<verb>` and its
   medium/short/opaque/wildcard forms).
2. **Attenuate.** For each requested entitlement, verify the caller's **held
   set satisfies it** using the existing kdex-entitlements checker (the same
   wildcard-aware verification used at the request-time gate). Wildcards narrow
   only: holding `vector_stores:X:write` cannot mint `vector_stores:*:write`;
   holding `vector_stores::write` can mint `vector_stores:X:write`. Reject the
   first offending entitlement with a clear, specific error.
   - **Held set (Phase 1) = static `KDexRoleBinding` grants only** — exactly what
     the connector PAT bridge already resolves
     (`Exchanger.ResolveInternalRolesAndEntitlements` →
     `roles.go:FindInternalRolesAndEntitlements` → `collectEntitlements`). See
     "Documented limitations."
3. **Clamp** `ttl_seconds` to the server-side cap (`spec.auth.mintToken.ttlCapSeconds`,
   default ~60s). Clamp `uses` to `spec.auth.mintToken.usesCap`.
4. **Apply destructive-verb policy.** Requested entitlements whose verb is
   `delete` or `own` force `uses = 1` and a shorter ttl cap (or a separate gate),
   per policy config.
5. **Mint** a host-audience JWT and, when `uses > 1` (or forced to 1 by policy),
   provision the budget counter (see below).
6. **Return** `{ token, expires_at, entitlements, uses_remaining }`.

### Component: the minted token (host-audience JWT)

Built with the existing signer:

```
sign.NewSigner(hostAudience, ttl, issuer, activePair.Private, activePair.KeyId, nil)
```

- `aud` = the `KDexHost` FQDN (`Config.Audience`) — **not** a function/FAT
  audience, **not** a PASETO PAT. This is what makes Fact 1 apply.
- `sub` = the caller's subject (from `authContext`).
- `entitlements` = exactly the requested (attenuated) set.
- A **marker claim** (e.g. `cap` / `mtu`) identifying this as a bounded-use
  capability, so the budget-decrement step (below) fires only for these tokens
  and never for ordinary session JWTs.
- `jti` (already attached by `SignProjected`) keys the budget counter.

The token is **stateless-verifiable**: identity and authorization are the
signature + claims. The only stateful bit is the *budget*, tracked separately.

### Component: bounded-use budget (jti-keyed Valkey counter)

`uses` is enforced with an atomic counter in the host's existing Valkey-backed
cache manager — **not** a new store, and **not** by caching the token value.

- **At mint** (`uses` effective > 1, or forced single-use): write
  `cap:uses:<jti> → remaining` with TTL = the token's own ttl. Self-expiring; no
  orphan state.
- **At each consuming request:** the inbound host middleware
  (`WithAuthentication`), immediately after a successful signature/audience
  validation of a token carrying the marker claim, calls a new atomic cache
  operation `DecrementIfPositive(cap:uses:<jti>) → (remaining, ok)`. `ok == false`
  → reject (`401`/`403`); the request never reaches routing. This single
  chokepoint covers **all** endpoints — no per-function work.
- **Atomicity:** the Valkey backend implements the op as one Lua script
  (`EXISTS`/`GET` → `DECR` → return), so N concurrent uses cannot over-spend
  (no TOCTOU). The in-memory backend (tests/dev) implements the same contract
  under a mutex.
- **Marker gate:** decrement keys off the marker *claim*, not the auth source, so
  a capability token cannot dodge counting by being presented as a cookie; and a
  normal session JWT (no marker) is never decremented.

Windowed (`uses` unbounded within ttl) tokens carry **no** counter and are pure
stateless short-lived JWTs — no cache interaction at all.

### Component: cache abstraction change (internal to host-manager)

The cache interface grows **one** atomic operation,
`DecrementIfPositive(ctx, key) (remaining int64, ok bool)`, with:

- a Valkey implementation backed by a Lua script (atomic decrement-if-positive),
- an in-memory implementation (mutex-guarded) preserving identical semantics for
  tests and dev-mode.

This is entirely internal; no CRD or cross-repo impact.

### Component: opt-in + policy (`KDexHost.spec.auth.mintToken`)

A small block under `spec.auth`, so the feature is off unless explicitly enabled
and its caps are server-owned:

```yaml
spec:
  auth:
    mintToken:
      enabled: true
      ttlCapSeconds: 60          # hard ceiling on ttl_seconds
      usesCap: 32                # hard ceiling on uses
      destructiveVerbs: [delete, own]   # forced uses=1 + short ttl
```

A function surfaces `mint_token` only when it is oauth2-protected **and**
`spec.auth.mintToken.enabled` is true. This is a `kdex-crds` field addition; the
plan must account for CRD version propagation (`updateCrdUsage.sh -t`) and the
two-commit plan-time-validation rule (land the CRD field, then use it).

## Data flow

Minting (through the connector):

```
MCP connector --(resource PAT, aud=/api/v1/mcp)--> host-manager proxy
  proxy: validate PAT against oauth2Resource; PAT bridge resolves held set into authContext
  intercept tools/call name=mint_token (do NOT forward to knowdb):
    parse -> attenuate (requested ⊆ held) -> clamp ttl/uses -> destructive policy
    mint host-audience JWT (entitlements=requested, marker, jti)
    if bounded: write cap:uses:<jti>=N (TTL=ttl)
    return { token, expires_at, entitlements, uses_remaining }
```

Consuming (off-context process, no prior credential):

```
local process --(Authorization: Bearer <minted JWT>)--> host-manager
  WithAuthentication: validate signature + aud(host); entitlements trusted verbatim -> authContext
  if marker present: DecrementIfPositive(cap:uses:<jti>); !ok -> reject
  route to KDexFunction (e.g. /api/v1/files)
    proxy identity gate + per-op security check (verify against attenuated entitlements)
    re-mint downstream FAT (Project copies entitlements) -> knowdb
      knowdb auth::entitlements::is_allowed enforces the same set
```

## Error handling

- **Malformed entitlement** → reject the mint with the offending string named.
- **Attenuation failure** (requested ⊄ held) → reject, naming the first
  entitlement not satisfied by the held set.
- **ttl/uses over cap** → clamp silently to the cap and reflect the clamped
  values in the response (`expires_at`, `uses_remaining`); do not error.
- **Budget exhausted / counter missing** → **fail-closed**: reject the consuming
  request. A missing counter for a still-valid token (Valkey eviction/flush) is
  treated as exhausted. Short TTLs + a persistent (hyperdisk-backed) host Valkey
  make this vanishingly unlikely; fail-closed is the correct default for a
  security capability. This makes a bounded-use token only as available as the
  host's Valkey — the same dependency sessions already carry.
- **Spend-on-attempt semantics:** a use is decremented at authentication time,
  before the downstream round-trip, so it is spent even if the backend
  subsequently fails. Refund-on-failure would require compensation logic threaded
  through the proxy `ErrorHandler` — the kind of coupling this design avoids. A
  capability budget is defined as "N authenticated attempts," not "N successful
  operations." Documented as tool behavior.

## Testing

- **Attenuation:** table-driven kdex-entitlements cases — exact match, short/medium
  form, wildcard-narrows-only (grant `X:write` cannot mint `*:write`; grant
  `::write` can mint `X:write`), opaque scopes, malformed input rejected.
- **Token shape:** minted token has `aud == host`, `entitlements ==` requested,
  marker claim present, `exp` within cap; asserts it validates through
  `WithAuthentication` and its entitlements reach `authContext` verbatim.
- **End-to-end enforcement:** a minted attenuated token is accepted for a granted
  route and 404/403'd for a route outside the attenuated set (proves Fact 1 with
  no new enforcement code).
- **Bounded-use counter:** `DecrementIfPositive` atomicity under concurrency
  (no over-spend), exhaustion → reject, missing key → fail-closed, TTL expiry;
  parity between Valkey and in-memory backends.
- **Interception:** `tools/list` splices exactly one descriptor and leaves
  knowdb's tools intact; `tools/call name=mint_token` is not forwarded; a batch
  mixing `mint_token` + knowdb tools merges results with correct `id`
  correlation; SSE `GET` and all other methods pass through untouched.
- **Opt-in gating:** tool absent when the host disables the feature or the
  function is not oauth2-protected.

## Phasing (build order; same end state)

1. **Stateless windowed token + interception.** `mint_token` mints a
   host-audience JWT (ttl-only, no counter), `tools/list` splice + `tools/call`
   handling, attenuation, ttl cap. Proves the flagship off-context upload/download
   path with zero cache changes — the first reviewable increment.
2. **Bounded-use.** Cache `DecrementIfPositive` op (Valkey Lua + in-memory),
   marker claim, mint-time counter provisioning, middleware decrement, fail-closed
   behavior, destructive-verb policy.

The `KDexHost.spec.auth.mintToken` field (with `enabled` + `ttlCapSeconds`) lands
with step 1; `usesCap` + `destructiveVerbs` are consumed in step 2.

## Documented limitations

- **Per-VS grants not mintable via the connector (Phase 1).** The connector's
  held set is static `KDexRoleBinding` grants only; dynamic per-vector-store
  `vs_entitlements` (from the login-time credential-check Lookup) are baked into
  the browser cookie JWT and are **not** re-resolved for a resource PAT. So
  `functions:*` route/function entitlements (including the flagship
  `functions:/api/v1/files:write|read`) mint fine, but `vector_stores:<id>:*`
  grants a user holds only via the Lookup are not mintable through the connector.
  Unifying the connector held set (resolve static ∪ `vs_entitlements`) is a
  broader PAT-bridge change — it would also affect knowdb's own per-VS MCP
  enforcement over the connector — and is out of scope here. Tracked as a
  follow-up.
- **Spend-on-attempt**, not spend-on-success (see Error handling).
- **Bounded-use availability** is bounded by the host's Valkey (fail-closed).

## Reuse (net-new surface is small)

Already exist and are reused verbatim: the entitlement grammar + checker
(kdex-entitlements), the FAT signer (`sign.Signer.Project` / `SignProjected`),
downstream enforcement (proxy identity gate + knowdb `is_allowed`), the
oauth2-protected-resource detection, and the Valkey-backed cache manager. Net-new:
the JSON-RPC augmentation on one route, the `mint_token` handler, one atomic cache
op, a marker claim, and the `spec.auth.mintToken` policy field.

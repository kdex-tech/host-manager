# FAT Token Exchange for Direct Function-to-Function Calls

- **Date:** 2026-09-07
- **Status:** Design (approved for spec review)
- **Repos touched:** `kdex-host-manager`, `kdex-fngogen` (no `kdex-crds` change)

## Problem

A `KDexFunction` handler often needs to call **another** function (B) as part
of serving a request. Today it can't do so authenticated:

- The handler receives only a **Function Access Token (FAT)** minted by the
  host proxy, scoped to **its own** audience (`fatAudienceFor(A)` — see
  `internal/host/proxy.go`). Presented to B, it fails B's audience check.
- The host strips the user's original `Authorization`/`Cookie` before the
  request reaches the handler (`internal/host/proxy.go`, #90), so the handler
  has no user-audience credential to replay either.
- The AS advertises only `authorization_code`, `client_credentials`,
  `password`, `refresh_token` (`internal/auth/discovery.go`). There is **no
  token-exchange grant** — nothing a handler can call to trade its FAT for a
  token addressed to B.

We want **direct, in-cluster B-to-B calls** (A calls B's Knative Service
directly, not back through the host proxy), where B validates the presented
token itself.

## Goals

- A handler can obtain a **host-signed JWT with `aud = B`** and call B directly.
- B — an fngogen-generated function — validates it on its **existing `bearer`
  path** (`jwt.Parse(t.Token, JWKS, WithAudience(AUDIENCE), WithIssuer(ISSUER))`,
  `kdex-fngogen/cmd/templates/main.go.tmpl`), with **no B-side change**.
- The target is chosen at **runtime** (env-selected), portable across
  environments where B's path/audience differs.
- **B may be `spec.internal: true`** — indeed that is the primary B-to-B target
  — and its audience must still resolve.
- No `kdex-crds` schema change (avoids the release-all-actors cascade); ships as
  a `host-manager` release plus an `fngogen` release.

## Non-goals

- **Non-escalation / on-behalf-of guarantees.** Out of scope for v1 by explicit
  decision. (The chosen mechanism happens to carry the *user's* re-resolved
  entitlements anyway — see Security model — but we are not committing to that as
  a guarantee, and B enforces its own entitlements regardless.)
- **A typed client for B** generated from B's OpenAPI. YAGNI — the handler calls
  B with any HTTP client.
- **Calling B *through* the host proxy.** Explicitly the direct path only.

## Decision

Add an **RFC 8693 token-exchange grant** to the host token endpoint. The handler
presents the **inbound FAT it already holds** as the `subject_token`; the FAT
itself is the authentication, so **no per-function client_id/secret is
provisioned**. A self-declared **env** on the calling function names the target;
host-manager resolves it to B's audience and mints a fresh `aud=B` JWT.

Rejected alternative — **client_credentials with a `resource` indicator**: it
would authenticate A with its own client credentials and mint a token carrying
**A's** entitlements (the grant's subject is the client — `internal/auth/exchange.go`
~L704), and it requires provisioning and rotating a client secret per function.
Token-exchange keyed on the FAT needs neither, and lets the handler "initiate the
flow with the request token" as intended.

## Components

### 1. host-manager — token-exchange grant at `/-/token`

Add `urn:ietf:params:oauth:grant-type:token-exchange`, advertised in
`grant_types_supported`.

**Request parameters (RFC 8693):**

| param | value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | the caller's inbound FAT |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` (JWT) |
| `resource` | the target: B's basePath, or issuer+basePath (RFC 8707) |

**Validation of `subject_token`:**

- Verify it is **host-signed** (host active key / JWKS), `iss` = host issuer,
  and unexpired. Any host-issued JWT (i.e. a real FAT) is an acceptable subject.
- Extract `sub`. A subject_token with no `sub` (anonymous call to A) → reject
  (`invalid_request`); there is no identity to re-resolve.

**Validation of `resource` (target audience):** see Component 2.

**Minting:** re-resolve the subject's roles/entitlements
(`ResolveInternalRolesAndEntitlements(sub)` — the #105 path every other grant
uses) and sign a **JWT** with `aud` = the resolved B audience, `iss` = host,
applying the host's `claimMappings` — the same projection the proxy FAT mint
performs, so B accepts it unchanged. Short TTL (reuse the signer duration used
for FATs). Include an **`act` (actor) claim** naming the calling function
(derived from the subject_token's `aud`) for audit/delegation legibility
(RFC 8693 §4.1).

Errors follow RFC 6749 §5.2 / RFC 8693 §2.2.2 JSON shape: unknown/disallowed
target → `invalid_target`; bad subject_token → `invalid_request`; resolver
failure → `server_error` (mirroring `internal/auth/exchange.go`'s existing
error discipline, #168).

**Reuses:** the per-audience signer pattern, `ResolveInternalRolesAndEntitlements`,
`sign.Project`, and the token endpoint's existing dispatch.

### 2. host-manager — target resolution (`resource` → B's audience), internal-inclusive

This is the load-bearing correctness point (raised in review): **B may be
`spec.internal: true`.**

- **Do NOT reuse `oauth2ResourceAudiences()`** (`internal/host/oauth2_resources.go`).
  It is built from `oauth2ProtectedResources()`, which **skips `fn.Spec.Internal`
  and any non-oauth2-protected function** (L40). Gating the exchange on it would
  reject internal targets — exactly the ones we want.
- Introduce a dedicated resolver — `exchangeTargetAudiences()` (or
  `functionAudienceByBasePath()`) — over **all `Ready` `KDexFunction`s on the
  host, `Spec.Internal` included**, mapping both `basePath` and
  `issuer + basePath` → `fatAudienceFor(fn)`.
- Mint for the resolved `fatAudienceFor(fn)`. For a Knative function
  (`Spec.Backend == nil`, true for internal functions) that is its cluster-local
  `Status.URL`, which is exactly the value B's `AUDIENCE` env is set to
  (`internal/deploy/deploy.go`, `internal/host/host.go`) — so exchange-minted and
  proxy-minted audiences are guaranteed identical because both flow through the
  single `fatAudienceFor` source of truth.
- A `resource` that resolves to no Ready function on this host → `invalid_target`.

**Why a global (not per-caller) target set is acceptable:** the minted token
carries the subject's own entitlements and **B enforces them on its bearer
path**, so naming an audience is not a privilege grant — a caller cannot do
anything at B the user couldn't. The resolver is hygiene (no minting for unknown
audiences), not an authorization boundary. (A per-caller allowlist can be layered
later if a future requirement reintroduces non-escalation; it is out of scope
here.)

### 3. fngogen — flow the raw inbound token to handlers

Today the generated `HandleBearer` stores only the parsed **claims** in the
request context (`UserContextKey` → `jwt.MapClaims`,
`kdex-fngogen/cmd/templates/main.go.tmpl` ~L242/L418); the raw `t.Token` is
never propagated, so a handler cannot initiate an exchange.

Change: in the generated security handlers, also stash the **raw bearer token
string** in the context under a new key (`RequestTokenContextKey`), alongside the
existing claims, and expose an accessor (e.g. `RequestTokenFromContext(ctx)`).
Small, regenerate-safe template change (it lives in the generated `main.go`, not
`custom.go`). Add a golden/template test asserting the raw token reaches `ctx`.

### 4. fngogen — the `Exchange()` helper (runtime lib)

Ship a small **importable runtime library** (versioned once, not copy-generated
into every `cmd/`) providing:

```go
// Exchange trades the inbound request token (from ctx) for a JWT
// addressed to `resource`, caching by (sub, resource).
func Exchange(ctx context.Context, resource string) (token string, err error)
```

It reads the raw token from `ctx` (Component 3) and the token endpoint from env
(`ISSUER` + `/-/token`, or a dedicated `TOKEN_ENDPOINT`), POSTs the RFC 8693
form, caches the result under `(sub, resource)` with a TTL below the token
lifetime (mirroring the proxy FAT cache skew), and returns the `aud=B` JWT. The
handler then attaches it to its own outbound HTTP call to B.

Generated code and `custom.go` both import this lib; the auth mechanics live in
one place.

### 5. Function configuration (env; no CRD change)

An outbound-calling function is configured purely by env:

- **Token endpoint** — reuse `ISSUER` + `/-/token`, or a `TOKEN_ENDPOINT` env.
- **Target(s)** — the function self-declares the target `resource` value(s) via
  its own env (e.g. `KDEX_OUTBOUND_<NAME>=/v1/other`). The handler passes that
  string to `Exchange()`.

No `client_id`/`client_secret`, no new `KDexFunction` field, **no `kdex-crds`
change.**

## Security model

- **Authentication of the exchange** is the `subject_token`: only a valid,
  unexpired, host-signed FAT can drive it. A handler only holds such a FAT while
  serving a real authenticated request.
- **The minted token carries the subject's re-resolved entitlements**, and **B
  enforces its own operation entitlements** on the bearer path. So the exchange
  grants no authority beyond what the user already has at B. This holds for
  `spec.internal` targets too: an internal fngogen function still validates
  `aud`/`iss`/JWKS; operations with no `security` requirement pass the
  entitlement check trivially, which is the intended internal-function posture.
- **No standing credential** to leak or rotate (no per-function secret).
- Non-escalation is explicitly *not* a v1 guarantee, but nothing here weakens B's
  own enforcement.

## Testing

- **host-manager (`internal/auth`, `internal/host`):**
  - valid FAT + known `resource` → `aud=B` JWT carrying entitlements, `iss`=host.
  - `resource` resolving to an **`spec.internal` Ready** function → success (the
    review check — explicit test).
  - unknown/absent `resource` → `invalid_target`.
  - forged / expired / no-`sub` subject_token → reject with correct error code.
  - exchange-minted `aud` == `fatAudienceFor(target)` == proxy-minted `aud`
    (drift guard).
- **fngogen:** golden/template test that the raw token reaches `ctx`;
  `Exchange()` unit tests (cache by `(sub,resource)`, endpoint resolution,
  error propagation).
- **e2e:** FunctionA handler calls `Exchange()` then hits FunctionB directly;
  B validates and serves; repeat with B `spec.internal: true`.

## Rollout

1. `kdex-host-manager` release: token-exchange grant + internal-inclusive target
   resolver + discovery advertisement.
2. `kdex-fngogen` release: raw-token-in-context + `Exchange()` runtime lib.
3. No `kdex-crds` change → no release-all-actors cascade.
4. Functions opt in by adding the target env(s) and calling `Exchange()` in
   `custom.go`; regenerate to pick up the context change.

## Open questions

- Exact env naming convention for targets (`TOKEN_ENDPOINT` vs derive from
  `ISSUER`; `KDEX_OUTBOUND_*` shape). Cosmetic; settle during implementation.
- Where the `Exchange()` runtime lib lives (a new small module vs a home in an
  existing shared kdex Go module). Decide at plan time per the DEPENDENCY rule.

## References

- `kdex-host-manager/internal/host/proxy.go` — `fatAudienceFor`, FAT mint, #90
  credential stripping.
- `kdex-host-manager/internal/auth/exchange.go` — grant implementations,
  `MintResourcePAT`, `ResolveInternalRolesAndEntitlements`, error discipline.
- `kdex-host-manager/internal/host/oauth2_resources.go` — `oauth2ProtectedResources`
  (the internal-skipping set the exchange must NOT reuse).
- `kdex-host-manager/internal/auth/discovery.go` — `grant_types_supported`.
- `kdex-fngogen/cmd/templates/main.go.tmpl` — `HandleBearer`, `UserContextKey`,
  `AUDIENCE`/`ISSUER`/`JWKS_URL` env contract.

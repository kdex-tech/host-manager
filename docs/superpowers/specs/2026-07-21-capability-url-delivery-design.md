# Capability-URL delivery — credential-less download-by-URL for `mint_token`

- **Date:** 2026-07-21
- **Tracking issue:** kdex-tech/host-manager#151 (Axis B — capability-URL delivery)
- **Status:** design approved, ready for implementation plan
- **Builds on:** [`2026-07-01-mint-token-mcp-capability-design.md`](./2026-07-01-mint-token-mcp-capability-design.md) (the base `mint_token` capability, shipped v0.4.0)

## Summary

Extend `mint_token` so a caller can mint a capability as a **redeemable URL**
instead of only a bearer token. The URL — `https://<host>/-/transfer/<handle>` —
pins **one concrete download operation** (method + path, e.g.
`GET /api/v1/files/<id>/content`) and is redeemable by a **credential-less**
recipient: a browser, a plain `curl`, an emailed or chat-shared link. No
`Authorization` header, no pre-installed credential.

```
mint_token({
  entitlements: string[],
  ttl_seconds?, uses?,
  delivery?: "bearer" | "url",             // NEW; default "bearer"
  target?: { method: string, path: string } // NEW; required when delivery=="url"
})
  -> { token?, url?, expires_at, entitlements, uses_remaining }
```

This is the classic secure-file-transfer shape — an S3/GCS-presigned-URL analog
— realized on top of the existing attenuated, bounded-use capability machinery.
The opaque `<handle>` maps back to the authorization through a **server-side
handle** stored in the host's existing cap cache, so the URL itself carries **no
credential**. `mint_token`'s existing attenuation, TTL/uses clamps, and
`kdx_cap` budget counter are reused verbatim; the only net-new enforcement is the
redemption route. **knowdb requires no changes.**

## Scope

### In scope

- **Download-by-URL.** `delivery:"url"` binds one concrete download target;
  `GET /-/transfer/<handle>` redeems it, re-dispatching the target request as the
  minted identity and streaming the bytes back.

### Out of scope (named follow-ons)

- **Upload-by-URL.** The upload target is body-/session-derived and therefore
  **AS-underivable** (readability ≠ authority) until knowdb exposes a
  path-addressable upload session whose id sits in the URL path. Requires backend
  cooperation. Issue #151 Q2/Q5. Follow-on spec.
- **Bearer-form in-JWT file caveats (full Axis A).** Confining the *bearer* token
  itself to one file, enforced at the proxy for header-delivered tokens. This
  spec confines the *URL* form via the server-side handle's bound target; the
  in-JWT caveat that also narrows the bearer form is the next spec. Issue #151
  Axis A / Q1.
- **Object-path / content-hash binding.** A `file_id` (or any concrete path) in
  `target.path` is sufficient here. Issue #151 Q6.

## Grounding facts (verified against source)

Three facts about the shipped system determine the design.

### Fact 1 — the proxy authorizes from `AuthContext`, not only from an inbound JWT

The function proxy resolves the caller's entitlements via
`AuthorizationChecker.GetParsedEntitlements(ctx)`
(`internal/auth/authorization.go:73`), which reads `GetAuthContext(ctx)`
(`internal/auth/context.go`). Any handler that populates the `AuthContext` via
`SetAuthContext` and then dispatches to the function-proxy path gets the full
identity-gate + per-op `security` check + downstream FAT re-mint **for free** —
the same reason the PASETO-PAT bridge already works without a host-audience JWT.

Consequence: redemption does not need to synthesize an inbound bearer token. It
builds an `AuthContext` from the stored claims, injects it, and re-dispatches.

### Fact 2 — the `kdx_cap` budget is a single atomic decrement keyed by `jti`

The bounded-use chokepoint lives in `WithAuthentication`
(`internal/auth/middleware.go:273-289`): a token carrying the `CapUsesClaim`
marker (`"kdx_cap"`, `middleware.go:19`) triggers
`MintCapCache.DecrementIfPositive(ctx, "uses:"+jti)`; `!ok` → reject
(fail-closed). The counter is provisioned at mint time in
`mintCapabilityToken` (`internal/host/mint_token.go:159-170`).

Consequence: the budget mechanism is credential-source-agnostic. URL redemption
reuses the identical `DecrementIfPositive("uses:"+jti)` call; it simply runs it
in the redemption handler (there is no inbound token for the outer middleware to
key off).

### Fact 3 — `WithAuthentication` runs before routing, so it cannot see `target`

The outer auth middleware runs before the `ServeMux` matches a route, so it never
sees a `{file_id}` path variable. The redemption route is registered as an
ordinary `/-/transfer/<handle>` handler; it owns the target dispatch itself
rather than relying on the pre-routing middleware.

## Architecture

### Component: mint surface (extends `mint_token`, `internal/host/mint_token.go`)

`MintTokenRequest` gains two optional fields; `MintTokenResult` gains one:

```go
type MintTokenRequest struct {
    Entitlements []string       `json:"entitlements"`
    TTLSeconds   int            `json:"ttl_seconds,omitempty"`
    Uses         int            `json:"uses,omitempty"`
    Delivery     string         `json:"delivery,omitempty"` // "bearer" (default) | "url"
    Target       *TransferTarget `json:"target,omitempty"`  // required when Delivery=="url"
}

type TransferTarget struct {
    Method string `json:"method"` // e.g. "GET"
    Path   string `json:"path"`   // e.g. "/api/v1/files/abc123/content"
}

type MintTokenResult struct {
    Token         string   `json:"token,omitempty"` // bearer delivery
    URL           string   `json:"url,omitempty"`   // url delivery
    ExpiresAt     int64    `json:"expires_at"`
    Entitlements  []string `json:"entitlements"`
    UsesRemaining int      `json:"uses_remaining"`
}
```

- `Delivery` omitted / `"bearer"` → **byte-for-byte today's behavior**; returns
  `Token`. Full back-compat.
- `Delivery == "url"`:
  1. Reject if `spec.auth.mintToken.urlDelivery` is false (feature off).
  2. Reject if `Target` is nil.
  3. **Attenuate** the requested entitlements exactly as today
     (`VerifyAttenuation(held, requested)`).
  4. **Fail-fast target pre-check (best-effort).** Resolve `Target.Path` against
     the registered function routes to find the owning function's
     `spec.api.basePath`, and verify the attenuated set satisfies the identity
     gate `functions:<basePath>:read` (the proxy identity gate is **always
     verb `read`**, independent of HTTP method — see the two-tier authz rule).
     Reject the mint if it can't pass, so the caller gets an immediate error
     rather than a dead link. This is best-effort: if mint-time route resolution
     is impractical, it may be simplified or skipped — the redeem-time identity
     gate (a `404`) is the guaranteed backstop. Full per-op `security` (whose
     verb may differ from `read`) is always a redeem-time check; the AS does not
     enumerate every op's scopes at mint time.
  5. Clamp `ttl`/`uses` with the **existing** `MintTokenTTLCap` /
     `MintTokenUsesCap` / destructive-verb rule, then **force `uses = 1`**
     (config-free, mirrors the existing `hasDestructiveVerb` forcing block).
  6. Sign the host-audience JWT and provision `uses:<jti>` exactly as today.
  7. Generate the handle, store the transfer record (below), and return `URL`
     (no `Token`).

The MCP `tools/list` descriptor (`mintTokenDescriptor`, `mint_token.go:268`)
grows `delivery` + `target` in its `inputSchema`, and its description gains one
sentence on URL delivery.

### Component: the transfer handle (server-side, in the existing cap cache)

On a `delivery:"url"` mint:

- `handle = base64url(32 random bytes)` — 256-bit, unguessable.
- Store in the existing `cap` cache (`hh.cacheManager.GetCache("cap", …Uncycled)`,
  same store the budget counter uses), self-expiring at the token TTL:

  ```
  transfer:<handle>  ->  { jti, sub, entitlements[], target:{method,path} }
  ```

- **Claims-only.** The signed JWT is *not* stored and not embedded in the URL —
  the stored claims are sufficient to rebuild the redemption `AuthContext`, and
  the handle's unguessability + the Valkey entry *is* the credential. Downstream
  enforcement (identity gate, per-op `security`, knowdb `is_allowed`) re-checks
  the entitlements regardless, so a stored signature would add nothing. (If a
  future requirement wants signature re-validation at redeem, persist the compact
  JWT alongside; not needed now.)
- **Revocation** = delete the `transfer:<handle>` key.
- The `uses:<jti>` budget counter is provisioned as today (value 1), so redemption
  decrements through the identical atomic path.

### Component: redemption route `/-/transfer/<handle>` (host-manager)

Registered under the reserved `/-/` prefix (never proxied to a function; the
sniffer already skips `/-/…`). Registered on the host `ServeMux` next to the
other `/-/…` system handlers (`internal/host/handlers.go`). It accepts the HTTP
method its stored target requires (GET for download).

```
GET /-/transfer/<handle>
  1. Look up transfer:<handle> in the cap cache. Missing/expired -> 410 (see below).
  2. Method guard: request method must equal target.method, else -> 410.
  3. DecrementIfPositive("uses:"+jti). !ok -> 410. [spend-on-attempt, as bearer]
  4. Build AuthContext{ sub, entitlements } from the stored claims; SetAuthContext.
  5. Rewrite the request: r.Method, r.URL.Path := target.method, target.path.
  6. Invoke the function-proxy path directly (NOT the outer WithAuthentication
     middleware — there is no inbound token to re-authenticate).
  7. Proxy identity gate + per-op security check run against the injected
     entitlements (Fact 1); FAT re-mint -> knowdb streams the bytes back through
     the existing stream-safe proxy path.
```

Everything a normal authenticated download does runs unchanged; redemption only
swaps the credential source (inbound bearer JWT → handle-resolved `AuthContext`)
and moves the budget decrement into the redemption handler.

**Non-redeemable response.** All non-redeemable cases — unknown handle, spent,
expired, wrong method — return an **identical `410 Gone`** with a short plain
body ("This transfer link is no longer valid."). Uniformity preserves
anti-enumeration (no distinguishing "never existed" from "spent"); a `410` (over
a bare `404`) is chosen because the 256-bit handle makes enumeration a non-threat
and a human who clicks a dead link deserves a legible message. This is the one
place the design deliberately diverges from the proxy's anti-enum `404`.

### Component: opt-in policy (`KDexHost.spec.auth.mintToken.urlDelivery`)

One new field on the **existing** `MintToken` CRD type
(`kdex-crds/api/v1alpha1/kdexhost_types.go`):

```yaml
spec:
  auth:
    mintToken:
      enabled: true          # existing — gates bearer minting
      ttlCapSeconds: 60      # existing — reused for URL TTL (no separate URL cap)
      usesCap: 32            # existing
      destructiveVerbs: [delete, own]   # existing
      urlDelivery: false     # NEW — must be true to permit /-/transfer links
```

- `urlDelivery` defaults **false**: minting bearer tokens does not imply handing
  out credential-less links — a distinct risk posture, so a host opts in
  explicitly. `delivery:"url"` when false → mint error.
- `target` is a runtime MCP-tool input field, **not** CRD; the only CRD change is
  this one bool.
- Resolved into `Config` in `applyMintTokenPolicy` (`internal/auth/config.go:345`)
  as a new `MintTokenURLDelivery bool`.
- **CRD propagation.** Adding `urlDelivery` is a `kdex-crds` change: run
  `./updateCrdUsage.sh -t -n` to release **both** host-manager and nexus-manager
  (an old nexus build would prune the unknown field on CR round-trip —
  see the "CRD schema change → release ALL actors" invariant), and observe the
  two-commit plan-time-validation rule (land the CRD field, then the code that
  uses it).
- **Alternative considered:** gate URL delivery on the existing `enabled` and add
  zero CRD fields. Rejected to keep an explicit URL opt-out, but this collapse is
  a clean fallback if the CRD churn is unwanted.

## Data flow

Minting a download URL (through the connector, as today):

```
MCP connector --(resource PAT)--> host-manager proxy
  PAT bridge resolves held set into authContext
  intercept tools/call name=mint_token (delivery="url"):
    require urlDelivery policy + target
    attenuate (requested ⊆ held)
    fail-fast (best-effort): resolve target.path -> function basePath;
      attenuated set satisfies functions:<basePath>:read (identity gate is always verb read)
    clamp ttl/uses (existing caps); force uses=1
    sign host-audience JWT (entitlements=requested, kdx_cap marker, jti)
    provision uses:<jti>=1 (TTL=ttl)
    handle=random(32B); store transfer:<handle>={jti,sub,entitlements,target} (TTL=ttl)
    return { url: https://<host>/-/transfer/<handle>, expires_at, entitlements, uses_remaining:1 }
```

Redeeming (credential-less recipient):

```
browser/curl --(plain GET, no credential)--> host-manager /-/transfer/<handle>
  lookup transfer:<handle>            (410 if missing/expired)
  method guard == target.method       (410 if not)
  DecrementIfPositive(uses:<jti>)      (410 if spent/exhausted; fail-closed)
  AuthContext{sub, entitlements} -> SetAuthContext
  rewrite request to target.method target.path
  dispatch function-proxy path directly:
    proxy identity gate + per-op security (against injected entitlements)
    FAT re-mint -> knowdb auth::entitlements::is_allowed
    stream file bytes back
```

## Error handling

| Case | Result |
|---|---|
| `delivery:"url"` but `urlDelivery=false` | mint error (feature off) |
| `delivery:"url"` but `target` nil | mint error (target required) |
| `target` not authorized by attenuated entitlements | mint error (fail-fast identity-gate pre-check) |
| malformed `target.path` / unsupported method | mint error |
| requested ⊄ held | mint error (existing attenuation, names the offender) |
| redeem: handle missing / spent / expired / wrong method | uniform **410 Gone** (anti-enum) |
| redeem: cap cache unreachable | fail-closed (treated as exhausted → 410) |
| redeem: target op's `security` verb unsatisfied | proxy's normal 404 identity-gate / 403 |

**Spend-on-attempt**, not spend-on-success: the use is decremented at redeem
before the backend round-trip, so a redeem the backend later fails still spent the
use. A capability budget is "N authenticated attempts," consistent with the
bearer path. Documented as tool behavior.

## Testing

- **Mint (unit):** `delivery:"url"` returns `url` and omits `token`; forces
  `uses=1`; missing `target` → error; `urlDelivery=false` → error; attenuation
  still rejects over-broad requests; fail-fast rejects a target the attenuated
  entitlements can't reach; `delivery` omitted → unchanged bearer result.
- **Handle lifecycle:** stored under `transfer:<handle>` with TTL = token ttl;
  single decrement; second redeem → 410; TTL expiry → 410; revoke (key delete)
  → 410.
- **Redemption:** re-dispatch targets exactly `target` (a different path is never
  reachable); method guard rejects a mismatched method; an authorized target
  streams bytes; a target outside the attenuated set 404s at the proxy; the
  injected `AuthContext` reaches `GetParsedEntitlements`.
- **Opt-in gating:** URL delivery unavailable when `urlDelivery=false` even with
  `mintToken.enabled=true`.
- **Anti-enum:** identical 410 for missing vs spent vs expired vs wrong-method.
- **Integration:** end-to-end download-by-URL through the proxy to a function /
  knowdb stub streams the file; the SSE/stream passthrough path is unaffected;
  the bearer mint path is unchanged (regression).

## Phasing (build order; same end state)

1. **Mint surface + handle + redemption (download).** `delivery`/`target` request
   fields, `url` result field, handle storage in the cap cache, the
   `/-/transfer/<handle>` route with lookup → method guard → decrement →
   AuthContext inject → re-dispatch. Reuses the existing attenuation, clamps, and
   budget counter. This is the flagship, reviewable increment.
2. **Policy field.** `spec.auth.mintToken.urlDelivery` (CRD addition + propagation
   + `applyMintTokenPolicy` wiring). Can land first as a no-op gate if the CRD
   two-commit rule pushes it ahead of the code that reads it.

## Reuse (net-new surface is small)

Reused verbatim: attenuation (`VerifyAttenuation`), the FAT signer, the
`kdx_cap` marker + `DecrementIfPositive` budget path, inbound/downstream
enforcement (proxy identity gate, per-op `security`, knowdb `is_allowed`), the
`AuthContext` inject/read plumbing (`SetAuthContext` / `GetParsedEntitlements`),
and the Valkey-backed cap cache. Net-new: two request fields + one result field on
`mint_token`; the `transfer:<handle>` record; the `/-/transfer/<handle>`
redemption handler; and the `spec.auth.mintToken.urlDelivery` opt-in bool.

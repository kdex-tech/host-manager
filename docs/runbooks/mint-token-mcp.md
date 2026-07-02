# Runbook — `mint_token` MCP capability

**Feature:** an Authorization-Server-owned MCP tool that lets a caller riding an
MCP connector mint a **short-lived, attenuated, bounded-use capability token**
(a host-audience JWT carrying a subset of the caller's own entitlements) for
credential-less use against the host / knowdb REST surface.

**Shipped in:** host-manager `v0.4.0` · kdex-crds `v0.14.226`
(`spec.auth.mintToken`) · kdex-entitlements `go/v0.2.1` (directional
`VerifyAttenuation`). Tracking: recoursellm-group/multi-modal-store#280.

**Design rationale (why this shape):** see
[`docs/superpowers/specs/2026-07-01-mint-token-mcp-capability-design.md`](../superpowers/specs/2026-07-01-mint-token-mcp-capability-design.md).
This runbook is the operator view: enable, configure, use, verify, troubleshoot.

---

## 1. Mechanism in one page

`host-manager`'s reverse proxy intercepts **two** JSON-RPC methods on an
OAuth2-protected `KDexFunction` route when the feature is enabled. Everything
else on that route (every knowdb tool, the SSE `GET` stream, `initialize`,
`prompts/*`, `resources/*`) is opaque passthrough.

| On the wire | host-manager does |
|---|---|
| `tools/list` response | **splices** the `mint_token` descriptor into `result.tools` (via `ModifyResponse`) so connectors discover it. knowdb's own tools are untouched. |
| `tools/call` with `name == "mint_token"` | **handled locally, never forwarded** to knowdb. Mints the token and returns the JSON-RPC result. |

Minting (`internal/host/mint_token.go` → `mintCapabilityToken`):

1. **Attenuate** — `entitlements.VerifyAttenuation(held, requested)`. Every
   requested entitlement must be *dominated* by a held one. Wildcards are honored
   **only on the held side** (holding `vector_stores::write` can mint
   `vector_stores:X:write`; holding `vector_stores:X:write` **cannot** mint
   `vector_stores:*:write`). The caller's **held** set is what the PAT bridge
   already resolved into `authContext` by the time the call reaches the proxy.
2. **Clamp** `ttl_seconds` → `MintTokenTTLCap`; `uses` → `MintTokenUsesCap`
   (silent clamp, reflected in the response — never an error).
3. **Destructive-verb policy** — if any requested verb is in
   `destructiveVerbs` (or is a `*`/`all` wildcard), force `uses = 1` and cap ttl
   at 10s.
4. **Sign** a **host-audience** JWT: `aud = KDexHost FQDN`, `sub = caller`,
   `entitlements = requested set`, plus the marker claim `kdx_cap: true`
   (injected via `Project` → `SignProjected`, because the signer's claim
   allowlist would otherwise drop it). This host audience is the linchpin:
   `WithAuthentication` trusts a host-audience JWT's `entitlements` claim
   verbatim, so no new enforcement code is needed downstream.
5. **Provision the budget** — write `cap:uses:<jti> = uses` into the Valkey-backed
   `"cap"` cache with TTL = the token ttl.

Consuming (any off-context process, no prior credential):

```
process --(Authorization: Bearer <minted JWT>)--> host-manager
  WithAuthentication: validate sig + aud(host); entitlements trusted verbatim
  if kdx_cap marker present: DecrementIfPositive("uses:"+jti); !ok -> 401
  route to KDexFunction; proxy identity gate + per-op check enforce the
    attenuated entitlements; downstream FAT re-mint carries them to knowdb
```

Decrement is **spend-on-attempt** (charged at authentication, before the
backend round-trip) and **fail-closed** (missing/exhausted counter → `401
capability exhausted`).

---

## 2. Prerequisites

The tool appears and works only when **all** of these hold:

1. **Auth is on for the host.** `KDexHost.spec.auth` must be configured — page/
   route security and `WithAuthentication` are no-ops otherwise.
2. **The MCP function is OAuth2-protected.** Interception gates on
   `fh.oauth2Protected` (detected via `oauth2ProtectedResources()`). A plain
   unauthenticated function is never augmented.
3. **The feature is enabled** on the host (§3).
4. **Valkey is reachable** by host-manager. The `"cap"` cache backs the
   bounded-use counter; with no cache manager, bounded tokens cannot be
   provisioned and consuming them fails closed. (ttl-only tokens still mint, but
   `uses` defaults to 1 and every mint provisions a counter, so Valkey is
   effectively required for the feature to be useful.)

---

## 3. Enable + configure

Add the `mintToken` block under `KDexHost.spec.auth` (infra TF — this is a host
CR field):

```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexHost
spec:
  auth:
    # ... existing auth config (issuer, keys, oauth2, etc.) ...
    mintToken:
      enabled: true
      ttlCapSeconds: 60              # hard ceiling on ttl_seconds
      usesCap: 32                    # hard ceiling on uses
      destructiveVerbs: [delete, own]  # these verbs force uses=1 + 10s ttl
```

**Field reference** (`kdex-crds` `MintToken`, applied by
`internal/auth/config.go:applyMintTokenPolicy`):

| Field | Type | Default when unset/≤0 | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. When false the whole block is inert. |
| `ttlCapSeconds` | int | `60` | Hard ceiling; a larger `ttl_seconds` request is clamped down. |
| `usesCap` | int | `32` | Hard ceiling on `uses`. |
| `destructiveVerbs` | []string | `[delete, own]` | Verbs that force `uses=1` and ttl ≤ 10s. A requested `*`/`all` verb always triggers this too. |

Notes:
- `enabled: false` (or omitting the block) leaves `MintTokenEnabled` false — the
  route is untouched and the descriptor never appears.
- Defaults apply **per field**: setting only `enabled: true` yields
  60s / 32 uses / `[delete, own]`.
- **CRD propagation / two-commit rule:** this field shipped in
  `kdex-crds v0.14.226`. If a cluster's live CRD predates it, `tofu plan`
  validates `kubernetes_manifest` against the live schema and will reject the
  field — bump the CRD first, then use it in a second apply.

---

## 4. Use it (end to end)

### 4a. Discover the tool

Any MCP client on the connector sees `mint_token` in `tools/list`:

```json
{ "name": "mint_token",
  "description": "Mint a short-lived, attenuated capability token ...",
  "inputSchema": { "type": "object", "required": ["entitlements"],
    "properties": {
      "entitlements": { "type": "array", "items": {"type":"string"} },
      "ttl_seconds":  { "type": "integer" },
      "uses":         { "type": "integer" } } } }
```

### 4b. Mint (through the connector — `tools/call`)

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": { "name": "mint_token",
    "arguments": {
      "entitlements": ["functions:/api/v1/files:write", "functions:/api/v1/files:read"],
      "ttl_seconds": 60,
      "uses": 10 } } }
```

Success result (`structuredContent`):

```json
{ "token": "<host-audience JWT>",
  "expires_at": 1751500000,
  "entitlements": ["functions:/api/v1/files:write", "functions:/api/v1/files:read"],
  "uses_remaining": 10 }
```

Domain failures (attenuation, empty entitlements, disabled) come back as an MCP
tool error — HTTP `200` with `isError: true` and a text explanation — **not** a
JSON-RPC transport error.

### 4c. Consume (off-context, no prior credential)

```bash
curl -H "Authorization: Bearer $TOKEN" \
     -X POST https://<host-fqdn>/api/v1/files ...
```

Each authenticated request decrements the budget by one. When it hits zero (or
the ttl expires) the token stops working.

---

## 5. Verify (smoke test)

1. **Descriptor present:** call `tools/list` on the MCP function; assert
   `mint_token` is in `result.tools` and knowdb's tools are still there.
2. **Mint within held set:** `tools/call mint_token` with an entitlement you
   hold → non-empty `token`, `uses_remaining` = clamped `uses`.
3. **Attenuation rejects:** request an entitlement you do **not** hold → tool
   error `entitlement not held by caller: <offender>`.
4. **Verbatim enforcement:** use the token against a route inside the attenuated
   set → success; against a route outside it → `403/404`.
5. **Budget exhausts:** with `uses: 1`, the second request → `401 capability
   exhausted`.

---

## 6. Troubleshooting

| Symptom | Likely cause | Check / fix |
|---|---|---|
| `mint_token` absent from `tools/list` | feature disabled, function not OAuth2-protected, or auth off | verify `spec.auth.mintToken.enabled: true`, that the function is oauth2-protected, and `spec.auth` is set; confirm the deployed host-manager is ≥ v0.4.0 |
| tool call returns `mint_token is not enabled on this host` | `MintTokenEnabled` false at config-build time | the running host-manager loaded a `KDexHost` without the enabled block — reconcile/roll the host |
| `entitlement not held by caller: X` | requested `X` not dominated by held set | request only entitlements you hold; remember **wildcards narrow only** — you cannot widen a specific grant into a `*` capability |
| `mint_token requires an authenticated caller` | no `sub` in auth context | the connector PAT didn't resolve; check OAuth2/PAT bridge |
| minted token immediately `401 capability exhausted` on first use | counter never provisioned (Valkey unreachable at mint) **or** Valkey evicted/flushed the key | check host-manager → Valkey connectivity; short ttls + persistent Valkey make eviction rare; fail-closed is intentional — see known issue #1 |
| `uses_remaining` smaller than requested | clamped to `usesCap`, or a destructive verb forced `uses=1` | expected; raise `usesCap` or drop the destructive verb |
| ttl shorter than requested | clamped to `ttlCapSeconds`, or destructive-verb 10s cap | expected |
| bounded token works past its budget | **would be a bug** — decrement is a single chokepoint in `WithAuthentication`; confirm the token actually carries the `kdx_cap` marker and a `jti` |

---

## 7. Security properties (what this guarantees)

- **No privilege escalation via minting** — directional dominance means a minted
  token can only ever carry a subset of the caller's held authority; wildcards
  are honored only on the held side.
- **Host audience, trusted verbatim** — the narrowed `entitlements` claim is
  enforced end-to-end by existing gates (proxy identity gate, per-op security,
  downstream FAT re-mint, knowdb `is_allowed`) with zero new enforcement code.
- **Bounded** — ttl-capped and (for `uses>0`) budget-capped; destructive verbs
  are single-use and ultra-short-lived.
- **Fail-closed** — a missing/exhausted counter rejects; availability of a
  bounded token is bounded by the host's Valkey (the same dependency sessions
  already carry).
- **Spend-on-attempt** — a use is charged at authentication, before the backend
  round-trip; it is spent even if the backend then fails. A budget is "N
  authenticated attempts," not "N successful operations."

---

## 8. Known issues & limitations

1. **DOA-token edge (host-manager):** `mintCapabilityToken` swallows the
   counter-`Set` error and the jti re-parse error. If Valkey is briefly
   unreachable at mint time, a token is returned but is rejected fail-closed on
   first use. Consider fail-fast/log hardening. (Follow-up, not issue-tracked.)
2. **Per-VS grants not mintable via the connector (by design, Phase 1).** The
   connector authenticates with a resource-bound PASETO PAT whose held set is
   **static `KDexRoleBinding` grants only**. Dynamic per-vector-store
   `vs_entitlements` resolved at login (baked into the browser cookie JWT) are
   **not** re-resolved for the PAT, so `vector_stores:<id>:*` grants held only
   via the login Lookup are not mintable through the connector.
   `functions:*` route entitlements (including the flagship
   `functions:/api/v1/files:write|read`) mint fine. Unifying the held set is a
   broader PAT-bridge change, out of scope.
3. **JSON-RPC batching not intercepted.** MCP revision 2025-06-18 removed
   batching; only single-object bodies are intercepted. An array body is passed
   through untouched to knowdb.
4. **Oversized bodies pass through unintercepted.** POST bodies larger than
   `maxMintPeekBytes` (1 MiB) are forwarded without inspection (reconstructed via
   `io.MultiReader`, never truncated) — a `mint_token` call is tiny, so this only
   affects large knowdb payloads, which should pass through anyway.

---

## 9. Version matrix

| Component | Version | Provides |
|---|---|---|
| kdex-crds | `v0.14.226` | `KDexHost.spec.auth.mintToken` |
| kdex-entitlements (go) | `go/v0.2.1` | directional `Dominates` / `VerifyAttenuation` |
| kdex-host-manager | `v0.4.0` | interception, mint handler, bounded-use counter |

Deploy: the in-cluster kcnas-operator image must be ≥ these versions for the
feature to be live. As of last check the RSI-dev operator image lagged at
`0.3.52` — deploy host-manager `v0.4.1`+ (which also carries the #131
status-loop fix) to activate.

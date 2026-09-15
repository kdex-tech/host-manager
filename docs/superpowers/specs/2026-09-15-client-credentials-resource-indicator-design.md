# client_credentials honors an RFC 8707 resource indicator

**Date:** 2026-09-15
**Status:** Design — approved for planning
**Repos touched:** kdex-host-manager (the feature), enterprise-user-manager (small consumer change). No kdex-crds, no kdex-nexus-manager.

## Problem

A backend companion service that authenticates as its own identity via
`client_credentials` — with no inbound Function Access Token (FAT) to forward,
because it is triggered by an out-of-band event (e.g. an HMAC-signed login-event
webhook), not a proxied user request — has **no supported way to obtain a token
addressed to a peer function's audience.**

Concretely, on the public tenant (`host-manager:0.14.1`), enterprise-user-manager
(eum) provisions self-registering users into the `blobsqlite` peer. Its store
client (`enterprise-user-manager/functions/eum/store/client.go`):

1. mints a `client_credentials` token (`client_id=eum-blobsqlite`) — succeeds, but
   the token is stamped `aud=<host>` (`sign.Signer` default, `internal/sign/sign.go`;
   `LoginClient` sets no explicit aud);
2. RFC 8693-exchanges it for one addressed to blobsqlite's audience.

Step 2 now fails **400 `invalid_request` / "invalid subject_token"**. host-manager
v0.14.1's #212 hardening (`internal/auth/exchange.go`, `ExchangeSubjectToken`)
gatekeeps the exchange input to a genuine function-audience FAT:

```go
if len(auds) != 1 || auds[0] == e.config.Audience {
    return TokenSet{}, fmt.Errorf("subject_token is not a function access token")
}
```

A host-audience `client_credentials` token trips this gate. Verified live: eum logs
`self-reg provision failed … token exchange … (status 400): invalid_request invalid
subject_token` (recurring; login still allowed, "self-heals next login" — but the
self-heal re-runs the same failing exchange, so new users are never written to
blobsqlite).

**Why the alternatives don't work (verified against source + the live path):**

- **Revert to 0.14.0** — re-opens the #212 HIGH vuln fleet-wide. Stopgap only.
- **eum presents a genuine FAT to exchange** — not viable. There is no FAT to
  exchange: the login event is an HMAC webhook, not a proxied request, so eum's
  handler holds no inbound `authContext`/FAT. And even a proxy-minted FAT carries
  the *caller's* subject (the just-logged-in user, who holds no provisioning
  authority), re-resolved by the exchange — not eum's privileged identity. Nothing
  mints a token that is both `sub=eum-blobsqlite` **and** `aud=<function>`:
  `client_credentials` gives the right subject but host aud; the proxy gives a
  function aud but the caller's subject, and never returns a caller its own FAT.
- **eum uses the existing resource-PAT path** (`writeResourcePATResponse`,
  `internal/auth/oauth2.go`) — not eligible: it is gated to
  `authorization_code`/`refresh_token` (MCP delegated flows) and mints an
  **entitlement-less** PAT, which blobsqlite could not authorize the write from.
- **blobsqlite accepts host-aud tokens** — a security regression on its audience
  binding. Rejected.

The gap is structural and lives in the token **issuer**: there is no path for
host-manager to issue a peer-function-audience token to a confidential M2M client.

## Chosen approach

host-manager honors an RFC 8707 `resource` indicator on the `client_credentials`
grant. When a confidential `client_credentials` client presents `resource=<R>` and
`R` is both in that client's allowlist and a registered exchange target, host-manager
mints a **FAT-shaped, resource-audienced token** — `aud = fatAudienceFor(R)`, carrying
the client's re-resolved entitlements — instead of the default host-audience token.

eum then drops the RFC 8693 exchange step entirely and just adds `resource=<blobsqlite>`
to its existing `client_credentials` mint. The `client_credentials` token already
carries the correct subject (`eum-blobsqlite`); this lets that mint emit the
function-audienced token directly, collapsing the impossible "mint-a-self-FAT-then-
exchange" into one legitimate step.

### Why this is #212-safe

#212 closed **privilege re-inflation**: exchanging an already-narrowed or
host-audience token *up* to full authority. This design does not do that. The client
authenticates with its **client secret** and receives a token for its **own**
re-resolved authority — it never presents a narrowed credential to be re-expanded.
The failure direction of the whole feature is a from-scratch mint, gated by the
secret plus an explicit allowlist. The exchange gate itself is untouched.

### Decisions (locked during brainstorming)

1. **Per-client allowlist gate.** The auth-client Secret gains an `allowed-resources`
   key naming the resources that client may target. A mint is honored only if
   `resource ∈ client.AllowedResources` AND `resource ∈ ExchangeTargets`. This bounds
   lateral movement — a leaked client secret can mint peer-audience tokens only for
   the resources explicitly listed for that client. (Chosen over implicit parity with
   the exchange, and over a fuzzier mint-time entitlement check.)
2. **Fail loud on an unhonorable resource.** A `resource` that is present but not
   allowed / not registered returns **`invalid_target`** (RFC 8707 §2.2), never a
   silent downgrade to a host-audience token. Silent downgrade is what let the
   original failure hide.
3. **Full entitlements, no `act`.** The minted token carries the client's full
   re-resolved entitlements (parity with the exchange's DI-2 "not under-granted";
   the target function's own oauth2/entitlement checks remain authoritative
   downstream). No `act` claim — the client is itself the subject; there is no
   delegation actor.
4. **No CRD change.** Confidential clients are `kdex.dev/secret-type: auth-client`
   Secrets, not a CRD type; exchange targets are computed from Ready functions
   (`exchangeTargetAudiences`, `internal/host/oauth2_resources.go`). Nothing in
   `kdex.dev/v1alpha1` changes, so nexus-manager is not a released actor here.

## host-manager changes

### 1. Auth-client loader: read `allowed-resources`
- `internal/auth/loaders.go` — for each `kdex.dev/secret-type: auth-client` Secret,
  read a new optional `allowed-resources` data key (space/comma-separated resource
  values, each a basePath or the full issuer+basePath form), parse into a
  `[]string`, and carry it onto the loaded client config.
- The client config struct gains `AllowedResources []string` (whatever type
  `oauth2.go` resolves a client into — mirror how `AllowedGrantTypes` is carried).
- Empty/absent `allowed-resources` ⇒ the client may target no resources (a bare
  `client_credentials` mint still works and returns a host-aud token; only
  `resource=` requests are gated).

### 2. Token endpoint: honor `resource` on `client_credentials`
- `internal/auth/oauth2.go`, the token handler, `client_credentials` branch (after
  the grant succeeds and `resource := r.FormValue("resource")` is read).
- When `resource != ""`:
  - Resolve the client (already done for the grant). If
    `resource ∉ client.AllowedResources` OR `resource ∉ o.ExchangeTargets` →
    `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidTarget, "…")` and return.
    (`errCodeInvalidTarget = "invalid_target"` already exists — `internal/auth/oautherr.go:74`,
    used by the exchange path at `oauth2.go:598`; reuse it.)
  - Otherwise mint the resource-audienced token (below) and write it as the
    `access_token` in the standard token response.
  - `resource == ""` ⇒ unchanged: the existing host-audience `client_credentials`
    token.
- This is a **distinct** path from `writeResourcePATResponse` (which stays
  authz_code/refresh-only and entitlement-less). Do not route `client_credentials`
  through it.

### 3. The mint — reuse LoginClient's resolution, differ only in the signer audience
The resource-audienced token must carry **the same authority** the client's
host-audience `client_credentials` token would — so it must use the **same resolver**
`LoginClient` uses, NOT the exchange's `subjectSigningContext`. `LoginClient`
(`internal/auth/exchange.go`):
- sets `sub = azp = clientID`;
- resolves roles/entitlements via **`e.ResolveInternalRolesAndEntitlements(clientID)`**
  (scope-gated by `grantedScopes` — `wantRoles`/`wantEntitlements`);
- does **not** merge data-driven backend claims (a client grant carries roles +
  entitlements only);
- signs with the default (host-aud) `e.config.Signer.Sign(...)`.

Preferred implementation: **factor `LoginClient`'s context-building + resolution so
the only difference for the resource path is the signer's audience.** Concretely,
build the identical `signingContext` (`sub`/`azp`/`scope`/roles/entitlements), then:
- host-aud (`resource == ""`): `e.config.Signer.Sign(signingContext)` (today);
- resource-aud (`resource != ""`, gated): sign with
  `sign.NewSigner(targetAudience, e.config.TokenTTL, e.config.Issuer, &e.config.ActivePair.Private,
  e.config.ActivePair.KeyId, e.config.ClaimMapper)` then `.Sign(signingContext)`.

- **No `act`** (the client is itself the subject; no delegation actor).
- TTL: `e.config.TokenTTL` (same as the default grant and the exchange).
- The token is addressed to exactly `targetAudience` (= `ExchangeTargets[resource]`
  = `fatAudienceFor(target)`), so it is not replayable against the host or other
  functions.

This "one context, two audiences" factoring is the single source of truth that keeps
the resource-aud and host-aud tokens carrying identical authority as the grant
evolves.

## enterprise-user-manager change

- `functions/eum/store/client.go` — replace the two-step
  (`client_credentials` mint → `kdexauth.Exchange`) with a single `client_credentials`
  mint that includes `resource=<cfg.Resource>` (`BLOBSQLITE_RESOURCE`, already
  plumbed via `ConfigFromEnv`). Drop the exchange call and the `cachedExchToken` /
  `exchExp` fields; the mint's returned token is already blobsqlite-audienced.
- No change to how eum authenticates (still its own `client_credentials` identity).

## Ops (deploy-time, not code)

- The `eum-blobsqlite` auth-client Secret gains `allowed-resources: <blobsqlite
  resource>` (basePath or issuer+basePath form, matching what eum sends). Sourced
  wherever that Secret is defined (infra).

## Testing

**host-manager:**
- `client_credentials` + `resource` in the client's allowlist and a registered
  target → 200; decoded token `aud == fatAudienceFor(target)` and carries the
  client's entitlements (not empty, not host-aud).
- `resource` present but NOT in the client's `allowed-resources` → `invalid_target`.
- `resource` present, in the allowlist, but NOT a registered `ExchangeTarget` →
  `invalid_target`.
- `client_credentials` with **no** `resource` → host-aud token, byte-for-byte
  today's behavior (regression guard).
- **Identical-authority parity:** for the same client + scope, the resource-aud
  token and the host-aud token carry the same `sub`/`azp`/roles/entitlements — they
  differ only in `aud` (the "one context, two audiences" property).
- Loader parses `allowed-resources` (present / absent / multi-valued).
- The `ExchangeSubjectToken` #212 gate is untouched (existing exchange tests still
  pass).

**enterprise-user-manager:**
- store client issues a `client_credentials` request carrying `resource=` and no
  longer performs an RFC 8693 exchange; the returned token is used directly for
  blobsqlite calls.

## Rollout / release

1. kdex-host-manager: implement, `make test lint`, tag (new grant capability →
   minor bump, e.g. **v0.16.0**).
2. enterprise-user-manager: implement, its own test/lint, release (eum:0.5.x).
3. Deploy (user-driven infra): repin host-manager + eum on the public tenant, and
   add `allowed-resources` to the `eum-blobsqlite` Secret. Order: host-manager first
   (it must understand `resource` before eum sends it), then the Secret, then eum.
   Until eum is repinned it keeps using the old exchange, which stays broken — so
   this does not self-heal until eum ships too.

## Out of scope

- **Token-exchange RoleBindingClaim follow-up (ruling #5)** — a separate concern on
  the same #212 surface; not addressed here.
- Extending `resource`-targeting to `password` or other grants — only
  `client_credentials` needs it (the delegated grants already have the resource-PAT
  path).
- Any change to the #212 exchange gate itself — it stays exactly as shipped.

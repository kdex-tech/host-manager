# RoleBindingClaim: match role bindings on a human-authorable claim

**Date:** 2026-09-14
**Status:** Design — approved for planning
**Repos touched:** kdex-crds (CRD field), kdex-host-manager (resolution + config), kdex-nexus-manager (release-only, per the CRD-serialization rule)

## Problem

Google (and other OIDC IdPs) issue an **opaque, stable `sub`** — a numeric string
like `104187...`. `KDexRoleBinding.Spec.Subject` is matched against the login
subject, so today an operator binding a role to a Google user must author the
binding against that opaque number: unreadable, unknowable before the user's first
login, and impossible to write by hand for a human they mean to grant access to.

The natural human key is the **email**. The question is how to let role bindings
match on email without breaking the identity model that (correctly) relies on a
stable, non-reassignable `sub`.

## Why not "map email → sub"

Two rejected alternatives, and why:

1. **ClaimMappings rule setting `sub`.** The `ClaimMappings` mapper runs inside
   `sign.Signer.Project` as the *last* step of signing
   (`internal/sign/sign.go`), which does `maps.Copy(projected, mapperOutput)` with
   no reserved-claim filter — so it *can* overwrite `sub`. But role resolution
   (`FindInternalRolesAndEntitlements`) runs **earlier**, at
   `internal/auth/exchange.go` (`ExchangeToken` ~L663, `subjectSigningContext`
   ~L1667), against the raw opaque `sub`. Rewriting `sub` at signing time only
   changes the value printed in the emitted token; the roles were already resolved
   against the opaque number. Net effect: bindings would still have to be authored
   against the opaque `sub`, and the token's identity would be decoupled from the
   identity every internal resolver, the gate, and the refresh/auth-code paths
   used. It makes things worse. (This mapper-vs-reserved-claim gap is separately
   tracked as host-manager #211 and is **out of scope** here.)

2. **`SubjectClaim` config that changes `sub` to email at identity establishment.**
   Localized and consistent, but trades away the stability of `sub`: theft-detection
   lineage (#71), JIT provisioning, token-exchange subject resolution, `act`
   delegation, and audit attribution all key on `sub`, and email is
   mutable/reassignable (especially in Workspace, where a freed address can be
   reassigned and silently inherit grants).

## Chosen approach: a separate binding key, `sub` unchanged

Introduce a **binding key** distinct from the identity subject. `sub` stays the
opaque, stable identity everywhere; only `KDexRoleBinding` matching uses the
configured claim.

This is the correct conceptual split: **identity ≠ the RBAC-authoring key.** It
preserves every `sub`-stability invariant, avoids the #211 mapper gap entirely
(nothing rewrites `sub`), and — because the existing matcher already supports
regex (`internal/auth/roles.go` ~L118-126) — unlocks **domain-scoped bindings**
like `Subject: /@acme\.com$/`.

### Decisions (locked during brainstorming)

1. **Scope: global with `sub` fallback.** One host-level config value. Role
   resolution uses `claims[RoleBindingClaim]` when it is a non-empty string, else
   falls back to `sub`. Non-OIDC logins (local/PAT/CI) carry no `email` claim and
   so fall back to `sub`/username automatically. Default `RoleBindingClaim = "sub"`
   reproduces today's behavior byte-for-byte.
2. **Unverified email ⇒ no email roles, login still succeeds.** When the binding
   claim is `email` and verification fails, the binding key falls back to `sub`
   (typically matching nothing) rather than denying the login. Login ≠
   authorization: the user authenticates but receives no email-keyed grants. Fails
   closed on *authority* without breaking *authentication*.
3. **Auth-code path carries the binding key.** The authorization-code → token
   exchange re-resolves roles without a fresh IdP round-trip and does not currently
   carry IdP claims, so an IdP-claims snapshot is carried in the auth code —
   mirroring the refresh path's `idpc` — so the resolver applies identical
   binding-key logic on every path (see Threading below).

## CRD changes (kdex-crds)

Two additive, optional fields on `OIDCProvider` (`api/v1alpha1/types.go` ~L843).
Both are optional and default-safe, so existing CRs are unaffected.

```go
// roleBindingClaim is the OIDC/identity claim whose value KDexRoleBinding.Subject
// is matched against. Default "sub" preserves the historical behavior of matching
// the opaque provider subject. Set to "email" (with a provider like Google that
// issues an opaque numeric sub) so operators can author role bindings against a
// human-readable, regex-matchable value (e.g. an exact address or /@acme\.com$/).
// When the named claim is absent or empty for a given login (e.g. a local or PAT
// credential), matching falls back to "sub".
// +kubebuilder:validation:Optional
// +kubebuilder:default="sub"
// +kubebuilder:validation:MaxLength=256
RoleBindingClaim string `json:"roleBindingClaim,omitempty" protobuf:"bytes,6,opt,name=roleBindingClaim"`

// requireEmailVerified gates use of the email claim as the role-binding key on the
// presence of email_verified == true in the login claims. It only has effect when
// roleBindingClaim == "email". Unset defaults to TRUE (a pointer is used so that
// "unset" resolves to the SECURE value rather than Go's zero-value false): an
// unverified email is a role-authoring key an attacker could assert at a permissive
// IdP. Google satisfies this automatically. Set explicitly to false only for a
// trusted enterprise IdP that does not emit email_verified.
// +kubebuilder:validation:Optional
RequireEmailVerified *bool `json:"requireEmailVerified,omitempty" protobuf:"varint,7,opt,name=requireEmailVerified"`
```

Notes:
- Protobuf field numbers `6`/`7` follow the existing `oidcProviderURL` (4) and
  `scopes` (5).
- `RequireEmailVerified` is a pointer specifically so a missing field resolves to
  `true`. A plain `bool` with `+kubebuilder:default=true` was considered; the
  pointer is chosen so host-manager's own decode (not only the apiserver's
  admission defaulting) treats "absent" as secure, and so an object already in
  etcd without the field is read as secure without depending on defaulting-on-read.
  (Revisit at spec review if the team prefers the kubebuilder-default bool.)
- Regenerate: `make manifests generate test lint docs` in kdex-crds. Watch the CEL
  cost budget rule for any XValidation (none added here) and the value-struct
  omitempty considerations for the pointer field.

## Config plumbing (host-manager)

`internal/auth/config.go`:
- Add `RoleBindingClaim string` and `RequireEmailVerified bool` to the internal
  `Config.OIDC` struct (~L64).
- `applyOIDC` (~L461) maps the CRD `OIDCProvider.RoleBindingClaim` (default "sub"
  if empty) and resolves `RequireEmailVerified` (`nil ⇒ true`) onto the internal
  config.

## Resolution changes (host-manager) — the core

The binding key is computed at each role-resolution site and passed to role
matching; identity resolution keeps using `sub`.

`internal/auth/roles.go`:
- Role matching (`resolveRoles` / `FindInternalRolesAndEntitlements`) is what keys
  on the subject today. Thread an explicit **binding key** into role matching so
  the caller decides the key. Entitlements returned by
  `FindInternalRolesAndEntitlements` are derived from the matched roles, so they
  follow the binding key naturally.
- Backend identity resolution (`ResolveClaims` / `FindInternal` credential lookup)
  is unchanged and stays keyed on the identity subject.

Binding-key computation (a small shared helper):

```
bindingKey(claims, cfg):
    if cfg.RoleBindingClaim == "" or cfg.RoleBindingClaim == "sub":
        return sub
    v := claims[cfg.RoleBindingClaim]
    if v is not a non-empty string:
        return sub                      # claim absent/empty → fallback
    if cfg.RoleBindingClaim == "email" and cfg.RequireEmailVerified
       and not truthy(claims["email_verified"]):
        return sub                      # unverified → no email roles (decision 2)
    return v
```

`truthy(email_verified)` accepts boolean `true` and the string `"true"`
(case-insensitive), and treats everything else (including absent, `false`,
`"false"`) as not verified.

## Threading the mint paths (host-manager)

- **Login (`ExchangeToken`, `internal/auth/exchange.go` ~L622):** the verified
  id_token claims are already in `signingContext` (including `email` /
  `email_verified`). Compute `bindingKey` there and use it for role resolution;
  keep `sub` for the gate, token, and backend resolve.
- **Refresh (`mintTokensFromSubject` ~L1869, via `RedeemRefreshToken` ~L1469):**
  `RefreshTokenClaims.IDPClaims` (`idpc`, ~L182) already persists the IdP snapshot
  built by `idpClaimSnapshot` (~L1998), which keeps every non-reserved claim —
  i.e. `email`/`email_verified` survive. Compute `bindingKey` from the replayed
  `idpClaims`. No new carriage.
- **Auth-code (`mintTokensFromCode` ~L1780):** `AuthorizationCodeClaims` (~L1584)
  carries only `Subject`. Add an `IDPClaims jwt.MapClaims` field (mirroring
  `RefreshTokenClaims.IDPClaims`) to carry an IdP-claims snapshot into the
  encrypted auth code. The `/-/authorize` handler (`internal/auth/oauth2.go` ~L187)
  has the authorizing session's signed claims (email was signed into the session
  token at login) in the authContext, so it populates the snapshot when creating
  the code. `mintTokensFromCode` then computes the binding key from that snapshot
  with the same helper the login and refresh paths use.

`sign.Signer.Project` is **unchanged**: `sub` is never rewritten, so no
reserved-claim filtering is required and #211 is untouched.

## Testing

- **envtest (CRD install):** the new fields install and default correctly; a
  `KDexHost` with and without them round-trips. (Decode-only tests do not catch
  schema/defaulting problems — this must be envtest, per the project's CEL/schema
  lesson.)
- **Resolver unit tests:** claim present → matches on it; claim absent → `sub`
  fallback; claim empty string → `sub` fallback; `RoleBindingClaim == "email"` with
  `email_verified` variously `true` (bool), `"true"` (string), `false`, `"false"`,
  and absent — verified paths use email, unverified fall back to `sub`;
  `RequireEmailVerified == false` uses email without the check.
- **Login path:** an OIDC login with `RoleBindingClaim == "email"` resolves roles
  from an email-keyed binding (exact and `/@domain$/` regex).
- **Refresh path:** a rotated session re-resolves the same email-keyed roles from
  the replayed `idpc` claims.
- **Auth-code path:** an authorization code minted from an email-verified session
  redeems to a token whose roles came from the email-keyed binding.
- **Regression:** default config (`roleBindingClaim` unset ⇒ "sub") leaves
  local/PAT/CI and OIDC role resolution byte-identical to today.
- `-race` the auth package (a lock-scope lesson from the last quad).

## Rollout / cross-repo release

1. kdex-crds: add the fields, `make manifests generate test lint docs`, commit.
2. From the workspace root: `./updateCrdUsage.sh -t` (bumps the crds patch tag,
   propagates go.mod/go.sum to host-manager and nexus).
3. Release **both** host-manager and nexus-manager, per the
   `crd-schema-change-release-all-actors` rule — run **each actor's `make test`**,
   not just `go build` (a schema/validation change can break downstream tests).
4. Deploy is a separate, user-driven infra step (not part of this change).

## Out of scope

- **host-manager #211** — filtering `ClaimMappings` mapper output against
  reserved claims in `sign.Signer.Project`. This design does not rewrite `sub`, so
  it neither needs nor closes #211; it stays open.
- Multi-IdP subject namespacing. Only one OIDC provider is configured per host
  today; cross-IdP email collision is not a current concern. Revisit if/when
  multiple providers are federated.

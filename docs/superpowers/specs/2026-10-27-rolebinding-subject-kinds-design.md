# KDexRoleBinding subjectKinds design

Issue: kdex-tech/host-manager#255. Date: 2026-10-27.

## Intent

A `KDexRoleBinding` names its subject in one of three forms: an exact
identifier, `*`, or `/regex/`. Users and auth clients share that one namespace.
#243 keeps exact names disjoint (no user may be named like a client), but a `*`
or `/regex/` binding still matches both kinds, by design of the matcher.

That bites in production. knowdrive-site's `*` and `/^.*$/` bindings were
written for people. They also grant every client_credentials client the same
roles: `apitokens:mint`/`revoke`, `users:me`, `/tenant/v1`, and so on. That
includes the site's new revoke-only and onboarding clients, which should hold
nothing but their own narrow grant. The over-grant is live in shipped config.

The fix lets a binding say which kinds of subject it may bind. The operator
narrows the bindings that need it, and nothing else changes.

## Goals

- **The field.** A new optional field, `spec.subjectKinds`, on `KDexRoleBinding`
  restricts the binding to the listed subject kinds.
- **Absent means any kind.** Every existing binding keeps its exact behavior.
  Narrowing is an explicit, per-binding backfill by the operator (user
  decision).
- **Initial kinds:** `User` and `Client`, Kubernetes style, mirroring
  `rbac.authorization.k8s.io` `Subject.kind` (user decision).
- **Room for `ServiceAccount`.** A later `ServiceAccount` kind must slot in as
  one more enum value plus one more branch in the classifier, with no change to
  bindings or to the resolver's shape (user decision: allow for it, don't build
  it).
- **Explainable.** An operator can see which bindings contributed to a
  subject's roles and which were skipped for a kind mismatch.

## Non-goals

- **Service accounts.** Machine identities that are not OAuth2 clients get their
  own design later. Today a dev token can only carry a real user's `sub`, so
  m2m work is audited against a person who never invoked it; that is the gap
  that design closes. This one only reserves the slot.
- **Flipping the default.** Making `*` stop matching clients is a behavior
  change nobody has asked for. Absent stays "any".
- **Matcher syntax.** The exact, `*` and `/regex/` forms are unchanged.
- **Status conditions.** `KDexRoleBinding.status` gets no new conditions.
- **Other identity checks.** `refuseClientNamedIdentity` (#243) and the
  `RoleBindingClaim` binding-key resolution behave exactly as today.

## Anti-goals

The design fails, even if it works, if:

- a binding without `subjectKinds` matches a different set of subjects than
  before;
- a subject can gain a role it could not gain before (the field only removes
  matches);
- any role-resolution path can run without a subject kind, which would silently
  mean "any";
- a kind value this host-manager doesn't know is treated as a match.

## The API (kdex-crds)

In `api/v1alpha1/kdexrolebinding_types.go`:

```go
// SubjectKind classifies the subject a KDexRoleBinding may bind.
// +kubebuilder:validation:Enum=User;Client
type SubjectKind string

const (
	SubjectKindUser   SubjectKind = "User"
	SubjectKindClient SubjectKind = "Client"
)
```

`KDexRoleBindingSpec` gains:

```go
// subjectKinds restricts the binding to subjects of the listed kinds.
// Absent means any kind, which is the historical behavior. ...
// +optional
// +listType=set
// +kubebuilder:validation:MinItems=1
// +kubebuilder:validation:MaxItems=8
SubjectKinds []SubjectKind `json:"subjectKinds,omitempty" protobuf:"bytes,6,rep,name=subjectKinds"`
```

- **Enum.** `User` and `Client` only. `ServiceAccount` is not admitted yet, but
  the doc comment names it as the reserved next kind.
- **Validation.**
  - `MinItems=1`: an empty list would read as "no kind", so it is invalid. Omit
    the field for "any". (my call)
  - `MaxItems` bounds the list for the CEL cost estimator. See the memory
    "CRD rule-level CEL needs bounded fields". The enum bounds item length.
  - `listType=set` rejects duplicates.
- **Protobuf tag 6.** Tag 4 is unused but may have been used once, so it is not
  reused. (my call)
- **Doc comment.** It describes the kinds: `User` is a human identity (OIDC or
  local); `Client` is a registered auth client (operator-configured or DCR). It
  says that absent means any kind and that a mismatch means the binding simply
  does not contribute.

## Subject classification (host-manager)

### The resolver takes the kind

The role resolver takes the subject's kind explicitly, alongside the lookup key:
`FindInternalRolesAndEntitlements` / `ResolveInternalRolesAndEntitlements` /
`subjectSigningContext`. The lookup key is not always the `sub`: under
`RoleBindingClaim` it may be an email. So the kind cannot be inferred from the
key inside the matcher; the caller supplies it.

Making kind a required parameter is deliberate. It makes "no kind" a compile
error rather than a silent "any". There is no variant that omits it.

### What each caller passes

| Call site | Kind |
|---|---|
| `LoginLocal` → `FindInternalWithSource` (`roles.go`) | `User` |
| OIDC login (`exchange.go`, after `userBindingKey`) | `User` |
| auth-code / refresh `subjectSigningContext` callers that resolve via `userBindingKey` | `User` |
| session-grant refresh (`session_grants.go`) | `User` |
| `buildClientSigningContext` (client_credentials, `exchange.go`) | `Client` |
| FAT token exchange (`subjectSigningContext(sub, sub)`, `exchange.go`) | classified from `sub` |
| PAT middleware (`middleware.go`) | the PAT's recorded kind |
| proxy PAT bridge (`proxy.go`) | the PAT's recorded kind |
| whoami (`whoami.go`) | the PAT's recorded kind, else classified from the caller's context |

The builder must re-enumerate every caller rather than trust this table (see
"Left to the builder").

### The classifier

A single helper on `Exchanger` (for example `SubjectKindOf(sub)`) classifies by
sub:

- **`Client`** if `NamesClient(sub)` is true: an operator-configured client id,
  or a `dcr_`-prefixed dynamically registered one.
- **`User`** otherwise.

This is sound because #243 refuses every user identity named like a client. It
decides the kind **at issue time**: when a PAT is minted, and for the FAT
exchange. It is never the per-request answer for a PAT that already carries a
kind.

### PATs record their kind (user decision)

A PAT re-resolves its roles on every request (middleware, proxy bridge), and
today it carries only `sub`. Classifying it from `sub` per request would go
wrong once its client is removed or renamed: `NamesClient` would turn false,
the PAT would read as `User`, and it would pick up every `*` + `[User]` binding.
That quietly undoes the narrowing. So the kind is fixed when the token is minted:

- **The field.** `apitoken.TokenData` gains a kind field (claim name is the
  builder's). The mint path (`MintStatelessKey` and its callers) takes the kind
  as a required parameter, so no PAT can be minted without one.
- **What gets recorded.** The minter records the kind of the token's subject,
  not of the caller. A client minting for itself records `Client`. A client
  minting for a provisioned user (#237) records `User`. An impersonating mint
  records the target's classified kind.
- **Resolving with a kind.** Per-request resolution uses the recorded kind. It
  does not consult `NamesClient` again.
- **Older PATs.** A PAT minted before this release has no kind. It is
  classified from `sub` as above. The one-time revocation below drains every
  kind-less client PAT, so after it no client token depends on that fallback
  beyond its own short life.
- **Unknown kinds.** A recorded kind this host-manager doesn't know, such as a
  future `ServiceAccount`, matches only bindings without `subjectKinds`. That is
  the same as today's behavior, and it never matches a narrowed binding.
- **Compatibility.** PASETO claims are JSON, so an older replica ignores the new
  field during a rolling update.

**Service accounts.** A future `ServiceAccount` slots in as the classifier's
third branch, plus the kind its PATs record at mint. Neither bindings nor the
resolver change shape. (my design)

### One-time revocation of client PATs (user decision)

All auth-client tokens are OAuth2 credentials with limited TTLs; a client gets
a fresh one with client_credentials at any time. So once the **whole fleet**
runs this release, every configured client's PATs are revoked once with the
existing `POST /-/apitokens/revoke {sub: <client id>, all: true}`. That drains
every kind-less client PAT.

- **It must run after the rollout completes.** An older replica still mints
  kind-less PATs during a rolling update.
- **What the cutoff blocks.** It refuses credentials issued before the cutoff,
  and a fresh client_credentials authentication is issued after it. So clients
  recover on their next token request.
- **DCR clients.** These are public clients and can't use client_credentials,
  so they have no client-subject PATs. They need no revocation.
- **Who runs it.** It is a runbook step, run per host by an operator holding
  revoke-any (infra on the fleet), not automatic in host-manager. An automatic
  one-shot would need a durable "done" marker, and would sign every client out
  again whenever that marker was lost. (my call)

## Matching semantics

- **Absent `subjectKinds`:** the binding matches by subject exactly as today.
- **Present `subjectKinds`:** the binding contributes only when the subject
  matches **and** the caller's kind is in the list. This applies equally to
  exact, `*` and `/regex/` subjects.
- **Fail closed, per entry.** A kind value in `subjectKinds` that this
  host-manager doesn't recognise is a dead entry: no subject's kind ever equals
  it. The other entries in the list still apply.
  - A binding with `[User, ServiceAccount]` read by this release still matches
    users.
  - A binding whose entries are all unknown matches nothing.

  This keeps a partly upgraded fleet from dropping users' roles when an operator
  adds a new kind. The enum makes unknown values unreachable through the
  apiserver today; this guards an older host-manager reading a binding written
  against a newer CRD. (my call)
- **Exact bindings keep their kinds.** Exact bindings are currently flattened
  into `map[subject][]roles`, which loses which binding a role came from. They
  must keep per-binding kinds, and the binding name for logging. The shape is
  the builder's.

## Logging

On the existing `role-binding` named logger (`binding_key.go`, V(2),
`--named-log-level=role-binding=2`), each resolution logs:

- the call site and the kind it ran with;
- the names of the bindings that contributed;
- the names of the bindings whose subject matched but were skipped for kind.

The lookup key is **never** logged. Under `RoleBindingClaim` it can be an email,
and `bindingKeyLogKV` deliberately logs outcomes, never that value (#215: an
email is PII). These lines follow the same rule. Binding names and the kind are
what an operator needs to explain a grant. (my call, following #215; field names
are the builder's)

## Release and rollout

1. **kdex-crds:** add the field, `make manifests generate docs`, then
   `./updateCrdUsage.sh -t -n` from the workspace root, then commit the
   dependents' `go.mod`/`go.sum`. See "CRD dev loop" and "release ALL actors".
2. **host-manager:** implement, run `make test lint`, run the quad over the
   range since the v0.28.1 marker, tag a minor release, and mark the quad.
3. **nexus-manager:** release on the new crds tag (CRD serialization change →
   release all actors), running its `make test`.
4. **Docs:**
   - crd-ref-docs regenerates the reference.
   - Update the kdex-kcnas skill's KDexRoleBinding section. Keep its source and
     installed copies identical, and diff them before syncing.
   - Add a short note to the main-site docs where KDexRoleBinding is
     documented.
5. **Fleet pin:** relay the release to infra.
   - Once every replica on every host runs it, infra runs the one-time
     client-PAT revocation (above): `{sub, all: true}` for each configured
     client id per host.
   - Then the dev smoke test: a client PAT minted before the revocation gets 401;
     a fresh client PAT carries `Client` and does not match a `[User]` binding.
6. **Site backfill:** tell the site session, which owns it, that the release
   landed and that its `*` / `/^.*$/` user bindings should add
   `subjectKinds: [User]`. Their clients then keep only bindings written for
   them.

**Ordering.** The site must not apply `subjectKinds` before the fleet runs a
host-manager that reads it. On an older host-manager the field is ignored, so
it fails open. That is no worse than today, but the narrowing isn't real until
the fleet is on the new release.

## Testing

- **kdex-crds:** an envtest install of the CRD covers the enum, MinItems,
  MaxItems, set semantics, and absent-is-valid. Decode tests alone don't catch
  CEL cost failures.
- **host-manager unit tests** (`roles.go`): the full matrix of
  {exact, `*`, regex} × {absent, `[User]`, `[Client]`, `[User, Client]`} ×
  {User, Client} for kind, plus an unknown-kind binding that never matches.
- **Classifier:**
  - a configured client id → Client;
  - a `dcr_` id → Client;
  - anything else → User.
- **Integration (per path):**
  - a client_credentials token under a `*` + `[User]` binding gets none of its
    roles;
  - the same client under a `[Client]` binding gets them;
  - a user PAT and a client PAT through the middleware and the proxy classify
    correctly;
  - an OIDC login keyed on email under `[User]` still matches.
- **Recorded kind:**
  - a client's self-minted PAT records `Client`;
  - a client minting for a provisioned user records `User`;
  - a `Client` PAT whose client is then removed from config still resolves as
    `Client`, and does not pick up a `*` + `[User]` binding;
  - a kind-less (pre-release) PAT falls back to classification by `sub`;
  - an unknown recorded kind matches only bindings without `subjectKinds`.
- **Unknown binding kinds, per entry:**
  - `[User, <unknown>]` still matches a User;
  - `[<unknown>]` matches nothing.
- **Logging:** under `RoleBindingClaim=email`, the `role-binding` output
  contains no email.
- **Regression:** existing role tests pass unchanged with the field absent.

## Left to the builder

- The internal data shape for compiled bindings, and how exact bindings retain
  kinds and names.
- How the recorded kind travels from `TokenData` to the resolver, and the claim
  name. Every path must arrive with a kind, and no path may default to "any".
- Enumerating every `MintStatelessKey` caller (self-mint, impersonating mint,
  provisioned mint, capability/`mint_token`, and any others `rg` finds), and
  confirming which subject kind each records.
- Re-enumerating every role-resolution call site with `rg` and confirming its
  kind. The table above is from a recon pass, not an audit.
- Log field names.
- The exact `MaxItems` value, any bound of at least 3.

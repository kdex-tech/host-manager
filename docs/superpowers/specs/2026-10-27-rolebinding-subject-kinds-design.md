# KDexRoleBinding subjectKinds design

Issue: kdex-tech/host-manager#255. Date: 2026-10-27. Revised 2026-10-28 after
the quad over the plan (the veto, the client registry, the kind carried by
every credential; the one-time revocation dropped).

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
- **A credential keeps its kind.** A client's credential can never come to be
  treated as a user's, on any path, including after the client is removed from
  config.
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
- **`grant_type` injection.** An OIDC id_token or a claimMapping can set
  `grant_type` (#211). This design protects only its own claim, `knd`. With the
  veto, an injected `grant_type` can only refuse the user's own session, never
  grant anything.

## Anti-goals

The design fails, even if it works, if:

- a binding without `subjectKinds` matches a different set of subjects than
  before;
- a subject can gain a role it could not gain before (the field only removes
  matches);
- any role-resolution path can run without a subject kind and be treated as
  "any";
- a kind value this host-manager doesn't know is treated as a match;
- a credential issued to a client is ever resolved, minted from or exchanged as
  a `User`.

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

// SubjectKinds is every kind this release knows, in enum order. The schema
// test pins it to the Enum marker above.
var SubjectKinds = []SubjectKind{SubjectKindUser, SubjectKindClient}

// Known reports whether k is one of SubjectKinds.
func (k SubjectKind) Known() bool
```

`KDexRoleBindingSpec` gains:

```go
// subjectKinds restricts the binding to subjects of the listed kinds.
// Absent means any kind, which is the historical behavior. ...
// +optional
// +listType=set
// +kubebuilder:validation:MinItems=1
// +kubebuilder:validation:MaxItems=8
SubjectKinds []SubjectKind `json:"subjectKinds,omitempty" protobuf:"bytes,6,rep,name=subjectKinds,casttype=SubjectKind"`
```

- **Enum.** `User` and `Client` only. `ServiceAccount` is not admitted yet, but
  the doc comment names it as the reserved next kind.
- **One list of kinds.** `SubjectKinds` and `Known()` live in kdex-crds next to
  the enum marker, so host-manager's `auth` and `apitoken` packages share one
  rule. A schema test asserts the generated `items.enum` equals `SubjectKinds`.
- **Validation.**
  - `MinItems=1`: an empty list would read as "no kind", so it is invalid. Omit
    the field for "any". (my call)
  - `MaxItems` bounds the list for the CEL cost estimator. See the memory
    "CRD rule-level CEL needs bounded fields". The enum bounds item length.
  - `listType=set` rejects duplicates.
- **Protobuf tag 6** with `casttype=SubjectKind`, as other typed enum fields
  carry. Tag 4 is unused but may have been used once, so it is not reused. (my
  call)
- **Doc comment.** It describes the kinds: `User` is a human identity (OIDC or
  local); `Client` is a registered auth client (operator-configured or DCR). It
  says that absent means any kind and that a mismatch means the binding simply
  does not contribute.

## Subject classification (host-manager)

### The resolver takes the kind

The role resolver takes the subject's kind explicitly, alongside the lookup
key. The lookup key is not always the `sub`: under `RoleBindingClaim` it may be
an email. So the kind cannot be inferred from the key inside the matcher; the
caller supplies it.

The key, the kind and the call-site label travel together in one named value,
`BindingSubject{Key, Kind, Site}`, so they can't be swapped silently the way
three positional strings can. `userBindingKey` returns one with Kind `User`,
so no user path can pass the wrong kind. (quad)

All resolution goes through one `Exchanger` entry point. Today OIDC login and
`subjectSigningContext` call the provider directly; they are routed through it.
That entry point is where an empty kind is logged at V(0), and where the
`role-binding` line is written. An empty kind matches only bindings without
`subjectKinds`, a subset of the correct answer. (quad)

### What each caller passes

| Call site | Kind |
|---|---|
| `LoginLocal` → `FindInternalWithSource` (`roles.go`) | `User` |
| OIDC login, auth-code redeem, refresh, session-grant refresh (all after `userBindingKey`) | `User` |
| `buildClientSigningContext` (client_credentials) | `Client` |
| FAT token exchange | the FAT's `knd`, else classified from `sub` |
| PAT middleware, proxy PAT bridge (one shared helper) | the PAT's `knd`, else classified from `sub` |
| whoami | the auth context's kind (below) |

A structural test records the kind each site passes, so a new site can't be
added without one. (quad)

### The classifier

A single helper on `Exchanger`, `SubjectKindOf(sub)`, classifies by sub:

- **`Client`** if `NamesClient(sub)` is true;
- **`User`** otherwise.

`NamesClient` is true for an operator-configured client id, any `dcr_`-prefixed
id, and any id in the client registry (below). This is sound because #243
refuses every user identity named like a client. The classifier decides a kind
only when nothing better is known: when a PAT is minted for another subject,
and for credentials minted before this release.

### The client registry (user decision: detect, don't revoke)

Host-manager forgets a client id once it leaves config, so a removed client's
old credentials would classify as `User`. The registry is a record of every
client id this host has ever had configured.

- **Where.** One key in a surviving-scope cache class (the #245 scope, `MaxItems`
  0, no TTL). Its value is the sorted set of ids.
- **When it is written.** `NewExchanger` atomically merges the configured ids
  into it (`Cache.Update`), then reads the merged set into memory. Lookups never
  touch the cache. Every replica builds its Exchanger from the same config, so
  each holds the same set.
- **Failure.** If the merge or the read fails, `NewExchanger` fails. The
  reconcile retries, and the previous Exchanger keeps serving. A partial
  registry would fail open, so none is used. (my call)
- **What it extends.**
  - `NamesClient`, so the classifier, #243's login refusal and the veto all see
    removed clients.
  - In particular, a user later named like a removed client is refused, as #243
    refuses one named like a current client: the client keeps the name.
  - DCR ids are not recorded; their prefix already covers them.
- **The in-memory backend.** Like revocations, the registry lasts only the
  process. Production runs Valkey.
- **Scope.** It covers clients removed after the host first runs this release.
  Clients removed earlier were never seen. See "Clients removed before the
  rollout".

### The kind travels with the credential

The kind is fixed when a credential is issued and carried from then on, in the
claim `knd`.

- **PATs.** `apitoken.TokenData` gains `SubjectKind` (`knd`). `MintStatelessKey`
  takes the kind and refuses one that isn't `Known()`.
- **The auth context.**
  - `ClaimSubjectKind = "knd"` sits next to `ClaimIssuedAt`.
  - It joins `mintDecidedClaims` and `reservedMintClaims`, so no claimMapping or
    backend claim can rewrite it.
  - It is stripped from the OIDC id_token claims before they enter the signing
    context, and re-asserted after the mapper where `auth_method` is.
  - Every auth context built from a credential sets it.
- **`AuthContext.SubjectKind()`.** It reads the context's `knd`. When the claim
  is absent, it falls back to `Client` if `ClientCredentialsSubject()` reports a
  client, else `SubjectKindOf(sub)`. This mirrors `ClientCredentialsSubject()`,
  and it is the one place the fallback lives. (quad)
- **Signed tokens.** client_credentials and login tokens carry `knd`. The proxy
  stamps it on the FAT it projects. `ExchangeSubjectToken` resolves with the
  FAT's `knd`.
- **One PAT helper.** The PAT-to-auth-context sequence is duplicated between the
  middleware and the proxy bridge today. It becomes one
  `Exchanger.PATAuthContext(data)`: it resolves the kind, the roles and the
  backend claims, and sets `knd`. Each caller adds only its own differences.
  (quad)
- **What a mint records.**
  - A self-mint records the caller's own `ac.SubjectKind()`.
  - An impersonating or provisioned (#237) mint records `SubjectKindOf(target)`.
  - `MintResourcePAT` (auth-code / refresh) records `User`.
- **whoami** uses `ac.SubjectKind()`, the same value enforcement used.
- **`/-/apitokens/verify`** reports `knd` with `omitempty`.
- **Older credentials.** A PAT or FAT minted before this release has no `knd`.
  It falls back to `SubjectKindOf(sub)`, which with the registry stays correct
  for clients removed after the rollout.
  - The fallback, and `ValidateToken`'s tolerance of a missing `knd`, are marked
    `LEGACY(#N)` against an issue filed for their removal.
  - The removal condition: once the longest PAT lifetime since the fleet ran
    this release has passed, kind-less PATs are refused outright.
- **Unknown kinds.** A recorded kind this host-manager doesn't know, such as a
  future `ServiceAccount`, matches only bindings without `subjectKinds`. That is
  the same as today's behavior, and it never matches a narrowed binding.
- **Compatibility.** PASETO and JWT claims are JSON, so an older replica ignores
  `knd` during a rolling update. The PAT jti does not include the kind, so
  revocation keys are unchanged.

**Service accounts.** A future `ServiceAccount` slots in as the classifier's
third branch, plus the kind its credentials record. Neither bindings nor the
resolver change shape. (my design)

### The veto (user decision)

Current config is a veto on a credential's kind, never its source. Wherever a
credential is accepted (the PAT helper, host JWT validation, and the FAT
subject of a token exchange), host-manager refuses it if:

- **its kind is `Client`** and its `sub` is not a configured client
  (`IsConfiguredClient`). Removing a client stops every live credential it
  holds, without anyone remembering a revocation step.
- **its kind is `User`** and its `sub` names a client (`NamesClient`, which
  includes the registry). This is #243's rule: the client keeps the name.

The veto closes every path the quad found by which a removed client could pass
as a `User`:

- self-mint;
- token exchange;
- `/-/oauth/authorize`;
- session-grant refresh.

A refused credential gets the same answer as an invalid one. It returns 401
and logs a V(0) line naming the rule, never the key.

### Clients removed before the rollout

The registry can't know a client removed before the host first runs this
release. Such a client's kind-less PATs classify as `User`, exactly as they do
today. Today `*` already grants them user roles, so #255 introduces no new
exposure; it just can't narrow that one.

- **The remedy.** The operator knows the few such ids within the last `maxTTL`,
  and revokes them with the existing
  `POST /-/apitokens/revoke {sub: <client id>, all: true}`.
- **Optional.** It is a runbook step, not automatic. (my call)

There is no fleet-wide revocation of client PATs. That was the first design,
which the user replaced with detection.

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
- **The compiled form.** Each compiled binding keeps its name, a `narrowed`
  flag and its kinds. "Any kind" is `narrowed == false`, never an empty kind
  set, so an all-unknown list can't collapse into "any". Exact subjects stay a
  constant-time map lookup. (quad)

## Logging

On the existing `role-binding` named logger (`binding_key.go`,
`--named-log-level=role-binding=N`), each resolution logs:

- the call site and the kind it ran with;
- the names of the bindings that contributed;
- the names of the bindings whose subject matched but were skipped for kind.

**Levels.** Issue-time sites (logins, auth-code, refresh, client_credentials,
token exchange) log at V(2). Per-request sites (host PAT, proxy PAT, whoami,
session-grant refresh) log at V(3), as the signer splits V(2)/V(3).

**Cost.** kdexlog's `Enabled` is coarse: any named logger at ≥ N turns it on,
and prod runs one at 2. So the matcher collects binding names only when the
entry point hands it a collector, and the entry point hands one over only under
`V(n).Enabled()`. With logging off, resolution allocates nothing more than
today. (quad)

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
   range since the last `Quad-Range:` marker, tag a minor release, and mark the
   quad.
3. **nexus-manager:** release on the new crds tag (CRD serialization change →
   release all actors), running its `make test`.
4. **Docs:**
   - crd-ref-docs regenerates the reference.
   - Update the kdex-kcnas skill's KDexRoleBinding section. Keep its source and
     installed copies identical, and diff them before syncing.
   - Add a short note to the main-site docs where KDexRoleBinding is
     documented.
5. **Fleet pin:** relay the release to infra.
   - **Install the new CRD on every cluster.** The nexus chart ships no CRDs,
     and a structural CRD silently prunes a field it doesn't know. A
     `subjectKinds` applied before the CRD is upgraded is dropped, and the
     binding stays "any kind".
   - **Optional:** revoke clients removed before the rollout (above).
   - **Dev smoke test:**
     - a fresh client PAT carries `knd: Client` on `/-/apitokens/verify`;
     - it does not match a `[User]` binding;
     - removing a test client makes its live PAT and client_credentials JWT
       return 401.

     Allow about 70 s for the session-grant cache before judging a binding
     change.
   - **Rollback.** A rollback below this release stops the veto, and mints
     kind-less PATs. On re-upgrade those classify through the registry, which
     the rollback leaves intact.
6. **Site backfill:** tell the site session, which owns it, that the release
   landed and that its `*` / `/^.*$/` user bindings should add
   `subjectKinds: [User]`. Their clients then keep only bindings written for
   them. After applying, check that
   `kubectl get kdexrolebinding <name> -o jsonpath='{.spec.subjectKinds}'` is
   non-empty on every host.

**Ordering.** The site must not apply `subjectKinds` before every cluster has
the new CRD and every replica runs a host-manager that reads it. On an older
host-manager the field is ignored, so it fails open. That is no worse than
today, but the narrowing isn't real until both are in place.

## Testing

- **kdex-crds:** schema tests pin the enum to `SubjectKinds`, plus MinItems,
  MaxItems, set semantics, and absent-is-valid. They use one shared
  CRD-schema helper; there are four copies today.
- **nexus-manager envtest:** the CRD installs and admits or rejects as
  specified. kdex-crds has no envtest, and decode tests alone don't catch CEL
  cost failures.
- **Matcher unit tests** (`roles.go`):
  - the full matrix of {exact, `*`, regex} × {absent, `[User]`, `[Client]`,
    `[User, Client]`} × {User, Client} for kind;
  - an unknown-kind binding that never matches;
  - an all-unknown list that matches nothing in its compiled form.
- **Classifier:**
  - a configured client id → Client;
  - a `dcr_` id → Client;
  - a registry-only id → Client;
  - anything else → User.
- **Registry:**
  - two Exchanger builds merge their ids;
  - a removed id survives a rebuild;
  - a merge failure fails `NewExchanger`.
- **Integration (real role provider, not fixed-role stubs):**
  - a client_credentials token under a `*` + `[User]` binding gets none of its
    roles;
  - the same client under a `[Client]` binding gets them;
  - an OIDC login keyed on email under `[User]` still matches.
- **Kind carried:**
  - a client's self-mint records `Client`;
  - a client minting for a provisioned user records `User`;
  - a FAT projected from a client PAT exchanges as `Client`;
  - `knd` in an OIDC id_token or a claimMapping is ignored;
  - a kind-less PAT falls back to `SubjectKindOf`;
  - an unknown recorded kind matches only bindings without `subjectKinds`.
- **Veto, one test per path:** after a client is removed, its:
  - `knd: Client` PAT (middleware and proxy) is refused;
  - kind-less PAT is refused;
  - client_credentials JWT is refused;
  - FAT exchange is refused;
  - self-mint is refused;
  - `/-/oauth/authorize` is refused;
  - cookie session-grant refresh is refused.

  A `User` PAT whose sub becomes a client id is refused.
- **Logging:**
  - under `RoleBindingClaim=email`, the `role-binding` output contains no email;
  - with the logger off, resolution allocates no more than before.
- **Structural:** a stub provider records the kind each resolution site passes.
- **Regression:** existing role tests pass unchanged with the field absent.

## Left to the builder

- The compiled-binding representation, within the rules above (`narrowed` flag,
  exact map).
- Log field names.
- The exact `MaxItems` value, any bound of at least 3.
- The registry's cache class and key names.
- Re-enumerating every role-resolution and `MintStatelessKey` call site with
  `rg`. The tables above come from recon and a quad, which agreed, but the
  structural test is the lasting guard.

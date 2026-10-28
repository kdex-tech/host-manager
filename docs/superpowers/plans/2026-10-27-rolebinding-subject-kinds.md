# KDexRoleBinding subjectKinds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `KDexRoleBinding` restrict which kinds of subject (`User`,
`Client`) it binds, so `*` / `/regex/` user bindings stop granting
client_credentials clients their roles, and make sure a client's credential is
never treated as a user's (host-manager#255).

**Architecture:**
- **kdex-crds** gains an optional `spec.subjectKinds` enum list, plus the Go list
  of known kinds.
- **host-manager's role resolver** takes a `BindingSubject{Key, Kind, Site}`
  through one `Exchanger` entry point. A binding with `subjectKinds` contributes
  only for a listed kind.
- **The kind is recorded** at issue in the claim `knd`, on PATs, auth contexts
  and FATs, and is carried from then on.
- **Current config is a veto, never a source.** A `Client` credential whose
  client is gone is refused, and so is a `User` credential whose sub names a
  client.
- **A surviving client registry** remembers every client id ever configured,
  so removed clients still classify as `Client`.

**Tech Stack:**
- Go 1.26.0, kubebuilder / controller-gen, controller-runtime fake client;
- envtest in kdex-nexus-manager;
- PASETO v4 PATs via `aidanwoods.dev/go-paseto`, golang-jwt host tokens.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-10-27-rolebinding-subject-kinds-design.md`
(revised 2026-10-28; read it in full before any task).

## Global Constraints

- **Field.** `subjectKinds`, Kubernetes-style values `User`, `Client` only.
  `ServiceAccount` is named in docs as reserved, NOT admitted by the enum.
- **Absent field = any kind** (today's behavior). An empty list is invalid
  (`MinItems=1`). `MaxItems=8`, `listType=set`, protobuf tag
  `bytes,6,rep,name=subjectKinds,casttype=SubjectKind`.
- **One list of kinds:** `kdexv1alpha1.SubjectKinds` / `SubjectKind.Known()`.
  No other package keeps its own list.
- **Fail closed:**
  - An unknown kind value in a binding's list is a dead entry; the other entries
    still apply. An all-unknown list matches nothing.
  - An unknown subject kind (including `""`) matches only bindings without
    `subjectKinds`. An empty kind is logged at V(0).
  - "Any kind" is a compiled `narrowed == false`, never an empty kind set.
- **The veto.** A `Client` credential whose sub is not `IsConfiguredClient` is
  refused. So is a `User` credential whose sub `NamesClient`. Either refusal
  is a 401, the same answer an invalid credential gets.
- **Never log the lookup key.** The `role-binding` logger never logs it; it may
  be an email (#215). Log the site, the kind and the binding names. Issue-time
  sites log at V(2), per-request sites at V(3), and names are collected only
  when the level is enabled.
- **`knd` is protected.** It is in `mintDecidedClaims` and
  `reservedMintClaims`, it is stripped from OIDC id_token claims, and it is
  re-asserted after the mapper. No caller can choose it.
- **Repos.**
  - Use `rg`, not grep. YAML is 2-space indented, one resource per file.
  - Commit inside each sub-repo. End every commit message with
    `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Dependency bumps.** After the kdex-crds change, run
  `./updateCrdUsage.sh -t -n` from the workspace root. Never use `go.work`, and
  never hand-edit `replace` directives.
- **Lint.** Run `make lint` with `GOTOOLCHAIN=go1.26.0`, then check
  `go mod tidy -diff` is clean.
- **Tests use the real role provider** (`NewRoleProvider` + fake client, as
  `exchange_rolebindingclaim_test.go` does) wherever a result depends on kind.
  Fixed-role stubs can't see it.

## Review Focus

1. **A client_credentials token under the site's real shape** (a `*` binding
   with `subjectKinds: [User]` plus a client-specific exact binding) must keep
   exactly the client's own roles, not none and not the user set. Covered in
   Task 3.
2. **Every live credential of a removed client is refused**, by both PAT paths,
   the JWT gate, token exchange and self-mint, whether or not it carries `knd`.
   Covered in Task 6.
3. **An email-keyed (`RoleBindingClaim=email`) OIDC user under a `[User]`
   binding** must still match, and the `role-binding` log must contain no
   email. Covered in Task 3.
4. **A provisioned-user mint by a client** (#237) must record `User`, not
   `Client`, or the provisioned user would lose their `[User]` grants. Covered
   in Task 5.
5. **A registry merge failure** must fail `NewExchanger`, so the previous
   Exchanger keeps serving and no partial registry is used. Covered in Task 4.

---

### Task 1: kdex-crds — `SubjectKind`, the known list, and `spec.subjectKinds`

**Files:**
- Modify: `kdex-crds/api/v1alpha1/kdexrolebinding_types.go`
- Create: `kdex-crds/api/v1alpha1/crd_schema_test_helpers_test.go` (the shared
  `crdSpecSchema(t, file)` helper). Migrate the four existing copies to it:
  - `kdextranslation_types_test.go:52`;
  - `kdexpage_types_test.go:93` and `:193`;
  - `kdexfunction_basepath_schema_test.go:37`.
- Test: `kdex-crds/api/v1alpha1/kdexrolebinding_types_test.go` (create)
- Regenerated: `config/crd/bases/kdex.dev_kdexrolebindings.yaml`,
  `zz_generated.deepcopy.go`, docs output of `make docs`

**Interfaces:**
- Produces:
  - `type SubjectKind string`, with const `SubjectKindUser SubjectKind = "User"`
    and const `SubjectKindClient SubjectKind = "Client"`;
  - `var SubjectKinds = []SubjectKind{SubjectKindUser, SubjectKindClient}`;
  - `func (k SubjectKind) Known() bool`;
  - `KDexRoleBindingSpec.SubjectKinds []SubjectKind`, json
    `subjectKinds,omitempty`.

- [ ] **Step 1: Write the failing tests.**
  - `TestKDexRoleBinding_SubjectKindsDecodes`: YAML with
    `subjectKinds: [User, Client]` decodes to
    `[]SubjectKind{SubjectKindUser, SubjectKindClient}`.
  - `TestKDexRoleBinding_WithoutSubjectKindsIsUnchanged`: YAML without the field
    decodes to `nil`, and re-marshals with no `subjectKinds` key.
  - `TestSubjectKind_Known`: `User`, `Client` → true; `""`, `"ServiceAccount"`,
    `"user"` → false.
  - `TestKDexRoleBindingGeneratedSchema_SubjectKinds`: in the generated CRD,
    `spec.properties.subjectKinds` has:
    - `items.enum` equal to `SubjectKinds` (as strings, same order);
    - `minItems == 1`, `maxItems == 8`;
    - `x-kubernetes-list-type == "set"`;
    - and `subjectKinds` is not in `spec.required`.
- [ ] **Step 2: Run them to see them fail.** Run
  `go test ./api/v1alpha1/ -run 'KDexRoleBinding|SubjectKind' -v`. Expected:
  compile failure (`undefined: SubjectKind`).
- [ ] **Step 3: Implement** the type, the consts, `SubjectKinds`, `Known()` and
  the field, as the spec's API section gives them.
  - Markers: `+optional`, `+listType=set`, `MinItems=1`, `MaxItems=8`, and
    `+kubebuilder:validation:Enum=User;Client` on the type.
  - Use the protobuf tag from Global Constraints.
  - The doc comment covers:
    - absent means any kind;
    - `User` is a human (OIDC or local);
    - `Client` is a registered auth client (configured or DCR);
    - a mismatch means the binding does not contribute;
    - `ServiceAccount` is the reserved next kind.

  Add one sentence to the `Subject` doc comment pointing at `subjectKinds` for
  restricting `*` / `/regex/` by kind. Move the four schema-loader copies onto
  `crdSpecSchema`.
- [ ] **Step 4: Regenerate, then confirm the tests pass.** Run
  `make manifests generate docs`, then
  `go test ./api/v1alpha1/ -v`. Expected: PASS, including the migrated tests.
- [ ] **Step 5: Run the whole module.** Run `make test lint`. Expected: PASS.
- [ ] **Step 6: Commit** in kdex-crds:
  `feat: KDexRoleBinding spec.subjectKinds (host-manager#255)`.
- [ ] **Step 7: Propagate.** From the workspace root, run
  `./updateCrdUsage.sh -t -n`. Then commit the `go.mod` / `go.sum` it changed
  inside kdex-host-manager and kdex-nexus-manager:
  `chore: bump kdex-crds to <tag> (#255)`.

  If kdex-crds main was committed before the script ran, push it by hand
  (memory: "CRD serialization change → release ALL actors"). Record the new
  crds tag for the release notes.

### Task 2: kdex-nexus-manager — envtest admission of `subjectKinds`

**Files:**
- Test: `kdex-nexus-manager/internal/controller/kdexrolebinding_subjectkinds_test.go`
  (create; mirror `kdextranslation_hostref_test.go`'s Ginkgo + `k8sClient` style)

**Interfaces:**
- Consumes: Task 1's `SubjectKind` consts via the bumped `kdex.dev/crds`.

- [ ] **Step 1: Write the test.** It creates `KDexRoleBinding`s against the
  envtest apiserver.
  - **Accepted:** the field absent; `[User]`; `[Client]`; `[User, Client]`.
    Read each back and assert `spec.subjectKinds` round-trips (not pruned).
  - **Rejected** (`apierrors.IsInvalid`):
    - `[]` (empty, minItems);
    - `[ServiceAccount]` (enum);
    - `[User, User]` (set duplicate);
    - nine entries (maxItems).
- [ ] **Step 2: Run it.** Run
  `go test ./internal/controller/ -run 'SubjectKinds' -v`. Expected: PASS. It
  passes on first run because Task 1 already shipped the schema; it exists to
  prove the CRD installs and admits as specified.
- [ ] **Step 3: Run the module.** Run `make test lint`. Expected: PASS. A
  downstream test pinning a schema message fails here, not in production.
- [ ] **Step 4: Commit** in kdex-nexus-manager:
  `test: envtest admission of KDexRoleBinding subjectKinds (host-manager#255)`.

### Task 3: host-manager — resolve roles with a kind, at every site

**Files:**
- Modify: `internal/auth/roles.go`:
  - the compiled-binding shape;
  - `resolveRoles`, `FindInternalRolesAndEntitlements`, `FindInternalWithSource`;
  - the `InternalIdentityProvider` interface.
- Modify: `internal/auth/binding_key.go` (`BindingSubject`, site constants, log
  level per site)
- Modify: `internal/auth/exchange.go`:
  - `ResolveInternalRolesAndEntitlements`, `subjectSigningContext`,
    `userBindingKey`, `buildClientSigningContext`;
  - the OIDC login direct call (~L737) and the `subjectSigningContext` direct
    call (~L1974): route both through the entry point;
  - token exchange (~L507), auth-code (~L2136), refresh (~L2231).
- Modify: `internal/auth/session_grants.go` (~L121, ~L149),
  `internal/auth/middleware.go` (~L104), `internal/host/proxy.go` (~L560),
  `internal/host/whoami.go` (~L206)
- Test: `internal/auth/roles_subjectkinds_test.go`,
  `internal/auth/exchange_subjectkinds_test.go` (create)
- Modify: the ~33 stub implementations and ~40 test call sites of
  `FindInternalRolesAndEntitlements`, so they compile

**Interfaces:**
- Consumes: `kdexv1alpha1.SubjectKind`, `SubjectKindUser`, `SubjectKindClient`,
  `Known()`.
- Produces:
  - `type BindingSubject struct { Key string; Kind kdexv1alpha1.SubjectKind; Site string }`.
    `Key` is the binding key and is never logged.
  - `type BindingNames struct { Contributed, SkippedForKind []string }`. It is
    the collector the matcher fills only when one is passed.
  - `InternalIdentityProvider.FindInternalRolesAndEntitlements(bs BindingSubject, names *BindingNames) ([]string, []string, error)`.
    `names` may be nil, and then nothing is collected.
  - `func (e *Exchanger) ResolveInternalRolesAndEntitlements(bs BindingSubject) ([]string, []string, error)`.
    It is the single entry point. It:
    - logs an empty or unknown `bs.Kind` at V(0);
    - passes a collector only under `bindingKeyLog.V(level).Enabled()`;
    - writes the one `role-binding` line.
  - Site constants in `binding_key.go`:
    - `SiteLocalLogin = "local login"`, `SiteOIDCLogin = "oidc login"`;
    - `SiteAuthCode = "auth-code redeem"`, `SiteRefresh = "refresh"`;
    - `SiteSessionGrantRefresh = "session-grant refresh"`;
    - `SiteClientCredentials = "client_credentials"`;
    - `SiteTokenExchange = "token exchange"`;
    - `SiteHostPAT = "host pat"`, `SiteProxyPAT = "proxy pat"`,
      `SiteWhoami = "whoami"`.

    Plus `func bindingLogLevel(site string) int`: 3 for the four per-request
    sites (host pat, proxy pat, whoami, session-grant refresh), 2 otherwise. Use
    the constants wherever `userBindingKey` already takes a site string.
  - `func (e *Exchanger) userBindingKey(claims jwt.MapClaims, sub, site string) (BindingSubject, error)`:
    Kind `User`.
  - `func clientBindingSubject(id string) BindingSubject`: Kind `Client`, site
    `SiteClientCredentials`.
  - `func (e *Exchanger) subjectSigningContext(subject string, bs BindingSubject) (roles, entitlements []string, backend jwt.MapClaims, err error)`.
  - `func (e *Exchanger) SubjectKindOf(sub string) kdexv1alpha1.SubjectKind`:
    `SubjectKindClient` if `e.NamesClient(sub)`, else `SubjectKindUser`. Its doc
    comment says a future `ServiceAccount` branch goes here.

**The compiled shape (required).**
- Exact subjects stay a map: `map[string][]compiledBinding`.
- `*` / regex bindings are a slice.
- Each `compiledBinding` carries `name string`, `roles`, `narrowed bool` and
  its kinds.
- It matches iff its subject matches AND (`!narrowed` OR
  `slices.Contains(kinds, kind)`).
- Unknown entries are kept as they are. They can never equal a known kind, so
  they are dead without being dropped.
- Never derive `narrowed` from the length of a filtered set.

**Kinds per site in this task.**

| Site | Kind |
|---|---|
| local login, OIDC login, auth-code, refresh, session-grant refresh | `User` (from `userBindingKey`) |
| client_credentials | `Client` (`clientBindingSubject`) |
| token exchange, host PAT, proxy PAT, whoami | `e.SubjectKindOf(sub)` for now. Task 5 replaces these with the carried kind. |

Before editing, run
`rg -n 'FindInternalRolesAndEntitlements\(|ResolveInternalRolesAndEntitlements\(|subjectSigningContext\(' --type go -g '!*_test.go'`.
Confirm the result matches: `roles.go:188`,
`exchange.go:507/737/1081/1974/2136/2231`, `session_grants.go:149`,
`middleware.go:104`, `proxy.go:560`, `whoami.go:206`.

- [ ] **Step 1: Write the failing tests.**
  - **`TestResolveRoles_SubjectKindMatrix`**: a table over
    - subject form {exact `"alice"` / `"svc-client"`, `"*"`, `"/^.*$/"`},
    - binding kinds {absent, `[User]`, `[Client]`, `[User, Client]`},
    - query kind {User, Client}.

    It asserts the role appears iff the kinds list is absent or contains the
    query kind. Absent and `[User, Client]` give identical results for both
    kinds.
  - **`TestResolveRoles_UnknownBindingKindIsDeadEntry`**: build the binding
    object directly with `SubjectKinds: []SubjectKind{"User", "ServiceAccount"}`
    (the fake client skips the enum).
    - It matches a `User` query.
    - A binding with only `{"ServiceAccount"}` matches neither `User` nor
      `Client` nor a `"ServiceAccount"` query.
  - **`TestResolveRoles_UnknownSubjectKindMatchesOnlyUnnarrowed`**: query kind
    `"ServiceAccount"` and kind `""` each get the roles of an absent-kinds
    binding, and none from `[User]` or `[Client]` bindings.
  - **`TestResolveRoles_LogNeverCarriesKey`**:
    - capture the `role-binding` logger at V(3), swapping in a funcr / testr
      sink for the test;
    - resolve key `"alice@example.com"` against a `[Client]` binding and an
      absent-kinds binding;
    - assert the output contains both binding names, the kind and the site, and
      does NOT contain `"alice@example.com"`;
    - assert the skipped binding is reported as skipped for kind.
  - **`TestResolveRoles_NoCollectorNoAllocs`**: compare `testing.AllocsPerRun`
    of `resolveRoles` with `names == nil` against a baseline. The narrowed
    binding set must add no allocation over the absent-kinds set.
  - **`TestResolutionSites_PassKinds`** (structural): a stub provider records
    every `BindingSubject` it receives. Drive each site once and assert:
    - local login, OIDC login, auth-code, refresh and session-grant refresh
      pass `User`;
    - client_credentials passes `Client`;
    - token exchange, host PAT, proxy PAT and whoami pass
      `SubjectKindOf(sub)`, which is `Client` for a configured client sub;
    - no site passes `""`.
  - **`TestSubjectKindOf`**:
    - a configured client id → `Client`;
    - `"dcr_abc"` → `Client`;
    - `"alice"` → `User`;
    - `""` → `User`.
  - **`TestClientCredentials_UserOnlyWildcardGrantsNothing`** (real provider):
    - bindings: `*` + `[User]` → role `user-role`; exact client id → role
      `client-role`;
    - a client_credentials token for that client carries `client-role` and NOT
      `user-role` (Review Focus 1);
    - with the `*` binding's kinds absent, it carries both. That is a regression
      guard for today's behavior.
  - **`TestClientCredentials_ClientKindBindingMatches`**: a `*` + `[Client]`
    binding grants a client_credentials token its role, and does not grant a
    password-login user that role.
  - **`TestOIDCLogin_EmailKeyedUserKindStillMatches`**: with
    `RoleBindingClaim=email`, an exact email binding + `[User]` grants the role
    on login (Review Focus 3).
- [ ] **Step 2: Run them to see them fail.** Run
  `go test ./internal/auth/ -run 'TestResolveRoles_|TestResolutionSites_|TestSubjectKindOf|UserOnlyWildcard|ClientKindBinding|EmailKeyedUserKind' -v`.
  Expected: compile failure (undefined `BindingSubject`, `SubjectKindOf`).
- [ ] **Step 3: Implement** the interfaces, the compiled shape and the per-site
  kinds above.
  - Keep the existing per-binding regex-compile-failure skip. Route its
    `fmt.Printf` through `bindingKeyLog`, with the binding name.
  - `userBindingKey` keeps its existing log line. The entry point's line
    replaces nothing, but must not repeat the key.
- [ ] **Step 4: Update the stale comments** that state the old invariant:
  - `internal/host/apitoken.go:286-287` ("PAT paths resolve roles by sub");
  - `exchange.go:2497-2499` ("a /regex/ or `*` binding matches users and clients
    alike": add "unless the binding sets `subjectKinds`");
  - `roles.go:109-113` (matcher syntax);
  - `exchange.go:1070-1073` (the resolver list).
- [ ] **Step 5: Run the tests.** Run
  `go build ./... && go vet ./... && go test ./internal/... -count=1`.
  Expected: PASS, including the unchanged `roles_test.go` cases (field absent =
  old behavior).
- [ ] **Step 6: Commit** in kdex-host-manager:
  `feat(auth): resolve KDexRoleBinding roles with the subject's kind (#255)`.

### Task 4: host-manager — the client registry

**Files:**
- Create: `internal/auth/client_registry.go`
- Modify: `internal/auth/exchange.go` (`NewExchanger`, `NamesClient` and its doc
  comment, `Exchanger` struct)
- Test: `internal/auth/client_registry_test.go` (create; use the in-memory
  `cache.CacheManager`, plus a failing fake `Cache` for the error path)

**Interfaces:**
- Consumes: `cache.CacheManager`, `cache.Cache.Update` / `Get`,
  `cache.CacheOptions{MaxItems: new(0), Uncycled: true}`.
- Produces:
  - `func loadClientRegistry(ctx context.Context, cm cache.CacheManager, configured map[string]AuthClient) (map[string]struct{}, error)`:
    - atomically merges `configured`'s keys into one key of a surviving class,
      a JSON sorted array of ids, via `Update`;
    - then reads it back with `Get` and returns the set;
    - a nil `cm` returns just the configured ids.
    - Class and key names are yours (for example class `client-registry`, key
      `ids`).
  - The `Exchanger.formerClients map[string]struct{}` field, set in
    `NewExchanger`. `NewExchanger` returns the error if
    `loadClientRegistry` fails.
  - `NamesClient(key)`: true for a configured id, a `dcr_` prefix, or a member
    of `formerClients`. Do not record `dcr_` ids. `IsConfiguredClient` is
    unchanged (current config only).

- [ ] **Step 1: Write the failing tests.**
  - **`TestClientRegistry_MergesAcrossBuilds`**: build with clients {a, b}, then
    with {b, c} on the same cache manager. The second set is {a, b, c}.
  - **`TestClientRegistry_RemovedClientStillNamesClient`**: after the second
    build:
    - `NamesClient("a")` is true and `IsConfiguredClient("a")` is false;
    - `SubjectKindOf("a") == Client`;
    - `userBindingKey` for a user with sub `"a"` returns
      `ErrSubjectNamesClient`.
  - **`TestClientRegistry_ConcurrentBuildsLoseNothing`**: 8 goroutines build
    with disjoint client sets. The final set holds them all.
  - **`TestNewExchanger_RegistryFailureFails`**: a cache whose `Update` errors
    makes `NewExchanger` return an error (Review Focus 5).
  - **`TestClientRegistry_SkipsDCR`**: `loadClientRegistry` given a
    `dcr_`-prefixed key does not write it to the stored set, and `NamesClient`
    is still true for it by prefix.
- [ ] **Step 2: Run them to see them fail.** Run
  `go test ./internal/auth/ -run 'ClientRegistry|RegistryFailure' -v`.
  Expected: compile failure.
- [ ] **Step 3: Implement** as above. `NamesClient` stays lock-free: the
  registry map is built once per Exchanger and never written afterwards.
- [ ] **Step 4: Run the package.** Run `go test ./internal/... -count=1`.
  Expected: PASS.
- [ ] **Step 5: Commit:**
  `feat(auth): remember every client id a host has configured (#255)`.

### Task 5: host-manager — the kind travels with the credential

**Files:**
- Modify: `internal/auth/apitoken/apitoken.go` (`TokenData`, `MintStatelessKey`,
  `ValidateToken`)
- Modify: `internal/auth/context.go` (`ClaimSubjectKind`)
- Modify: `internal/auth/config.go` (`mintDecidedClaims`)
- Modify: `internal/auth/exchange.go`:
  - `reservedMintClaims`;
  - the OIDC signing context (~L691): strip `knd`;
  - set `knd` in every signing context: OIDC, local, auth-code, refresh,
    client_credentials, token exchange;
  - `MintResourcePAT` (~L608);
  - `ExchangeSubjectToken` reads the FAT's `knd`;
  - the new `PATAuthContext` and `ContextSubjectKind`.
- Modify: `internal/sign/sign.go` (re-assert `knd` after the mapper, where
  `auth_method` is, ~L233)
- Modify: `internal/auth/middleware.go` (`hostPATIdentity` uses
  `PATAuthContext`), `internal/host/proxy.go` (bridge uses `PATAuthContext`;
  the projected FAT carries `knd`)
- Modify: `internal/host/apitoken.go` (mint handler ~L504; verify ~L579)
- Modify: `internal/host/whoami.go`
- Test: create
  - `internal/auth/apitoken/apitoken_subjectkind_test.go`;
  - `internal/auth/pat_context_test.go`;
  - `internal/host/apitoken_subjectkind_test.go`.

  Update existing `MintStatelessKey` call sites mechanically.

**Interfaces:**
- Consumes: Task 3's `BindingSubject`, entry point and site constants; Task 4's
  `NamesClient`.
- Produces:
  - `TokenData.SubjectKind kdexv1alpha1.SubjectKind`, json `knd,omitempty`.
    Absent on older PATs → `""`.
  - `var ErrUnknownSubjectKind`, in `apitoken`.
  - `func (tm *TokenManager) MintStatelessKey(aud, sub string, kind kdexv1alpha1.SubjectKind, action, scope string, ttl time.Duration) (string, error)`:
    writes `knd`, and refuses `!kind.Known()` with `ErrUnknownSubjectKind`.
  - `const ClaimSubjectKind = "knd"`, in `context.go`.
  - `func (e *Exchanger) ContextSubjectKind(ac AuthContext) kdexv1alpha1.SubjectKind`,
    the one fallback chain:
    1. the context's `knd` if it is `Known()`;
    2. else `Client` if `ac.ClientCredentialsSubject()` reports a client;
    3. else `e.SubjectKindOf(sub)`.

    Steps 2–3 are `LEGACY(#N)`.
  - `func (e *Exchanger) PATAuthContext(ctx context.Context, data *apitoken.TokenData, site string) (AuthContext, error)`.
    It resolves:
    - the kind: `data.SubjectKind` if `Known()`, else `SubjectKindOf(data.Subject)`
      (`LEGACY(#N)`);
    - the roles, through the entry point with the given site;
    - the backend claims (not overwriting).

    It sets `knd`, and builds `{sub, roles, entitlements, scp, iat, knd}`. The
    middleware adds `EnrichAuthContext` and the proxy adds `PATBridgeClaim`;
    nothing else differs.

What each mint records:
- **`MintResourcePAT`**: `SubjectKindUser`.
- **`/-/apitokens/mint`:**
  - a self-mint (`subject == requestingSub`) records
    `exchanger.ContextSubjectKind(ac)`;
  - an impersonating or provisioned mint records `SubjectKindOf(subject)`.

Before editing, run `rg -n 'MintStatelessKey\(' --type go -g '!*_test.go'`.
Expected: `exchange.go:608` and `internal/host/apitoken.go:504` only. If there
are others, give each the kind of its subject, and note it in the commit body.

- [ ] **Step 1: File the LEGACY issue.** Run `gh issue create` in kdex-tech/host-manager,
  titled "Remove the kind-less credential fallback (#255)". Its body is the
  removal condition: once the longest PAT lifetime since the fleet ran v0.29.0
  has passed, `ValidateToken` refuses a PAT without `knd`, and both
  `LEGACY(#N)` fallbacks are deleted. Use its number for `#N` below.
- [ ] **Step 2: Write the failing tests.**
  - **`TestMintStatelessKey_RecordsSubjectKind`**: mint with `Client`, and
    `ValidateToken` returns `SubjectKind == Client`. Same for `User`.
  - **`TestMintStatelessKey_RefusesUnknownKind`**: `""` and `"ServiceAccount"`
    each return `errors.Is(err, ErrUnknownSubjectKind)`.
  - **`TestValidateToken_KindlessTokenDecodes`** (`LEGACY(#N)`): a token signed
    without `knd` (built in the test with the same key and claims minus `knd`)
    validates with `SubjectKind == ""`.
  - **`TestPATAuthContext_Kind`**:
    - a recorded `Client` resolves `[Client]` bindings and sets `knd: Client`;
    - a kind-less PAT for a configured client sub → `Client`;
    - a kind-less PAT for a user sub → `User`.
  - **`TestPATAuthContext_MiddlewareAndProxyAgree`**: one PAT through
    `hostPATIdentity` and through the proxy bridge yields the same `sub`, roles,
    entitlements and `knd`.
  - **`TestSelfMint_RecordsCallerKind`**: a client authenticated by
    client_credentials self-mints, and the PAT records `Client`. A user's
    self-mint records `User`.
  - **`TestMint_ProvisionedUserRecordsUser`**: a client minting for a
    provisioned user (reuse `apitoken_provisioned_test.go`'s setup) produces a
    PAT whose `SubjectKind == User`, and which gets `[User]` grants (Review
    Focus 4).
  - **`TestProxyFAT_CarriesKind`**: a FAT projected from a `Client` PAT carries
    `knd: Client`. `ExchangeSubjectToken` on it does not pick up `*` + `[User]`
    roles.
  - **`TestKindClaim_NotInjectable`**:
    - an OIDC id_token carrying `knd: Client` yields a session whose `knd` is
      `User`;
    - a claimMapping that targets `knd` does not change the signed token's
      `knd`.
  - **`TestWhoami_UsesContextKind`**: whoami for a `Client` PAT and for a
    client_credentials context excludes `[User]`-only entitlements.
  - **`TestVerify_OmitsEmptyKind`**: `/-/apitokens/verify` on a kind-less token
    has no `knd` key; on a new token it has `knd`.
- [ ] **Step 3: Run them to see them fail.** Run
  `go test ./internal/auth/... ./internal/host/ -run 'SubjectKind|PATAuthContext|SelfMint|ProvisionedUserRecordsUser|ProxyFAT_CarriesKind|KindClaim|Whoami_UsesContextKind|Verify_OmitsEmptyKind|KindlessToken|RefusesUnknownKind' -v`.
  Expected: compile failure / FAIL.
- [ ] **Step 4: Implement** the interfaces above.
  - `ValidateToken` reads `knd` with `GetString`, treating a missing claim as
    `""`, not an error. This is `LEGACY(#N)`.
  - The middleware and proxy call `PATAuthContext` with `SiteHostPAT` /
    `SiteProxyPAT`, replacing their duplicated sequence.
  - Token exchange resolves with `ContextSubjectKind` of the FAT's claims.
  - whoami resolves with `ContextSubjectKind(ac)` and `SiteWhoami`.
  - Update `TestResolutionSites_PassKinds`: token exchange, host PAT, proxy PAT
    and whoami now pass the carried kind. Add a case where the carried kind
    and `SubjectKindOf(sub)` differ, and assert the carried kind wins.
- [ ] **Step 5: Run the module.** Run `make test` (envtest included). Expected:
  PASS.
- [ ] **Step 6: Commit:**
  `feat(auth): credentials carry their subject kind (#255)`.

### Task 6: host-manager — the veto

**Files:**
- Modify: `internal/auth/exchange.go` (`VetoSubjectKind`, applied in
  `PATAuthContext` and `ExchangeSubjectToken`)
- Modify: `internal/auth/middleware.go` (`WithAuthentication`: after the gate
  parses a host JWT, before the context is stored)
- Test: `internal/auth/veto_test.go`, `internal/host/veto_test.go` (create)

**Interfaces:**
- Consumes: Task 4's `NamesClient`; Task 5's `ContextSubjectKind`,
  `PATAuthContext`.
- Produces:
  - `var ErrCredentialKindRefused`.
  - `func (e *Exchanger) VetoSubjectKind(sub string, kind kdexv1alpha1.SubjectKind) error`.
    It returns `ErrCredentialKindRefused`:
    - for kind `Client` when `!e.IsConfiguredClient(sub)`;
    - for kind `User` when `e.NamesClient(sub)`.

    Any other kind passes. Each refusal logs one V(0) line naming the rule and
    the site, never the sub.

Where it applies: `PATAuthContext`, which covers both PAT paths; the host JWT
gate in `WithAuthentication`, with the kind from `ContextSubjectKind`; and
`ExchangeSubjectToken`'s subject. A refusal is a 401, the same answer as an
invalid credential. Self-mint, `/-/oauth/authorize` and session-grant refresh
all arrive through the gate or a PAT, so they need no site of their own.

- [ ] **Step 1: Write the failing tests.** Each test configures client `c`,
  issues the credential, removes `c` from config, rebuilds the Exchanger on the
  same cache manager, then presents the credential. Present in every test:
  - an exact binding for `c`;
  - a `*` + `[User]` binding.

  Tests (Review Focus 2):
  - **`TestVeto_RemovedClientPATRefused`**: a `knd: Client` PAT, through the
    middleware and the proxy bridge.
  - **`TestVeto_RemovedClientKindlessPATRefused`**: a kind-less PAT, through
    the middleware and the proxy bridge (classified `Client` through the
    registry).
  - **`TestVeto_RemovedClientJWTRefused`**: a client_credentials JWT, at
    `WithAuthentication`.
  - **`TestVeto_RemovedClientFATExchangeRefused`**: a FAT projected from `c`'s
    PAT before removal, at `ExchangeSubjectToken`.
  - **`TestVeto_RemovedClientSelfMintRefused`**: `/-/apitokens/mint` with `c`'s
    JWT returns 401 and mints nothing.
  - **`TestVeto_RemovedClientAuthorizeRefused`**: `/-/oauth/authorize` with
    `c`'s JWT opens no session.
  - **`TestVeto_RemovedClientSessionGrantRefused`**: `c`'s JWT replayed as the
    session cookie gets no grants.
  - **`TestVeto_UserPATNamingClientRefused`**: a `knd: User` PAT whose sub is
    later configured as a client.
  - **`TestVeto_ConfiguredClientAccepted`**: with `c` still configured, each
    credential above is accepted. That is the control.
- [ ] **Step 2: Run them to see them fail.** Run
  `go test ./internal/auth/ ./internal/host/ -run 'TestVeto_' -v`. Expected:
  FAIL (every removed-client credential still accepted).
- [ ] **Step 3: Implement** as above.
- [ ] **Step 4: Run the module.** Run `make test`, then
  `GOTOOLCHAIN=go1.26.0 make lint` and `go mod tidy -diff`. Expected: all
  clean.
- [ ] **Step 5: Commit:**
  `feat(auth): refuse a credential whose kind current config contradicts (#255)`.

### Task 7: Docs

**Files:**
- Modify: `kdex-main-site/docs-app/content/src/en/031_Topics/031_security-and-access-control.md`
- Modify: `/home/rotty/projects/RSI/knowdrive-site/.claude/skills/kdex-kcnas/SKILL.md`
  (source) and `/home/rotty/.claude/skills/kdex-kcnas/SKILL.md` (installed)

- [ ] **Step 1: Check the skill copies first.** Run
  `diff /home/rotty/projects/RSI/knowdrive-site/.claude/skills/kdex-kcnas/SKILL.md /home/rotty/.claude/skills/kdex-kcnas/SKILL.md`.
  Expected: no output. If they differ, stop and report; don't pick a side.
- [ ] **Step 2: Main-site docs.** In the security doc's KDexRoleBinding section,
  add `subjectKinds`:
  - the values, and that absent means any kind;
  - the `*` + `[User]` example;
  - that every credential records its subject kind;
  - that removing a client refuses every live credential it holds;
  - that a removed client's id can't be reused by a user.
- [ ] **Step 3: The skill.** Make the same addition to the skill's
  KDexRoleBinding section, plus two operator rules:
  - apply the new CRD before applying `subjectKinds`, then check that the field
    stuck;
  - a client removed before v0.29.0 should be revoked with
    `{sub: <client id>, all: true}`.

  Copy it to the installed path, then confirm `diff` prints nothing.
- [ ] **Step 4: Commit** in kdex-main-site and in knowdrive-site:
  `docs: KDexRoleBinding subjectKinds (host-manager#255)`.

---

## Release (orchestrator, not a subagent task; needs the user's signing / go)

1. **Quad.**
   - Run it on host-manager from the last marker
     (`git log -1 --grep='^Quad-Range:'`, currently `545cabc..0036701`) to
     HEAD, and on kdex-crds and nexus over their new commits.
   - Fix the findings in a `fix(quad): …` commit.
   - Mark every covered repo with an empty
     `chore(quad): mark the A..B quad (#255)` commit carrying a `Quad-Range:`
     trailer.
2. **Tag host-manager** v0.29.0, and **tag nexus** on the new crds tag. Both are
   signed tags.
3. **Infra relay.** Send the fleet pin, plus the runbook:
   - install the new crds tag's CRDs on every cluster;
   - optionally, revoke any client removed before v0.29.0 within the last
     `maxTTL` with `{sub, all: true}`;
   - run the dev smoke test (spec §Release 5). Allow about 70 s for the
     session-grant cache.
4. **Site.** Tell the site session the release and the CRD are live, and that
   they can backfill `subjectKinds: [User]` on their `*` / `/^.*$/` bindings,
   then check the field stuck on every host.
5. **Memory.** Update the project memory.

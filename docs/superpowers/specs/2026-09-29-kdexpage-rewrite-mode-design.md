# KDexPage rewrite mode — design

- **Issue:** kdex-tech/host-manager#217 (folds in #201)
- **Date:** 2026-09-29
- **Repos:** kdex-crds (schema), kdex-host-manager (reconcile + serving), kdex-nexus-manager (crds bump + release only), kdex-main-site (docs)

## Goal

Add a third operating mode to `KDexPage` that **rewrites the request inside the server**. A rewrite page owns a path and serves the response of another KDexPage or KDexFunction on the same host. The browser's URL stays the same and no 3xx is sent.

The primary use is **alias / vanity URLs**, for example:
- `/docs/latest/…` serving `/docs/v3/…`;
- `/u/{user}` serving `/profile/{user}/`;
- legacy URLs kept alive without a visible redirect;
- one page reachable at several paths without duplicating the CR;
- a page-style URL in front of a KDexFunction's GET endpoint.

### Success criteria

- An author declares a rewrite page with a typed reference to a page or function, plus an optional path template. Requests to the rewrite page's routes return the target's response.
- Both authorization gates apply: the rewrite page's own `security`, then the target's. A rewrite never bypasses a target's requirements.
- A target that moves (its `basePath` changes) does not break the rewrite.
- These are surfaced as `Degraded` at reconcile, not discovered at request time: a missing target, a target that is itself a rewrite, an internal function, or an unknown path placeholder.
- No request can deadlock on `hh.mu`, including while `SetHost` runs at the same time.

## Operating modes after this change

| Mode | Selected by | Served by |
|---|---|---|
| HTML | `contentEntries` with a `main` slot; none of `mimeType`/`rewrite` | archetype composition (`pageHandlerFunc`) |
| Text | `mimeType` + `body` | template pipeline, `contentTypeFor` |
| **Rewrite** | `rewrite` | `rewriteHandler` re-dispatch (this design) |

Exactly one mode per page, enforced by CEL.

## 1. Schema (kdex-crds)

```go
// KDexPageSpec
// rewrite, when set, makes this page an internal alias of another KDexPage or
// KDexFunction on the same host. Mutually exclusive with contentEntries and
// mimeType/body.
// +kubebuilder:validation:Optional
Rewrite *RewriteSpec `json:"rewrite,omitempty" protobuf:"bytes,17,opt,name=rewrite"`

type RewriteSpec struct {
    // targetRef names the page or function whose response this page serves.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:XValidation:rule="self.name.size() > 0",message="rewrite.targetRef.name must not be empty"
    // +kubebuilder:validation:XValidation:rule=`self.kind == "KDexPage" || self.kind == "KDexFunction"`,message="'kind' must be either KDexPage or KDexFunction"
    TargetRef KDexObjectReference `json:"targetRef" protobuf:"bytes,1,req,name=targetRef"`

    // path is joined to the target's basePath with exactly one '/'. {name}
    // placeholders are substituted from this page's patternPath wildcards.
    // Empty means the target's own registered route (see §3).
    // +kubebuilder:validation:MaxLength=512
    // +kubebuilder:validation:Pattern=`^[^:?#]*$`
    // +kubebuilder:validation:XValidation:rule="!self.contains('//') && !self.split('/').exists(s, s == '..')",message="rewrite.path must not contain '//' or '..' segments"
    // +kubebuilder:validation:Optional
    Path string `json:"path,omitempty" protobuf:"bytes,2,opt,name=path"`

    // canonical, when true, adds `Link: <target URL>; rel="canonical"` to the
    // response so the alias does not compete with the target in search indexes.
    // +kubebuilder:validation:Optional
    Canonical bool `json:"canonical,omitempty" protobuf:"varint,3,opt,name=canonical"`
}
```

Decisions:
- **`targetRef.kind` is required and not defaulted.** The nexus-manager defaulter webhook runs with `failurePolicy: Ignore` (nexus-manager#57), so defaulting could silently not happen.
- **`targetRef.namespace` is ignored.** Targets are resolved in the page's own namespace, as with the page's other refs. Cross-namespace targets would cross host boundaries.
- **CEL mode rules** on `KDexPageSpec`. The existing HTML rule is amended, and the others are new:
  - `has(self.mimeType) || has(self.rewrite) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))` — the "HTML page must declare main" rule, amended.
  - `!(has(self.rewrite) && has(self.mimeType))` — rewrite excludes text.
  - `!has(self.rewrite) || !(has(self.contentEntries) || has(self.pageArchetypeRef) || has(self.overrideHeaderRef) || has(self.overrideFooterRef) || has(self.overrideNavigationRefs) || has(self.scriptLibraryRef))` — a rewrite page carries no content fields. They would be ignored, so accepting them would only mislead.
  - `!(has(self.mimeType) && has(self.patternPath))` — from #201. A text page registers only at its exact `basePath`, so `patternPath` is dead configuration there.
- **From #201:** fix the `Paths.PatternPath` doc comment (`types.go`). It still says "prefixed … by `/{l10n}`", but that wildcard has been replaced by per-language literal prefixes.
- **CEL cost:** every field these rules touch is bounded (`MaxLength` on `path`, the existing `MaxItems`/`MaxProperties` on lists and maps). The CRD must pass **envtest install**, because an unbounded field makes the whole CRD fail to install.

## 2. Reconcile (host-manager `internal/controller/kdexpage_controller.go`)

A rewrite page skips the archetype, header, footer, navigation and script-library resolution (it has none of them). `parentPageRef` is still resolved, because navigation placement uses it. Instead, the controller:

1. Resolves `spec.rewrite.targetRef` using the existing reference-resolution helpers (`ResolveKDexObjectReference` / `ResolvePage` style), in the page's namespace. A missing target produces the same not-found handling and requeue as other refs.
2. Adds a `Watches(...)` with `MakeHandlerByReferencePath(..., "{.Spec.Rewrite.TargetRef}")` for **KDexPage** and **KDexFunction**, so the rewrite page re-reconciles when its target appears, changes or disappears.
3. Sets `Degraded` with a distinct reason when:
   - the target is a KDexPage that is itself in rewrite mode (reason `RewriteTargetIsRewrite`; one hop only);
   - the target is a KDexFunction with `spec.internal: true` (reason `RewriteTargetInternal`; internal functions are never on the host mux);
   - `rewrite.path` contains a `{name}` that is not a wildcard name in this page's `patternPath` (reason `RewriteUnknownPlaceholder`).
4. Otherwise it proceeds as for other pages, handing the page to the host handler.

A target function that exists but is not Ready is **not** a page-level Degraded condition. The route answers 404 until the function is Ready (see §3). That matches how function routes themselves appear and disappear.

## 3. Serving (host-manager `internal/host`)

### Registration (`addHandlerAndRegister`)

Rewrite pages go through the same per-language registration loop as HTML pages. Route-collision ownership (`routes.claim`), `localized`, the non-default `/<lang>/…` routes and the default-language 301 therefore all apply unchanged. Paths register like HTML pages: `toFinalPath(basePath)` plus `patternPath`.

When the routes are rebuilt (`rebuildMuxSnapshot`), each rewrite page's target is looked up in the same in-memory state the rebuild already holds:
- **KDexPage target:** its current `basePath` and `localized` flag, from the rendered page set.
- **KDexFunction target:** `spec.api.basePath`, and only when the function is Ready and not internal (the same filter the function loop applies).

The resulting target base path is bound into the rewrite handler for that snapshot. If no target is found, the route is registered with a 404 handler that logs the reason at V(1). The target is never guessed.

### `rewriteHandler` (new file `internal/host/rewrite.go`)

For each request:

1. **Own gate.** Run the rewrite page's `security` check, with the same checker, fault handling (500 on a check that fails to run) and denial classification as the page gate. The gate block in `pageHandlerFunc` is extracted into a shared helper that both handlers call, rather than copied.
2. **Build the target path.** Substitute each `{name}` in `rewrite.path` with `r.PathValue(name)`. A `{rest...}` value may span segments. A substituted value that would introduce a `..` segment or `//` is refused with 400. `path.Clean` is **not** applied to the author's template (CEL already constrains it), only to the substitution check. Then join:
   - **Empty `path`:** dispatch to the target's *registered* form, so the mux never answers with a slash redirect, which would expose the target URL. That is `toFinalPath(basePath)` (trailing slash) for an HTML page target, the exact `basePath` for a text page target, and `basePath` for a function target.
   - **Non-empty `path`:** `strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(path, "/")`, exactly one slash at the seam. The author's trailing slash (or lack of one) is kept as written, because it decides which of the target's routes matches.
3. **Language.** For a KDexPage target whose `localized` is true, a request registered under a non-default `/<lang>` prefix goes to `/<lang>` + target path. Every other case, including the default language and every function target, goes to the bare target path.
4. **Canonical.** If `canonical: true`, set `Link: <scheme://host + target path>; rel="canonical"` before dispatching. The host comes from the request, the same way other absolute URLs in this package are derived.
5. **Loop guard.** If the request context already carries the rewrite marker, answer **508 Loop Detected**. Otherwise add the marker. Reconcile already prevents this case; the guard is a safety net for the time between a target changing mode and the next reconcile.
6. **Dispatch.** Clone the request (`r.Clone`), set `URL.Path` and `URL.RawPath`, keep `URL.RawQuery`, and call `ServeHTTP` on the **mux snapshot captured when the handler was built**, never `hh.Mux`. Authentication and `DesignMiddleware` have already run in the outer wrappers, so dispatching to the inner mux does not repeat them. The target's own handler, and so its own gate, runs as usual.

**Locking (hard requirement).** `rewriteHandler` never acquires `hh.mu`. `pageHandlerFunc` holds `hh.mu.RLock()` for the whole request. A handler that held it while dispatching into a page handler would take the RWMutex read lock twice, and that deadlocks once a writer (`SetHost` under `Lock`) queues between the two. Anything the handler needs (target base path, security requirements, language) is captured when the routes are built. The shared gate helper therefore must not take `hh.mu` itself: the page handler calls it while already holding the lock, and the rewrite handler calls it holding none. If the helper needs `hh` state, it takes a snapshot argument.

**Methods.** Only `GET` routes are registered, like every page. Non-GET requests to a rewrite path get the mux's usual 405/404.

### OpenAPI

Rewrite routes are registered in `/-/openapi` with summary and description "Alias of <target kind>/<name>" and a 200 response described generically ("Response of the target"). They do not reuse `regFunc`'s hard-coded `text/html` shape; that shape is the mistake #199 tracks for text pages. The operationId follows the existing `<name>[-pattern][-<lang>]-get` scheme.

## 4. nexus-manager

No code change. The KDexPage validator (content-entry template checks, root-page rule) and defaulter (ref `kind` defaults) accept rewrite pages as they are. The defaulter is deliberately **not** extended to `rewrite.targetRef` (see §1). nexus-manager takes the kdex-crds bump and a release.

## 5. Navigation and render

No change. A rewrite page appears in navigation only when it sets `navigationHints`, as today. `label` is still required (used for the nav entry and the OpenAPI summary), and `spec.tags` still project onto `PageEntry.Tags`.

## 6. Release choreography

This is a CRD serialization change (a new field, amended validation messages), so:
1. Land kdex-crds and run its `make test` (envtest CRD install included), then `./updateCrdUsage.sh -t`.
2. Run **`make test` in both host-manager and nexus-manager** against the bumped crds, not just `go build`. An amended validation message breaks downstream tests that pin it.
3. **Release both actors**, even though nexus-manager has no code diff.

## 7. Testing

- **kdex-crds (envtest):**
  - the CRD installs;
  - each mode rule accepts and rejects the intended combinations, including rewrite with each forbidden content field, and text with `patternPath`;
  - the `rewrite.path` pattern and CEL (`//`, `..`, `:`/`?`/`#`);
  - `targetRef.kind` values outside {KDexPage, KDexFunction} are rejected.
- **host-manager controller:** each Degraded reason (`RewriteTargetIsRewrite`, `RewriteTargetInternal`, `RewriteUnknownPlaceholder`, target missing); re-reconcile when the target is created, changes mode, or is deleted.
- **host-manager handler:**
  - page and function targets both serve the target's body;
  - an empty `path` to an HTML page target returns 200 from the target, with no 301/307;
  - query string preserved;
  - placeholder substitution, and a `..`/`//` value is refused with 400;
  - own gate denies before dispatch, and the target's gate denies after it (rewrite page public, target gated);
  - language: `/fr/alias/` goes to `/fr/target/` for a localized page target, the default language goes to the bare path, a function target is never prefixed;
  - `canonical: true` emits the `Link` header, the default emits none;
  - the loop marker gives 508;
  - no target in the snapshot gives 404;
  - no deadlock when the handler runs while `SetHost` runs, repeatedly (`-race`, bounded by a deadline);
  - route-collision ownership applies to rewrite routes.
- **OpenAPI:** rewrite routes are described as aliases, not `text/html`, and operationIds are unique.

## 8. Docs

- kdex-main-site: a "Page operating modes" section in the KDexPage docs covering HTML, text and rewrite, with a page-alias example (`/docs/latest/{rest...}`) and a function-alias example.
- kdex-kcnas skill: the same three-mode note in its KDexPage guidance.

## Out of scope

- Non-GET methods (a later additive `rewrite.methods`).
- Chains of more than one hop.
- Targets outside this host, absolute URLs, and `/-/` / `/.well-known/` system paths.
- Response-header overrides.
- Cross-namespace `targetRef`.

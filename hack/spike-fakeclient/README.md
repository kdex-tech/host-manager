# Task 0.1 spike: fake-client + reconcilers

Throwaway spike for Phase 0 of the unified `kdex` CLI design
(`docs/superpowers/specs/2026-05-31-kdex-unified-cli-design.md`). Question:
**can the existing host-manager reconcilers run in-process behind
`sigs.k8s.io/controller-runtime/pkg/client/fake.Client`, with the resulting
`HostHandler` state served by `internal/web/server`?**

## How to run

```sh
go run ./hack/spike-fakeclient
```

Success criterion: prints `status=200` and a recognizable HTML fragment.

## Result

**`status=200`, ~561 bytes of HTML containing the theme style block
(`:root { --spike: 1; }`) and the page content (`<p>SPIKE_HOME_CONTENT</p>`)
under the archetype's `<!doctype html>` skeleton.**

Page reconciler ran cleanly behind fake.Client and pushed exactly one entry
into `HostHandler.Pages`; the web server then rendered against that state on
GET `/`.

## What was tested

| Component                          | How                                                            | Result |
| ---------------------------------- | -------------------------------------------------------------- | ------ |
| Fixture decode (3 CR YAML files)   | `serializer.CodecFactory(scheme).UniversalDeserializer().Decode` | OK     |
| `fake.Client` with status subresource + objects                | `fake.NewClientBuilder().WithScheme(...).WithStatusSubresource(...).WithObjects(...).Build()` | OK |
| `cache.NewCacheManager("", focalHost, nil)` (in-memory) | direct                                                       | OK     |
| `host.NewHostHandler(c, focalHost, ns, log, cm)`        | direct                                                       | OK     |
| `KDexPageReconciler.Reconcile(ctx, req)` — two-pass    | direct, no Manager                                           | OK (Pages=1) |
| `KDexInternalHostReconciler.Reconcile`                  | NOT INVOKED                                                  | (see findings) |
| `HostHandler.SetHost(...)` to seed minimal host state   | direct                                                       | OK     |
| `server.New(":0", hostHandler)` + `httptest.NewServer`  | direct                                                       | OK     |
| `GET /` → 200 with rendered HTML                        | `http.Get` against test server                               | **OK** |

## Findings

### 1. controller-runtime Manager vs fake.Client

We did **not** attempt to start a `controller-runtime/pkg/manager.Manager`
with the fake client. The Manager's source-of-truth wiring assumes a real
`*rest.Config` — it dials the apiserver for watch streams, leader election,
informers, and the field indexer (which the fake client supports separately
via `WithIndex`). Direct `r.Reconcile(ctx, req)` invocation, as the task
scaffold blesses, was used instead. This is the pattern existing tests in
`internal/controller/*_test.go` use whenever they reach for fake.Client
(e.g. `kdexinternalpackagereferences_controller_test.go:84-86`).

### 2. Constructor signatures

| Symbol                           | Signature                                                                                       |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| `cache.NewCacheManager`          | `(addr, host string, ttl *time.Duration) (CacheManager, error)` — `addr==""` selects `InMemoryCacheManager`. |
| `host.NewHostHandler`            | `(c client.Client, name, namespace string, log logr.Logger, cm cache.CacheManager) *HostHandler`. |
| `server.New`                     | `(address string, hostHandler *host.HostHandler) *http.Server` — `Handler` is the composed handler; pass it to `httptest.NewServer` to test without binding. |
| `KDexPageReconciler` (fields)    | `Client, Configuration (configuration.NexusConfiguration), ControllerNamespace, FocalHost, HostHandler, RequeueDelay, Scheme`. |
| `configuration.LoadConfiguration` | `(file string, scheme *runtime.Scheme) NexusConfiguration` — returns embedded YAML defaults when file is missing; **requires `configuration.AddToScheme(scheme)`** at the call site or it panics with `no kind "NexusConfiguration" is registered`. |

### 3. fake.Client surprises (none fatal)

`fake.Client` from controller-runtime v0.21.x supported everything the page
reconciler exercises:

- **Status subresource**: declared at builder time via
  `WithStatusSubresource(&kdexv1alpha1.KDexPage{}, ...)`. `r.Status().Update()`
  in the deferred status flush works correctly.
- **Finalizers**: the reconciler's two-pass pattern (add finalizer + requeue,
  then real reconcile) works as in envtest.
- **Custom indexes**: not strictly required for `KDexPageReconciler.Reconcile`
  (the page handler reads its own CR by name). Would be required for the
  *host* reconciler (line 226 `client.MatchingFields{internal.HOST_INDEX_KEY: r.FocalHost}`).
  Adding them via `WithIndex` is straightforward.
- **List + cluster-scope resources**: `KDexClusterPageArchetype` lookup via
  `c.List(ctx, &list, client.MatchingLabels{...})` works.

### 4. Why we did NOT drive `KDexInternalHostReconciler.Reconcile`

The host reconciler (`kdexinternalhost_controller.go:93-665`) is ~570 LOC of
imperative orchestration that depends on multiple apiserver-only behaviors
that fake.Client cannot synthesize:

- **Deployment readiness gate** (`kdexinternalhost_controller.go:566-599`):
  it iterates created Deployments, waits for `DeploymentAvailable=True`, and
  returns `RequeueAfter` until satisfied. Nothing in fake.Client reconciles
  `appsv1.Deployment.Status`, so the host reconciler would loop indefinitely
  and never call `SetHost`.
- **Secret resolution** (line 151) requires per-secret-type material
  (PASETO keys, OIDC client info, NPM creds, etc.) to be present.
- **Auth pipeline** (lines 471-563) constructs `auth.Config`,
  `auth.RoleProvider`, `auth.Exchanger`. Each builder step has its own
  failure modes; producing a "valid empty" auth config is a multi-step puzzle
  separate from the spike's question.
- **Ingress/HTTPRoute reconciliation** (lines 459-469) writes networking
  resources we don't care about in the preview-tool context.

None of those are obstacles in principle — they're obstacles in *practice*
for a developer-side preview tool. **For the unified-CLI design we don't
need to run the host reconciler at all**: the preview tool can call
`SetHost(...)` directly with values projected from the user's YAML, which is
what `internal/host/empty_host_test.go` already does as a unit-test pattern.

The spike confirms this is the right shape: a single `SetHost(...)` call
plus the page reconciler is enough to drive a fully-rendered page through
the web server.

### 5. What the page reconciler needed from the spike

For `KDexPageReconciler.Reconcile` to succeed:

1. A `KDexPage` CR with non-empty `spec.hostRef.name` and `spec.contentEntries[main]`
   (kdex-crds validates `MinItems=1` + the XValidation that `main` slot exists).
2. A default archetype reachable via `ResolveOrDefaultPageArchetype` —
   either an explicit `spec.pageArchetypeRef` on the page, or a
   `KDexClusterPageArchetype` carrying `metadata.labels."kdex.dev/default" = "true"`.
   Without one, `archetypeObj` is nil and the reconciler nil-derefs at
   `kdexpage_controller.go:140` (`archetypeObj.GetGeneration()`). The spike
   synthesizes the cluster-scope default in code (see `defaultClusterPageArchetype`).
3. `configuration.AddToScheme(scheme)` so `LoadConfiguration` can decode the
   embedded YAML defaults.

### 6. Template-field gotcha

The archetype `spec.content` is a Go template with delimiters `[[` `]]`
(per `kdex.dev/crds/render/render.go`'s contract). Available fields are
defined on `render.TemplateData` (`kdex.dev/crds/render/types.go:53`).
Notably the slot map is `.Content` (**singular**), not `.Contents` — the
host handler's `Renderer{PageMap: ...}` populates `Content`, and a typo
yields a 500 from `text/template` rather than a panic. The spike's archetype
uses `[[.Content.main]]`.

## Decision: **PROCEED** to Phase 1

The spike answers both questions affirmatively:

1. **Reconcilers DO run cleanly behind `fake.Client`** when invoked
   directly via `r.Reconcile(ctx, req)`. The two reconcilers most relevant
   to the preview path — `KDexPageReconciler` and (by extension)
   `KDexInternalTranslationReconciler`/`KDexInternalUtilityPageReconciler`,
   all of which have the same simple "compute → call HostHandler method →
   set conditions → status update" shape — are compatible.
2. **The web server serves correctly from a populated `HostHandler`** —
   GET `/` returned a 200 with theme + page content end-to-end.

The one heavyweight reconciler (`KDexInternalHostReconciler`) does NOT need
to be driven from fake.Client: its job is to materialize cluster
infrastructure (deployments, ingresses, auth), most of which a developer
preview tool has no business creating. The preview can substitute a direct
`HostHandler.SetHost(...)` call that takes its inputs from the user's
YAML — exactly the pattern `internal/host/empty_host_test.go` already
uses for unit testing.

**Recommended Phase 1 shape:**

- For each user-supplied `KDexHost` / `KDexInternalHost` CR, project the spec
  fields into a single `HostHandler.SetHost(...)` call. Skip secrets/
  deployments/auth in dev preview unless the user opts in.
- For `KDexPage`, `KDexInternalTranslation`, `KDexInternalUtilityPage` CRs,
  load into the fake client and invoke the matching `Reconcile` directly
  (two-pass to clear the finalizer add). The handler-side state mutations
  (`HostHandler.Pages.Set`, `AddOrUpdateTranslation`, `AddOrUpdateUtilityPage`)
  are the actual product of those reconcilers — and they all work behind
  fake.Client.
- A default `KDexClusterPageArchetype` (and likely a default
  `KDexClusterUtilityPage` set) needs to be provided by the preview tool
  itself, since users typically don't bundle those with their own CRs.

**Out of scope for this spike (deferred to Phase 1):**

- Watching the user's workspace for CR changes and re-running reconcilers
  on edit (covered by the design doc §5).
- Browser auto-reload on render delta.
- Resolving `KDexApp` content entries that point at real OCI artifacts —
  the spike used a `rawHTML` static entry to avoid that whole code path.

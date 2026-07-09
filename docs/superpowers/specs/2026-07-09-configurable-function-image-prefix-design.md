# Configurable function-image path prefix (`FUNCTION_IMAGE_PREFIX`)

**Date:** 2026-07-09
**Status:** Approved — ready for implementation plan
**Repos touched:** `kdex-host-manager` (feature), `knowdrive-site` (first consumer)

## Problem

host-manager derives every function image's registry path as
`{ImageRegistry}/{HostRef.Name}/{function.Name}` — the host name is a
hardcoded path segment (`internal/build/build.go:52,54`, and the kpack
`Image` resource name at `:30`). For knowdrive-site that yields
`…/kdex-docker/rsi-dev/feedback` and `…/kdex-docker/rsi-prod/feedback` —
**different paths per environment**.

This blocks a clean promotion model. The intended lifecycle is: **dev
builds** a function (source-authoritative kpack), the image is
**verified**, then **promoted** for prod, and **prod runs only promoted
images** as pinned executables (`spec.origin.executable`, per the RSI
"all prod functions are executables" policy). With per-env paths,
promotion requires **copying** the image from `rsi-dev/<func>` to
`rsi-prod/<func>`. If instead dev and prod shared one path, promotion is
just **adding a tag** to the already-verified digest — no copy.

Artifact Registry IAM is repository-level (verified in
`infra/terraform/artifact_registry.tf`): `rsi-dev/` and `rsi-prod/` are
name prefixes inside the single `kdex-docker` repo, read by one puller
and written by one pusher. So a shared path needs **no IAM change** — the
only thing forcing per-env paths is host-manager's hardcoded segment.

## Goal / Non-goals

**Goal:** let an operator configure the function-image path prefix per
host-manager instance, so multiple hosts (e.g. `rsi-dev` + `rsi-prod`)
can share one function-image path and promote by tag alone.

**Non-goals:**
- The per-host **packages** OCI image (`internal/packref` /
  `…/{HostRef.Name}/packages`) is **out of scope** — dev and prod have
  different app sets, so their bundles are genuinely different content and
  are not promoted. Only **function** images change.
- No CRD/API change. The prefix is a host-manager **process env var**, not
  a `KDexHost` field (deliberate: it's an operator/deployment concern, and
  keeps the change to host-manager + its chart).
- No change to how `ImageRegistry` itself is sourced
  (`host.Spec.Registries.ImageRegistry`, a CR field).

## Design

### host-manager: `FUNCTION_IMAGE_PREFIX`

Introduce a single env var read once at startup: **`FUNCTION_IMAGE_PREFIX`**.
It is a literal prefix string that **includes its own trailing slash**
(so it can also be empty for a flat/root path).

Resolution of the prefix used for a function build:

| `FUNCTION_IMAGE_PREFIX` | Resolved prefix | Resulting path | Meaning |
|---|---|---|---|
| **unset** | `function.Spec.HostRef.Name + "/"` | `{reg}/rsi-dev/feedback` | **today's behavior — backward compatible** |
| `fn/` | `fn/` | `{reg}/fn/feedback` | shared namespace (knowdrive dev + prod) |
| `` (set empty) | `` | `{reg}/feedback` | flat / repo root |

`os.LookupEnv` distinguishes **unset** (→ host-name default) from **set
empty** (→ flat), so all three are expressible.

**`build.go` change** — replace the hardcoded segment with the resolved
prefix (note the format string drops the middle `/` since the prefix
carries its own):

```go
// Builder gains one field:
type Builder struct {
    client.Client
    ImageRegistry  string
    ImagePrefix    string // e.g. "rsi-dev/", "fn/", or "" (flat)
    Scheme         *runtime.Scheme
    ServiceAccount string
    Source         kdexv1alpha1.Source
}

// tag + additionalTags (was: "%s/%s/%s", registry, HostRef.Name, name):
"tag": fmt.Sprintf("%s/%s%s:latest", b.ImageRegistry, b.ImagePrefix, function.Name),
"additionalTags": []any{
    fmt.Sprintf("%s/%s%s:%d", b.ImageRegistry, b.ImagePrefix, function.Name, function.GetGeneration()),
},
```

The kpack `Image` **resource name** (`build.go:30`,
`fmt.Sprintf("%s-%s", HostRef.Name, function.Name)`) is a namespaced k8s
object name, not an image path — it stays as-is (unique per namespace, no
collision across dev/prod namespaces). Likewise the `kdex.dev/host` label
at `:140` stays the host name.

**Plumbing** — the resolved prefix must reach `Builder`. The controller
constructs the `Builder` and already sets `ImageRegistry` from
`hc.host.Spec.Registries.ImageRegistry`
(`kdexfunction_controller.go:~1169`). Read `FUNCTION_IMAGE_PREFIX` once at
startup into host-manager's config, thread it to the reconcile path, and
resolve at Builder-construction time:

```go
// pseudocode at Builder construction:
prefix := function.Spec.HostRef.Name + "/"   // default
if v, ok := cfg.FunctionImagePrefix(); ok {  // (value, wasSet)
    prefix = v                               // may be "" for flat
}
builder := &build.Builder{ /* … */, ImageRegistry: reg, ImagePrefix: prefix }
```

The exact config struct / startup wiring is an implementation detail for
the plan (mirror how existing env/flags are read in `cmd/` / `main.go`).

### host-manager chart: deliver the env var

The per-host host-manager Deployment is helm-managed; `KDexHost.spec.helm.
hostManager.values` flows into the chart. The chart must let an operator
set `FUNCTION_IMAGE_PREFIX` on the manager container. If the chart already
supports arbitrary env (e.g. an `extraEnv` list) use it; otherwise add
minimal `extraEnv` passthrough. Confirm during the plan.

### knowdrive-site: adopt `fn/`

1. **Set the env** on both hosts: `FUNCTION_IMAGE_PREFIX=fn/` in
   `k8s/dev/host.yaml` and `k8s/prod/host.yaml`
   `spec.helm.hostManager.values` (whatever passthrough the chart exposes).
2. **credcheck (executable / buildx path)** — `Makefile` `IMAGE_REPO`:
   `…/kdex-docker/rsi-dev/user-credential-check` →
   `…/kdex-docker/fn/user-credential-check`.
3. **Executable CR pins** — after rebuild, repoint the `image:` in
   `k8s/dev/function_user_credential_check.yaml` and
   `k8s/prod/function_user_credential_check.yaml` to the `fn/` path digest.

### Promotion workflow (tag-based)

With dev + prod sharing `…/fn/<func>`, only **dev** builds (kpack pushes
`:latest` + `:{generation}`). Promotion of a verified digest is a
same-repo tag add — no copy, no cross-path pull:

```
gcloud artifacts docker tags add \
  …/kdex-docker/fn/<func>@sha256:<verified> \
  …/kdex-docker/fn/<func>:prod
```

`:prod` is a **moving marker** for the current prod-approved build; prod
CRs still pin the immutable **digest** (`…/fn/<func>:prod@sha256:<d>` or
just `@sha256:<d>`) for reproducibility. A `make promote FUNC=<f>` helper
in knowdrive-site wraps: resolve dev's verified digest → `tags add :prod`
→ print the digest to pin. (Helper design is refined in the plan.)

This replaces the ad-hoc "Go-Live" step (prod pins whatever dev is
running): the very first use is to align credcheck via this flow.

## Backward compatibility

Every existing host-manager (kdex-main-site, any other site) runs with
`FUNCTION_IMAGE_PREFIX` **unset**, so the resolved prefix is
`HostRef.Name + "/"` — byte-identical paths and tags to today. No other
site rebuilds or repins. The behavior change is opt-in per host-manager
instance.

## Verification

1. Build + deploy the host-manager change to the **dev** cluster; set
   `FUNCTION_IMAGE_PREFIX=fn/` on the `rsi-dev` host.
2. **Source-authoritative functions** (`feedback`, `tenancy-service`,
   `user-service-{auth,admin,profile}`): trigger a rebuild (generation
   bump / reconcile) and confirm the kpack `Image` `spec.tag` and the
   running Knative image are now `…/kdex-docker/fn/<func>…`, and each
   `KDexFunction` returns to `Ready`.
3. **Executable function** (`user-credential-check`): `make functions-credcheck`
   pushes to `…/fn/user-credential-check`; pin the dev CR; confirm `Ready`.
4. Confirm **no** existing site regressed: a host with the env unset still
   builds to `…/{hostname}/<func>` (spot-check `Image.spec.tag`).
5. Exercise `make promote FUNC=user-credential-check` → `:prod` tag added
   to the verified dev digest → pin in prod CR → prod credcheck `Ready` on
   the `fn/` path.

## Rollout sequence

1. host-manager: implement `build.go` + config + chart env passthrough;
   ship a release (chart + image). No behavior change until an operator
   sets the env.
2. knowdrive-site dev: bump the host's host-manager to the new version,
   set `FUNCTION_IMAGE_PREFIX=fn/`, rebuild dev functions, verify (steps
   1–4 above). Dev is the proving ground before prod ever uses `fn/`.
3. knowdrive-site prod: set `FUNCTION_IMAGE_PREFIX=fn/` on `rsi-prod`,
   promote + pin credcheck (and, as later phases bring more functions to
   prod, promote each).

## Risks / considerations

- **Same-path `:latest` clobber.** Dev and prod share `…/fn/<func>`, but
  **only dev builds** (prod is executables), so only dev writes `:latest`
  / `:{gen}`. Prod reads by digest. No writer conflict. (If a future host
  both shares a prefix AND builds, the `:latest`/generation tags would
  race — out of scope; the promotion model assumes one builder per shared
  path.)
- **Empty-prefix collisions.** A flat (`""`) prefix places images at the
  `kdex-docker` root; safe only while no other root-flat host shares a
  function name. knowdrive uses `fn/` (namespaced), avoiding this.
- **Generation-tag semantics unchanged** — still
  `{prefix}{func}:{generation}`; only the prefix segment moved.
- **Chart env passthrough** is the one unknown; if absent it's a tiny
  additive chart change (no default behavior change).

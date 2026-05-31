# kcnas-preview — Design Spec

> **Status: SUPERSEDED** by [2026-05-31-kdex-unified-cli-design.md](2026-05-31-kdex-unified-cli-design.md).
> The unified design absorbs this preview spec as the `kdex preview` subcommand of a broader CLI that also includes `kdex codegen go`. Binary name changes from `kcnas-preview` to `kdex`; cmd path changes from `cmd/preview/` to `cmd/kdex/`; design content otherwise carries over. Refer to the unified spec for current direction.

**Date:** 2026-05-19
**Status:** Superseded (kept for historical context)
**Repo:** kdex-tech/host-manager (in-tree alongside the existing controller binary)

## 1. Overview

`kcnas-preview` is a single-binary developer-experience tool that renders KDexHost composition (theme + pages + archetypes + page-headers/footers/nav) from a directory of CRs on disk, served as a live-reloading local web server.

The tool reuses `host-manager`'s existing reconcilers and rendering pipeline in-process, backed by a fake Kubernetes client seeded from filesystem YAML. Local development artifacts (themes, apps) are wired in via explicit CLI flags or a config file; everything else either no-ops or surfaces helpful 4xx/5xx responses.

### Primary users

All three personas are served from the same binary:

- **Theme authors** — iterate on a theme's HTML/CSS/assets without packaging it as OCI and pushing it.
- **App authors** — iterate on an ES-module app composed into a representative page within a representative host.
- **Page/host composers** — preview KDexHost + KDexPage YAMLs that compose pre-built themes and apps without applying CRs to a cluster.

### In scope

- Page composition: theme + page + archetype expansion + page-headers/footers/nav merged into HTML.
- App-slot rendering with overrides; visible placeholder for unwired apps.
- Hot reload via fsnotify + WebSocket push.
- Kustomize-aware CR loading (flat-dir fallback).
- Explicit local overrides via CLI flags + `kcnas-preview.yaml` config file.
- Distribution as raw binary, Homebrew formula, and npm package (optional-dependencies pattern).

### Out of scope

- **Importmap generation** — `KDexInternalPackageReferences` resolution intentionally skipped; apps resolve via `--app` overrides.
- **Auth gate / PASETO / login / feedback widget** — `internal/host/login.go`, `internal/host/apitoken.go`, `internal/host/feedback.go`.
- **Proxy to backend services** — `internal/host/proxy.go`.
- **OpenAPI aggregation** — `internal/host/openapi.go`.
- **`KDexFunction` reconciliation** and kpack builds.
- **Browser-driven tests** (Playwright/headless Chromium) — possible future addition.
- **Multiple-host rendering in a single run** — v1 serves one KDexHost at a time. If `--crs` contains exactly one KDexHost it's selected automatically; if more than one is present, `--host <name>` is required and the loader exits with a clear error otherwise.

## 2. Architecture

```
                ┌────────────────────────────────────────────────────────────┐
                │  cmd/preview/main.go                                       │
                │                                                            │
  ./crs ─┐      │  ┌──────────────┐    ┌──────────────────┐                  │
         ├──▶   │  │ CR loader    │───▶│ fake client      │ ◀──┐             │
  --crs  │      │  │ (kustomize-  │    │ (client-go fake) │    │             │
         ┘      │  │  aware)      │    └────────┬─────────┘    │             │
                │  └──────────────┘             │              │             │
  fs events ──▶ │  ┌──────────────┐             ▼              │             │
                │  │ fsnotify +   │      ┌──────────────┐      │             │
                │  │ debouncer    │      │ existing     │──────┘  reconcile  │
                │  └──────┬───────┘      │ controllers  │         loop       │
                │         │              │ (in-process) │                    │
                │         │              └──────┬───────┘                    │
                │         │                     │                            │
                │         │                     ▼                            │
                │         │              ┌──────────────┐                    │
                │         │              │ internal/    │                    │
                │         │              │ cache        │                    │
                │         │              └──────┬───────┘                    │
                │         │                     │                            │
                │         ▼                     ▼                            │
                │  ┌──────────────┐      ┌─────────────────────┐             │
  WS ◀──────────│──│ reload hub   │◀─────│ internal/web/server │──▶ HTTP     │
                │  └──────────────┘      │ + override resolver │             │
                │                        │ + JS reload shim    │             │
                │                        └─────────────────────┘             │
                └────────────────────────────────────────────────────────────┘
```

### Data flow

1. **Boot.** Load CRs from `--crs` directory (kustomize-aware), seed the fake client, start an in-process controller-runtime manager with the existing reconcilers. They reconcile to steady state, populating `internal/cache` exactly as they would in production.
2. **Serve.** `internal/web/server` handles HTTP from the cache. The override resolver intercepts theme/app URL emission and substitutes local-override URLs. A small `<script>` shim is injected into rendered HTML; it opens a WebSocket to the reload hub.
3. **Reload.** fsnotify watches `--crs` and each local-override path. On change: 250ms debounce, re-run loader, diff against fake-client state, apply create/update/delete via the fake client. Reconcilers re-run via their watches. After reconcile drains, the reload hub broadcasts `{"type":"reload"}` to all connected WS clients.

### Why fake-client and not envtest

- Smaller binary footprint (no embedded apiserver+etcd binaries).
- Faster startup (no apiserver+etcd boot).
- Sufficient fidelity for the rendering pipeline, since controllers consume CRs and produce in-memory cache entries — they don't depend on apiserver behavior beyond the Reader/Writer interfaces.

**Risk:** controllers may have latent assumptions about a live API server (watch event semantics, resource versions, status subresource quirks) that fake-client doesn't replicate. **Mitigation:** phase-0 spike validates this against one realistic fixture before committing to the full plan. Fallback paths: narrow patches to the controllers, or switch to `envtest`.

## 3. Components

### Reused as-is from `internal/`

- `internal/controller/*` — all reconcilers run unchanged behind the fake client.
- `internal/cache/*` — populated by reconcilers, read by the web server. No changes.
- `internal/host/*`, `internal/page/*` — composition logic.
- `internal/web/server/*` — HTTP serving. Gains two narrowly-scoped extension points (see §3 hookpoints): a constructor option for an HTML-response middleware, and a constructor option for an override resolver. Both default to nil, preserving the production code path.

### Reused conditionally (stubbed in preview mode)

- `internal/host/proxy.go`, `internal/host/openapi.go`, `internal/host/login.go`, `internal/host/apitoken.go`, `internal/host/feedback.go` — registered with replacement handlers that return `501 Not Implemented` with a helpful message.

### New code

All under `cmd/preview/` and a new `internal/preview/` package tree:

| Package | Responsibility |
|---|---|
| `cmd/preview/main.go` | Entrypoint, flag/config parsing, wires the rest. |
| `internal/preview/loader/` | Reads `--crs` dir, runs kustomize if `kustomization.yaml` is present, parses into typed CR objects, returns a snapshot. |
| `internal/preview/fakeclient/` | Wrapper around `sigs.k8s.io/controller-runtime/pkg/client/fake`; knows how to seed/diff/apply snapshots. |
| `internal/preview/watcher/` | fsnotify wrapper with debounce; watches CR dir + override paths; emits events on a channel. |
| `internal/preview/resolver/` | Override registry loaded from flags + config. Exposes `ResolveTheme(name) → URL` and `ResolveApp(name) → URL \| Placeholder`. |
| `internal/preview/reload/` | WS hub + JS shim asset; broadcasts `reload` when reconcile drains. |
| `internal/preview/config/` | `kcnas-preview.yaml` schema + loader. |
| `internal/preview/stubs/` | 501 handlers for out-of-scope routes. |

### Hookpoints in existing code

Two narrowly-scoped, gated changes to reused code:

1. **HTML response middleware** in `internal/web/server` that injects `<script src="/__preview/reload.js"></script>` before `</body>`. Active only when constructed in preview mode (controlled by a constructor option, not a build tag, so the production binary path is identical to today).
2. **Theme/app URL emission point** (likely in `internal/host/page.go` or `internal/page/page.go`): consults the override resolver if injected. A `nil` resolver means prod behavior, which is the default. This is the only intrusive change to reused composition code, and it's gated.

The phase-0 spike confirms these are the only two hookpoints needed.

## 4. Local-override resolution

### CLI flags

```
kcnas-preview \
  --crs ./crs \                                         # required
  --addr :8080 \                                        # default :8080
  --host my-host \                                      # optional; required if >1 KDexHost in --crs
  --theme mytheme=./themes/mytheme \                    # repeatable
  --app myapp=http://localhost:5173/src/main.js \       # repeatable
  --app shared=./apps/shared/dist/index.js \            # local path → served by preview
  --config ./kcnas-preview.yaml \                       # optional
  --missing-app placeholder|skip|error                  # default: placeholder
```

### Config file (equivalent, persistent)

```yaml
addr: :8080
crs: ./crs
host: my-host
themes:
  mytheme: ./themes/mytheme
apps:
  myapp: http://localhost:5173/src/main.js
  shared: ./apps/shared/dist/index.js
missingApp: placeholder
```

Flags override config-file values. CLI is for ad-hoc; config file is for committing into a project alongside `make preview`.

### URL substitution

- **Theme override pointing at a local path:** the preview serves the theme dir at `/__preview/themes/<name>/*` and the resolver returns that URL.
- **Theme override pointing at `http(s)://`:** returned as-is — lets you point at a separate dev server.
- **App overrides:** same model — local path served at `/__preview/apps/<name>/*`, http URLs passed through.
- **Path overrides are watched** (§5) so editing the theme or app triggers a reload.
- **Local-path serving:** filesystem-rooted with traversal protection. `http.FileServer` over the resolved absolute path. Symlinks escaping the root are rejected.

### Missing-app behavior

With `missingApp: placeholder` (default), the resolver returns a sentinel that the page renderer emits as:

```html
<div class="kcnas-preview-missing-app" data-app="myapp">
  App "myapp" is not overridden.
  Pass --app myapp=URL or set apps.myapp in kcnas-preview.yaml.
</div>
```

Styled via the same CSS asset that ships the reload-error overlay, so it's visually obvious without being ugly.

`missingApp: skip` omits the script tag entirely. `missingApp: error` exits nonzero at boot if any referenced app is unresolved (useful for `--check`-style CI later, though `--check` itself is out of v1 scope).

## 5. Hot reload protocol

### Watched paths

- `--crs` directory (recursive).
- Every local path appearing in `--theme` / `--app` overrides.
- The config file if `--config` is given.

### Debounce

250ms quiet period before reacting. Editor save patterns (format-on-save firing twice in quick succession) shouldn't double-trigger.

### Pipeline on event

1. Re-run loader to produce a new CR snapshot.
2. Diff against current fake-client state; apply create/update/delete via the fake client's `Client` interface.
3. Wait for reconcile to drain. Mechanism: a controller-runtime event-source counter, or a short fixed delay (~100ms). Phase-0 spike picks the simplest workable approach.
4. Reload hub broadcasts `{"type":"reload"}` to all connected WS clients.

### JS shim

`/__preview/reload.js`, ~30 lines:

- Opens `ws://host/__preview/ws`.
- On `{"type":"reload"}`: calls `location.reload()`.
- On `{"type":"error", "message": "..."}`: shows a fixed-position overlay banner (à la Vite's error overlay). Previous good render stays on screen — degraded but useful.
- On disconnect: exponential-backoff reconnect (so restarting the binary doesn't leave dead tabs).

### Error surfacing

Loader/validation errors during reload do not crash the server. They're broadcast as `{"type":"error",...}` and the shim renders the overlay. Server keeps serving the last good render. Errors are also logged to the binary's stderr.

## 6. Stubbing strategy

For out-of-scope features the goal is "fail loudly but helpfully," not "silently pretend."

All stubbed handlers register at their normal routes and return:

```
HTTP/1.1 501 Not Implemented
Content-Type: text/plain

kcnas-preview does not serve <feature>.
This endpoint requires a live cluster: <one-line "what would normally happen here">.
```

**Routes stubbed:** the proxy mount point, OpenAPI aggregation routes, login/feedback/apitoken routes.

**Reconcilers handled specially:** `KDexFunction` and `KDexInternalPackageReferences` reconcilers are registered with the manager but no-op'd via a `--preview-mode` boolean on the reconciler struct. Reason: registering them keeps the scheme + RBAC + indexers consistent so other controllers' joins don't fail; no-op'ing avoids attempting kpack / Artifact Registry / NPM-registry calls that would error. Phase-0 spike validates this — if no-op-with-registration is messy, fall back to skipping registration entirely (likely fine for page composition).

## 7. Distribution

### Build (in-repo)

- `cmd/main.go` stays as the host-manager entry (no rename).
- New `cmd/preview/main.go` for the preview binary.
- Makefile target `build-preview` produces `dist/kcnas-preview-<os>-<arch>`.
- `goreleaser.yaml` extended with a second binary block. Both binaries ship under the same release tag, as separate archive entries.

### Homebrew

- Tap repo `kdex-tech/homebrew-tap` (created or reused; check in phase 4).
- `Formula/kcnas-preview.rb` points at the goreleaser-published darwin + linux archives.
- `brew install kdex-tech/tap/kcnas-preview`.

### npm

- Package `@kdex-tech/kcnas-preview`.
- `package.json` declares `bin: { "kcnas-preview": "./bin/kcnas-preview.js" }`.
- Per-arch sub-packages (`@kdex-tech/kcnas-preview-linux-x64`, `-darwin-arm64`, etc.) listed in `optionalDependencies`. npm installs only the matching one. The JS shim resolves the platform package and execs the binary inside it.
- **Why not postinstall-download:** that pattern fails behind corporate proxies and is the #1 complaint for tools like `puppeteer`. Optional-deps requires more upfront setup but is more robust.

### Raw binaries

GH release archives + SHA256 checksums for users who want neither brew nor npm.

### Platforms shipped at v1

- `darwin-arm64`
- `darwin-amd64`
- `linux-arm64`
- `linux-amd64`

Windows is not in v1 scope but can be added later — no architectural blockers.

## 8. Testing

### Unit

- `loader`: kustomize-aware path + flat-dir path; multi-doc YAML splitting; namespace inference.
- `resolver`: flag + config parsing, override precedence, URL substitution rules, missing-app sentinels.
- `watcher`: debounce semantics, override-path tracking, config-file reload.
- `fakeclient`: snapshot diff (creates, updates, deletes) against existing state.

### Integration

Start the preview server against fixtures under `internal/preview/testdata/` and hit pages with `net/http/httptest`. Assert rendered HTML contains expected slots / placeholders / theme assets. Target ~5–10 fixture scenarios:

1. Single theme + single page, no apps.
2. Single theme + page with archetype.
3. Theme + page-headers/footers/navigation composition.
4. App slot with `--app` override (local path).
5. App slot with `--app` override (remote URL).
6. App slot with no override → visible placeholder.
7. Kustomize overlay (base + dev overlay).
8. Multi-doc YAML in a single file.
9. CR change triggers reload (WS message asserted via Go WS client).
10. Loader error triggers error overlay (WS error message asserted).

### Browser-driven testing

Out of scope for v1. The WS reload protocol is exercised via a Go WS client in integration tests. Adding Playwright is a possible v2 enhancement.

## 9. Phasing

| Phase | Scope | Duration | Exit criterion |
|---|---|---|---|
| **0. Spike** | Boot existing controllers under fake-client with a hand-coded fixture; render one page. No flags, no kustomize, no hot reload. Throw it away. | 1 day | Page renders with theme + composition correct. If blocked → escalate to envtest decision before phase 1. |
| **1. MVP** | Loader (flat dir only), fake-client wiring, override resolver, web server with stubs, override URL serving, manual-refresh. | ~1 week | `kcnas-preview --crs ./fixtures` renders a multi-page host with theme + app overrides. |
| **2. Hot reload** | fsnotify + debouncer + WS hub + JS shim + error overlay. | ~3 days | Editing a CR or local theme file reloads the browser within 1 second. |
| **3. Kustomize + config file** | krusty integration + `kcnas-preview.yaml`. | ~2 days | Kustomize overlay tree works; config file equivalence with flags. |
| **4. Distribution** | goreleaser config, brew formula, npm optional-deps package, release docs. | ~3 days | `brew install` and `npm i -g` both produce a working binary on the four target platforms. |

**Total:** ~2.5 weeks engineering time, consistent with the "B" scope option from brainstorming.

## 10. Open questions deferred to implementation

- **Reconcile-drain detection.** Counter vs. fixed delay vs. callback. Phase-0 spike picks the simplest working approach.
- **Naming.** `kcnas-preview` is the working name. Alternatives: `kdex-preview`, `kdh-preview` ("KDex host preview"). Decide before phase 4 ships releases; renaming after public release is costly.
- **`KDexFunction` / `KDexInternalPackageReferences` reconciler handling.** Register-and-no-op vs. skip-registration. Phase-0 spike confirms which works.
- **Brew tap repo.** Use existing kdex-tech tap if present; create one in phase 4 if not.

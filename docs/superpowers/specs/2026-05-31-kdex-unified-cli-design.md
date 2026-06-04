# `kdex` — Unified CLI Design Spec

**Date:** 2026-05-31
**Status:** Draft, pending implementation plan
**Repo:** kdex-tech/host-manager (in-tree alongside the existing operator binary)
**Supersedes:** [2026-05-19-kcnas-preview-design.md](2026-05-19-kcnas-preview-design.md)

## 1. Overview

The unified `kdex` CLI addresses three developer-experience friction points across the KDex SDLC, all of which currently force the developer into a cluster round-trip to validate work:

1. **Function API** (OpenAPI spec → scaffolding) — handled by `kdex codegen <lang>`.
2. **Function code** (handler implementation) — happens in the user's editor; the CLI ensures the surrounding project is buildable/runnable after one command, with no intermediate language-specific tooling step.
3. **KCNAS runtime** (KDexHost composition preview) — handled by `kdex preview`.

### v1 scope

- `kdex preview` — local KCNAS-runtime preview server (carry-over of the [2026-05-19 design](2026-05-19-kcnas-preview-design.md), reframed as a subcommand). **Now includes the function-proxy override** (`--fn name=URL`) — closes the editor→browser SDLC loop. Promoted from v2 after the phase-0 spike confirmed the architecture supports it cleanly; see §4.5.
- `kdex codegen go` — Go function scaffolding generator. Independent reimplementation of `kdex-fngogen`, parity-tested via golden files against fngogen's `test-fixtures/`. Coexists with kdex-fngogen until cluster cutover (Phase 8).

### v2 territory (out of v1 scope; named here to prevent feature creep)

- `kdex codegen node` — defer until the first KDex Node function lands. No current usage of kdex-fnnodejsgen.
- `kdex package` — port of kdex-cli-tools (OCI artifact packaging).
- Bash script-bundle tools (kdex-node-tools).

### Permanently out of scope

These are non-goals — naming them prevents future scope creep:

- Generic OpenAPI code generation for arbitrary HTTP servers. KDex is FaaS-focused.
- Non-FaaS deployment targets (no support for plain VM / generic K8s Deployment scaffolding).
- Customizable templating or plugin systems. Templates are embedded and curated.
- Opt-out of KDex security defaults. Security is determined by the OpenAPI spec, not by codegen flags.

### Design principles

These shape every section that follows; they are not commentary.

- **Spec-first strict adherence.** OpenAPI is the source of truth. Regenerated files never tolerate drift; preserved files are explicit, bounded, and never re-touched. The set of preserved files is small and documented (§6).
- **KDex security as default.** Generated middleware mirrors the spec's `security` declarations using the exact runtime keys host-manager's `internal/auth/` already speaks (§7). No KDex-specific security extension is introduced; the OpenAPI spec is the sole voice.
- **FaaS from the ground up.** Generated output assumes Knative runtime, CNB build via `project.toml`, single-binary deployment, and the FAAS adaptor's env-var contract (`AUDIENCE`, `ISSUER`, `JWKS_URL`, `PKS_URL`, `ANONYMOUS_ENTITLEMENTS`, `DEFAULT_SECURITY_SCHEME`). No knobs to disable this.

## 2. Repo & binary structure

The repo keeps its current name (`kdex-host-manager`), accepting the imperfect fit between the name and the broadened contents. A rename is a one-time pain that doesn't pay back against not-doing-it.

Two binaries ship from the same module:

- **`host-manager`** — the existing operator. Cmd path renamed from `cmd/main.go` to `cmd/host-manager/main.go` for cmd-tree symmetry.
- **`kdex`** — the new unified CLI. Cmd at `cmd/kdex/main.go`. Subcommands `preview` and `codegen <lang>`.

```
kdex-host-manager/
├── cmd/
│   ├── host-manager/main.go     # operator binary (renamed from cmd/main.go)
│   └── kdex/main.go             # unified CLI entry, cobra root
├── internal/
│   ├── cache/                   # manager (existing)
│   ├── controller/              # manager (existing)
│   ├── host/                    # manager (existing)
│   ├── page/                    # manager (existing)
│   ├── web/                     # manager (existing)
│   ├── preview/                 # NEW: crosses the manager boundary
│   │   ├── loader/
│   │   ├── fakeclient/
│   │   ├── watcher/
│   │   ├── resolver/
│   │   ├── reload/
│   │   ├── config/
│   │   └── stubs/
│   └── tools/                   # NEW: tools subtree
│       └── codegen/             # none of this imports manager internals
│           └── gogen/
│               ├── parse/       # OpenAPI ingestion (kin-openapi)
│               ├── analyze/     # op/scheme/schema records
│               ├── emit/        # template-driven file emission
│               ├── ogen/        # ogen-as-library invocation
│               ├── preserve/    # preserved-file contract
│               └── templates/   # embedded text/template files
├── docs/superpowers/specs/
└── ...
```

### Boundary semantics

The "tools vs. manager" boundary the design calls for is encoded in the directory shape, not Go visibility:

- `internal/tools/codegen/*` imports only stdlib and external libraries; **never** imports from `internal/cache/`, `internal/controller/`, `internal/host/`, `internal/page/`, or `internal/web/`. Enforced by code review.
- `internal/preview/*` is the documented exception that crosses the boundary. It must import manager internals to do its job (reusing the reconciler + cache + page composition).
- A linter rule (`go vet` import-restrictions or similar) can be added to mechanize this if drift becomes an issue.

## 3. CLI shape

### Library

[cobra](https://github.com/spf13/cobra). Reasons:
- Shell completion comes free.
- Subcommand discoverability is well-supported.
- Every Go CLI of meaningful size uses it (`kubectl`, `helm`, `tofu`, etc.).
- `cobra-cli` scaffolding accelerates skeleton work.

### Top-level structure

```
kdex                                # root cmd, prints help
├── preview                         # preview the KCNAS runtime locally
│   --crs <dir>                     # required
│   --addr :8080                    # default
│   --host <name>                   # optional; required if >1 KDexHost in --crs
│   --theme <name>=<path|URL>       # repeatable
│   --app <name>=<path|URL>         # repeatable
│   --config <path>                 # optional kdex-preview.yaml
│   --missing-app placeholder|skip|error   # default: placeholder
└── codegen                         # generate function scaffolding
    └── go                          # only language in v1
        --spec <path>               # required (OpenAPI 3.x JSON or YAML)
        --target <dir>              # required
        --module <go module path>   # required; e.g. kdex.dev/fns/my-fn
        --force                     # rewrite preserved files (with confirmation)
        --yes                       # bypass confirmation prompts
```

`kdex codegen` without a `<lang>` subcommand prints a help-style "available languages" list, so new languages have a discoverable home.

### Help text

Every subcommand has long-form help that explicitly states what's in scope and what's not. The "permanently out of scope" items appear in `kdex codegen go --help` so users don't ask for features that won't come.

During v1 development, `kdex codegen go --help` carries a top-line `EXPERIMENTAL — see <spec link>` banner until parity is reached.

## 4. Preview subcommand — deltas from the 2026-05-19 spec

Everything in the 2026-05-19 spec carries over except:

| Aspect | Old (kcnas-preview spec) | New (kdex preview) |
|---|---|---|
| Binary name | `kcnas-preview` | `kdex` (preview is a subcommand) |
| Invocation | `kcnas-preview --crs ...` | `kdex preview --crs ...` |
| Cmd path | `cmd/preview/main.go` | `cmd/kdex/main.go` (preview lives in the CLI dispatch tree under cobra) |
| Config filename | `kcnas-preview.yaml` | `kdex-preview.yaml` |
| Internal Go package | `internal/preview/*` | `internal/preview/*` (unchanged) |
| Distribution | npm package `@kdex-tech/kcnas-preview`, brew `kcnas-preview` | npm package `@kdex-tech/kdex`, brew `kdex` |
| Existing operator cmd | `cmd/main.go` (unchanged) | `cmd/host-manager/main.go` (renamed for symmetry with `cmd/kdex/`) |
| Function proxying | Out of scope (proxy stubbed with 501) | **In scope.** `--fn name=URL` overrides resolve KDexFunction proxy targets to a locally-running developer process; see §4.5 |

Unchanged from the 2026-05-19 spec:

- Architecture (in-process controller-runtime with fake client).
- Hot reload (fsnotify + debouncer + WebSocket + JS shim + error overlay).
- Override resolver (CLI flags + config file; theme/app local paths or URLs).
- Kustomize-aware loading with flat-dir fallback.
- Missing-app placeholder behavior.
- Phase-0 spike to validate fake-client + existing reconcilers.

Changed from the 2026-05-19 spec:

- **Function proxy now in scope** (was: 501 stub). Proxy routes for KDexFunction CRs resolve via the new `--fn` override map (§4.5) instead of Knative Service URLs; falls back to the placeholder pattern when an override is missing. Auth/login/feedback/OpenAPI routes remain stubbed as 501.

## 4.5 Function-proxy override

The `--fn name=<path|URL>` flag (repeatable, mirrors `--app` and `--theme`) lets a developer wire a KDexFunction's proxy target to either a locally-running process (URL form, for tunnels / IDE-debug processes / already-running replicas) or — the recommended form — to a directory containing a `kdex codegen go`-produced project, in which case **preview supervises the function process itself**.

The directory form is the dev-friendly path: one command starts the whole local KCNAS host, no separate `tmux` pane per function, no port-tracking, no env-var setup. The URL form stays as a fallback for non-supervised cases.

### Why this is in v1

Phase 0's fake-client spike confirmed the architecture composes cleanly: reconcilers run in-process behind `fake.Client`, `HostHandler.SetHost(...)` is called directly from CR data, and the existing `internal/host/proxy.go` middleware reads its route targets from `HostHandler`. Wiring overrides into that resolution path is a small surgical change, not a separate subsystem. Original deferral to v2 was conservative; the spike removed the uncertainty. The directory-supervision refinement adds a small process-management layer on top of that without touching the proxy semantics.

### CLI shape

```
kdex preview \
  --crs ./crs \
  --fn checkout=./functions/checkout \       # directory form (recommended)
  --fn search=./functions/search \
  --fn legacy=http://localhost:9000 \        # URL form (fallback)
  ...
```

In the config file (`kdex-preview.yaml`):

```yaml
functions:
  checkout: ./functions/checkout             # directory
  search:   ./functions/search               # directory
  legacy:   http://localhost:9000            # URL
```

A value is resolved as a directory if it is a filesystem path that exists and is a directory; otherwise it must parse as an `http(s)://` URL. Anything else is rejected at boot with a clear error.

### Language detection (directory form)

For each directory-form override, preview inspects the directory's contents to choose a spawn command:

| Detected file | Spawn command | Notes |
|---|---|---|
| `go.mod` | `go run .` (run from the directory) | v1: only Go is supported via `kdex codegen go`. |
| `package.json` with `scripts.dev` | `npm run dev` | v2 once `kdex codegen node` lands. Listed here so the language-detection contract is forward-compatible. |
| (neither) | error at boot | "Function `<name>` directory `<path>` is not a recognized KDex function project (no `go.mod`)." |

Detection is local to the override; there is no project-wide config. Mixed languages in one preview invocation are fine.

### Process supervision (directory form)

For each directory-form `--fn`, preview:

1. **Allocates an ephemeral port** by binding `:0`, reading the assigned port, then closing the listener (the function will rebind it). This avoids the user needing to declare or de-conflict port numbers.
2. **Spawns the function child** with `PORT=<ephemeral>` and with `AUDIENCE` / `ISSUER` / `JWKS_URL` / `PKS_URL` **intentionally unset** (see "Auth handling" below). Child stdout/stderr stream through preview's log output with a `[<fn-name>]` prefix.
3. **Waits for the child to bind its port** before forwarding any proxy traffic to it. Default timeout: 30 seconds (configurable via `--fn-startup-timeout`). Cold-start of a non-trivial Go function via `go run` can take 2–10s — the wait avoids serving `502` to the user's first browser request.
4. **Plugs `http://localhost:<ephemeral>` into `HostHandler`** the same way a URL-form override would. From the proxy middleware's perspective, supervised and non-supervised overrides are indistinguishable.
5. **Owns the child's lifecycle.** On preview shutdown (SIGINT/SIGTERM, browser disconnect is irrelevant), preview sends SIGTERM to each child and waits up to 5 seconds before SIGKILL. If a child crashes during the session, preview marks the function as "unhealthy" and routes its proxy traffic to a 502-with-banner page that names the function and surfaces the last 20 lines of the child's stderr.

If preview itself dies abnormally (e.g., panic), the OS process group reaper handles child cleanup; preview sets `Setpgid` on each spawn so children can be killed as a group. Orphan processes from killed-preview runs are documented in the README as a known edge case for v1.

### Resolution semantics

Preview applies the same "skip the reconciler that doesn't compose; synthesize state directly" pattern the spike validated for `KDexInternalHost` (see `hack/spike-fakeclient/README.md`):

- **`KDexFunctionReconciler` is skipped** in preview mode. Production resolves a function's proxy URL from KDexFunction `Status.URL` (the Knative Service URL stamped by the FaaS adaptor). In preview, no Knative serving = no status URL.
- **Loader walks `KDexFunction` CRs** from `--crs` and matches each to the override map. Matched (directory or URL): the resolved URL is plugged into the proxy route table via `HostHandler` directly. Unmatched: emits a missing-function placeholder (see below).
- **`internal/host/proxy.go` middleware is unchanged.** It reads target URLs from the `HostHandler` route table the same way it does in production; whether the URL came from a real Knative Service, a `--fn` URL override, or a preview-supervised child is opaque to the proxy itself. This minimizes the change surface and keeps preview's proxy behavior faithful to prod.

### Auth handling

Per §1 design principles, KDex security is spec-driven and not opt-out. In preview, the developer is running their function without the production auth substrate (no JWKS endpoint, no PASETO public-key set, no Knative-stamped service account).

- **The proxy middleware does not mint a per-Service FAT audience in preview mode.** Forwarded requests reach the override URL without the `Authorization` headers the FAAS adaptor would normally inject.
- **For directory-form overrides**, preview deliberately omits `AUDIENCE` / `ISSUER` / `JWKS_URL` / `PKS_URL` from the child's environment. The `kdex codegen go`-emitted middleware (§7) treats missing vars as "no security expected" — matches the case where the OpenAPI spec declares no `security` block. The developer's function therefore runs auth-permissive without any opt-in flag.
- **For URL-form overrides**, the developer is responsible for the running process's auth posture. Acceptable patterns: (a) run the function with the auth env vars unset (same as supervised case); (b) a dev-mode variant that short-circuits auth checks (e.g. behind a `KDEX_DEV=1` env).

Pattern (a) is the path of least resistance for spec-first functions and is what `kdex codegen go`'s emitted code naturally supports.

### Missing-function behavior

Mirrors missing-app (§5 in the 2026-05-19 spec; carried over):

- `missingFn: placeholder` (default) — the proxy returns a styled HTML stub for routes whose function isn't overridden: "Function `checkout` is not overridden. Pass `--fn checkout=<path|URL>` or set `functions.checkout` in `kdex-preview.yaml`."
- `missingFn: skip` — proxy returns `502 Bad Gateway` with no body. Useful when previewing a page whose function dependencies aren't ready yet.
- `missingFn: error` — preview boot fails if any referenced function lacks an override. Useful for `--check`-style CI validation later.

### Hot reload

In **Phase 2 (Preview MVP, manual refresh)**, preview supervises function children with spawn-once semantics: they're started on boot and torn down on shutdown. Source changes inside a function directory don't trigger any action; the developer kills+restarts preview (or sends SIGHUP, if supported) to pick up function-code edits. Equivalent to the manual-refresh behavior of CR changes in Phase 2.

In **Phase 3 (Hot reload)**, fsnotify scope expands to cover **`--crs`**, **`--theme` paths**, **`--app` paths**, **and `--fn` directory paths** uniformly. Source change inside a function dir → kill child → respawn → wait for port → WS broadcast `reload`. Build errors (e.g. `go run` compile failures) stream to the same WS error overlay used for CR validation errors; the previous good function instance stays alive until the new one binds (or until a configurable build-error timeout elapses, after which the proxy serves the unhealthy-fn 502 page).

Adding/removing entries via the config file is also picked up in Phase 3 — the watcher already covers the config file. Changing a URL-form `--fn` to a directory-form (or vice versa) triggers a tear-down + respawn of that function only.

### Phase 2 scope summary

For clarity on what's deferred to Phase 3 vs. shipped in Phase 2:

| Concern | Phase 2 (MVP) | Phase 3 (Hot reload) |
|---|---|---|
| CR change detection | Browser refresh only | fsnotify + WS reload |
| Theme/app path change | Browser refresh only | fsnotify + WS reload |
| Function source change | Restart preview manually | fsnotify + kill child + respawn + WS reload |
| Function startup wait | Yes (block until port bound or timeout) | Yes |
| Function crash detection | Yes (route to unhealthy-fn 502) | Yes |
| Build error surfacing | Logged to preview stdout | Logged + WS error overlay |

## 5. Codegen subcommand — architecture

### Goal

`kdex codegen go --spec X --target Y --module Z` produces a project tree where `cd Y && go build ./...` succeeds with no intermediate steps. No `go generate`, no separate ogen invocation, no manual `go mod tidy`.

### Pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│  internal/tools/codegen/gogen                                        │
│                                                                      │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌─────────────────┐  │
│  │ parse   │───▶│ analyze  │───▶│ emit     │───▶│ preserve check  │  │
│  │         │    │          │    │          │    │                 │  │
│  │ kin-    │    │ ops, sec │    │ template │    │ checksum-vs-    │  │
│  │ openapi │    │ schemes, │    │ rendering│    │ first-emit;     │  │
│  │         │    │ schemas  │    │          │    │ skip preserved  │  │
│  └─────────┘    └──────────┘    └────┬─────┘    └────────┬────────┘  │
│                                      │                   │           │
│                                      ▼                   ▼           │
│                              ┌──────────────┐    ┌──────────────┐    │
│                              │ ogen library │    │ writer       │    │
│                              │ (in-process) │    │ (fs ops)     │    │
│                              └──────┬───────┘    └──────────────┘    │
│                                     │                                │
│                                     └──── api/*.go directly ────────▶│
└──────────────────────────────────────────────────────────────────────┘
```

### Stages

1. **parse** — Load the OpenAPI 3.x document via `kin-openapi`. Validates the spec; refuses to proceed on invalid input. Both JSON and YAML accepted.
2. **analyze** — Walk operations, security schemes, schemas. Produce typed analysis records consumed by both `emit` and the ogen invocation. Centralizes the OpenAPI→Go-template-data mapping so emit and ogen invocation can't disagree about, e.g., which operations need security middleware.
3. **emit** — Render scaffold files from embedded `text/template` templates. (Note: `text/template`, not `html/template` — fngogen uses `html/template` and works around its escaping; we avoid that class of bug from the start.) Files emitted:
   - `cmd/main.go` (regenerated)
   - `cmd/default.go` (regenerated — 501 implementation)
   - `cmd/custom.go` (preserved — user's implementation)
   - `cmd/security.go` (regenerated — security middleware wiring)
   - `go.mod` (preserved after first emit, when user-added deps appear)
   - `project.toml` (regenerated — CNB metadata)
   - `Dockerfile` (regenerated — optional; cluster path uses kpack, but local dev may want this)
4. **ogen invocation** — Call ogen's Go API as a library to produce `api/*.go`. ogen exposes a programmatic generator that takes a parsed spec and an output FS. Using it that way avoids the `go generate` step and the implicit `go run github.com/ogen-go/ogen/cmd/ogen@latest` chain that today's `entry-point.sh` relies on. Phase-0 spike validates that ogen's library API is sufficient. **Fallback if library API is insufficient:** bundle the ogen binary inside the `kdex` image and `kdex` package, and invoke it via subprocess. PATH-dependence is rejected because it breaks the "one command, project is buildable" promise — users of `kdex codegen go` must not need to install ogen separately.
5. **preserve check** — For each emitted file, compute SHA-256 of the rendered content. Compare against `.kdex/codegen-manifest.json`. Resolve to a per-file action (§6).
6. **writer** — Apply writes. Emit a summary: `generated: 8 files, preserved: 1 (cmd/custom.go), skipped: 0`. Non-zero exit on any write failure.

### Why ogen as library, not subprocess

The "one command, project is buildable" promise breaks if codegen depends on ogen being installed separately. Linking ogen statically means the `kdex` binary ships everything needed for codegen, including the heavy OpenAPI→Go mapping logic.

This is a load-bearing assumption. The phase-0 spike must validate that ogen's library API can be driven from in-process Go and produces output equivalent to the CLI invocation. If it can't, we fall back to subprocess + a bundled ogen binary (binary size penalty) before committing to phase 6.

### Why kin-openapi for parse, but ogen for type-tree emit

`kin-openapi` is the de-facto Go OpenAPI parser; it has good validation and is widely used. ogen's strength is the OpenAPI→Go-types-and-server mapping. Using both means each tool handles what it's best at; the small cost is two passes over the spec (one in our `parse` stage, one inside ogen).

## 6. Spec-first preservation contract

### File classes

- **Regenerated** — overwritten on every `kdex codegen go` run. Examples: `cmd/main.go`, `cmd/default.go`, `cmd/security.go`, `api/*.go`, `project.toml`, `Dockerfile`. The user can edit these, but their edits will be silently overwritten on the next run. The spec is the source of truth.
- **Preserved** — written once on first emission; never touched again unless `--force`. Examples: `cmd/custom.go`, `go.mod` (after the user adds deps), `go.sum`, `.gitignore`.

### Manifest

`kdex codegen go` writes `.kdex/codegen-manifest.json` to the target dir:

```json
{
  "version": "1",
  "specHash": "sha256:...",
  "kdexVersion": "<the kdex binary version that wrote this file>",
  "files": {
    "cmd/main.go":             { "class": "regenerated", "lastEmitHash": "sha256:..." },
    "cmd/custom.go":           { "class": "preserved",   "firstEmitHash": "sha256:..." },
    "go.mod":                  { "class": "preserved",   "firstEmitHash": "sha256:..." },
    "api/oas_handlers_gen.go": { "class": "regenerated", "lastEmitHash": "sha256:..." }
  }
}
```

### Drift resolution

For each file on subsequent runs:

| Class | On-disk hash matches manifest? | New rendered content matches? | Action |
|---|---|---|---|
| regenerated | yes | yes | skip (no-op write) |
| regenerated | yes | no  | overwrite |
| regenerated | no  | (any) | overwrite (user-edited a regenerated file; their edit is lost, by design) |
| preserved | (any) | (any) | skip (preserved files are never touched after first emit) |

`--force` overrides the preserved-class skip behavior and rewrites everything from scratch. Without `--yes`, `--force` prompts for confirmation listing every preserved file that will be overwritten.

### Why this design enforces strict spec adherence

Regenerated files never accumulate human edits. The set of preserved files is small, named, and bounded — every other file is owned by the spec. There is no path by which the spec and the generated code drift apart silently.

## 7. Security defaults

The OpenAPI spec is the sole voice on security. The generator emits middleware that strictly mirrors what the spec declares.

### Determination

- **Top-level `security`** in the spec sets the default for every operation that doesn't override.
- **Operation-level `security`** overrides for that operation.
- **No security declared on an operation (and no top-level default)** → no security middleware wired for that route. The route is publicly accessible.

No KDex-specific extension exists to express "no auth." The OpenAPI spec is sufficient on its own.

### Recognized schemes

These map onto the runtime keys that host-manager's `internal/auth/` already speaks. The keys match fngogen's existing `TemplateData` fields exactly (`APIKeyCookieSecurity`, `APIKeyHeaderSecurity`, `APIKeyQuerySecurity`, `BearerSecurity`, `OAuth2Security`, `OpenIdConnectSecurity`), so golden-file parity testing validates the mapping by construction.

| OpenAPI scheme | KDex middleware emitted | Runtime key | Env vars |
|---|---|---|---|
| `type: http, scheme: bearer` | JWT validation (golang-jwt/jwt/v5) | `bearer` | `JWKS_URL`, `AUDIENCE`, `ISSUER` |
| `type: apiKey, in: cookie` | PASETO V4 Public validation | `apiKeyCookie` | `PKS_URL`, `AUDIENCE`, `ISSUER` |
| `type: apiKey, in: header` | PASETO V4 Public validation | `apiKeyHeader` | `PKS_URL`, `AUDIENCE`, `ISSUER` |
| `type: apiKey, in: query` | PASETO V4 Public validation | `apiKeyQuery` | `PKS_URL`, `AUDIENCE`, `ISSUER` |
| `type: oauth2` | OAuth2 scope-based authorization | `oauth2` | `JWKS_URL`, `AUDIENCE`, `ISSUER` |
| `type: openIdConnect` | OIDC discovery-based authorization | `openIdConnect` | `JWKS_URL`, `AUDIENCE`, `ISSUER` |

### Entitlements

Wired per operation when the operation declares the `x-kdex-entitlements` extension with a list of required entitlement keys. This extension is the only KDex-specific OpenAPI extension the generator consumes; it is security-additive (it tightens, never loosens, the spec's `security` declarations).

### Runtime env-var contract

Baked into the emitted `cmd/main.go`:

| Var | Required? | Notes |
| --- | --- | --- |
| `PORT` | optional | Default `8080`. |
| `AUDIENCE` | required if any security scheme used | JWT/PASETO audience claim. |
| `ISSUER` | required if any security scheme used | Issuer claim. |
| `JWKS_URL` | required for bearer/oauth2/openIdConnect | JWKS endpoint. |
| `PKS_URL` | required for any apiKey scheme | PASETO public key set endpoint. |
| `ANONYMOUS_ENTITLEMENTS` | optional | Space-separated entitlements granted to all callers. |
| `DEFAULT_SECURITY_SCHEME` | optional | Default `bearer`. Disambiguates when multiple schemes apply. |

Required-vs-optional is determined statically from which schemes the spec actually uses; the emitted code's startup-time validation reflects that.

## 8. Parity test harness for codegen

### Source of truth

`kdex-fngogen`'s `test-fixtures/` directory. Each fixture is an `openapi.json` paired with the canonical expected output tree.

### Test pipeline

```
internal/tools/codegen/gogen/parity_test.go

for each fixture in fngogen/test-fixtures/*:
    1. Run in-tree `kdex codegen go --spec <fixture>/openapi.json --target <tmp>/<fixture>`
       via direct package call, not exec.
    2. Run `kdex-fngogen ...` via subprocess against a tmp dir.
       Binary built once and cached. If not on PATH and KDEX_FNGOGEN_BIN unset,
       mark the test SKIPPED with a clear message rather than failing.
    3. Walk both trees; for each file emitted by either side:
       - normalize: gofmt both, strip trailing whitespace
       - diff
    4. If diffs exist, write them to t.TempDir() and fail with a pointer.
```

### Normalization rules

- `gofmt` applied to both sides before compare (eliminates trivial formatting drift).
- Line endings normalized to LF.
- Trailing whitespace stripped.
- `go.mod` compared by dep set + version constraints, not literal text.
- `.kdex/codegen-manifest.json` excluded from diff (metadata, expected to differ).

### Status reporting

The test logs a parity matrix on every run:

```
PARITY MATRIX (8 fixtures)
  t1: PASS  (12/12 files match)
  t2: PASS  (12/12)
  t3: PASS  (13/13)
  t4: FAIL  (28/29 — api/oas_handlers_gen.go diverges, see /tmp/.../t4.diff)
  ...
```

### CI integration

- During v1 development (phases 6–7), parity test runs on every PR touching `internal/tools/codegen/gogen/`. Failures are informational, not blocking — the parity goal is staged.
- Once parity reaches 100%, the test gates merge.

### Cluster cutover criterion

Parity reaches 100% across all fngogen fixtures **and** a one-week confidence period passes during which `kdex codegen go` is preferred over `kdex-fngogen` in dev usage with no regressions. At that point, `knative-deployer`'s `entry-point.sh` is updated to call `kdex codegen go` (via the `ghcr.io/kdex-tech/kdex` image, §9), and `kdex-fngogen` is archived.

## 9. Distribution

### Build (in-repo)

- `cmd/host-manager/main.go` (renamed from `cmd/main.go`)
- `cmd/kdex/main.go` (new)
- Makefile targets `build-host-manager` and `build-kdex` produce `dist/host-manager-<os>-<arch>` and `dist/kdex-<os>-<arch>`.
- `goreleaser.yaml` extended with two binary blocks. Both ship under the same release tag, as separate archive entries.

### Container images

The existing `Dockerfile` is reorganized into a multi-stage build that produces two images:

- `ghcr.io/kdex-tech/host-manager:<tag>` — operator image, unchanged consumers. The helm chart references this.
- `ghcr.io/kdex-tech/kdex:<tag>` — thin image (~30MB target) containing the `kdex` binary only. This is the image `knative-deployer`'s codegen Job will invoke once the cluster cuts over (Phase 8), replacing the kdex-fngogen image.

### Homebrew

- Tap repo `kdex-tech/homebrew-tap` (verify or create during phase 5).
- `Formula/kdex.rb` points at the goreleaser-published darwin + linux archives.
- `brew install kdex-tech/tap/kdex`.

### npm

- Package `@kdex-tech/kdex`.
- `package.json` declares `bin: { "kdex": "./bin/kdex.js" }`.
- Per-arch sub-packages (`@kdex-tech/kdex-linux-x64`, `-darwin-arm64`, etc.) listed in `optionalDependencies`. npm installs only the matching one; the JS shim resolves the platform package and execs its binary.
- Rationale: the postinstall-download pattern (used by puppeteer) fails behind corporate proxies. Optional-deps is more robust.

### Raw binaries

GH release archives + SHA256 checksums for users who want neither brew nor npm.

### Platforms shipped at v1

- `darwin-arm64`
- `darwin-amd64`
- `linux-arm64`
- `linux-amd64`

Windows: not in v1; no architectural blockers.

## 10. Testing

### Unit tests

**Preview:**
- `loader`: kustomize-aware + flat-dir; multi-doc YAML splitting; namespace inference.
- `resolver`: flag + config parsing, override precedence, URL substitution rules, missing-app sentinels.
- `watcher`: debounce semantics, override-path tracking, config-file reload.
- `fakeclient`: snapshot diff (creates, updates, deletes) against existing state.

**Codegen:**
- `parse`: kin-openapi happy paths; invalid-spec rejection; YAML and JSON acceptance.
- `analyze`: security-scheme mapping (the table in §7); operation-level vs top-level security; `x-kdex-entitlements` extension consumption.
- `emit`: template rendering; preserved-vs-regenerated file classification.
- `preserve`: manifest read/write; drift resolution decisions per the §6 table; `--force` behavior.

### Integration tests

**Preview:** start the preview server against fixtures under `internal/preview/testdata/` and hit pages with `net/http/httptest`. ~5–10 scenario fixtures covering page composition, kustomize overlays, missing apps, hot-reload WS messages, error overlays. (Identical to the 2026-05-19 spec's testing section.)

**Codegen:** the parity harness (§8) is the primary integration test. Supplemented by a small set of "synthetic spec" tests for things fngogen doesn't currently cover (edge cases the parity tests can't exercise because no fixture demonstrates them).

### Browser-driven testing

Out of scope for v1. The preview WS reload protocol is exercised via a Go WS client in integration tests.

## 11. Phasing

| Phase | Scope | Duration | Exit criterion |
|---|---|---|---|
| **0. Spike** | (a) Boot existing controllers under fake-client with a hand-coded fixture; render one page. (b) Invoke ogen as a library against a minimal OpenAPI fixture; produce buildable Go. Throw both away. | 1–2 days | (a) Page renders correctly; (b) ogen library API is sufficient and `go build ./...` works on the output. If (a) blocked → escalate to envtest decision. If (b) blocked → escalate to subprocess invocation with a bundled ogen binary. |
| **1. Restructure** | Rename `cmd/main.go` → `cmd/host-manager/main.go`. Add `cmd/kdex/main.go` with cobra scaffolding; `preview` and `codegen go` registered as stub subcommands. Update Makefile, Dockerfile (multi-stage; two images), CI. Verify host-manager still builds + tests pass. | 1 day | `make build-host-manager build-kdex` produces both binaries; `make test` for host-manager passes; chart still references unchanged image. |
| **2. Preview MVP** | Loader (flat dir only), fake-client wiring, override resolver (theme + app + **function**), web server with stubs, override URL serving, **function-proxy supervision (dir-based spawn-once + URL fallback per §4.5)**, manual-refresh. | ~1.5 weeks | `kdex preview --crs ./fixtures --fn checkout=./functions/checkout` renders a multi-page host where preview supervises the local function child and routes proxy traffic to it. URL form (`--fn name=http://...`) also works as a fallback. |
| **3. Preview hot reload** | fsnotify + debouncer + WS hub + JS shim + error overlay; watcher covers `--crs`, `--theme`, `--app`, **and `--fn` directories**. Function-source change → kill child + respawn + WS reload (§4.5). | ~5 days | Editing a CR, theme, app, or function-source file reloads the browser within 1–3 seconds (3s upper bound accounts for `go run` recompile on function-source change). |
| **4. Preview kustomize + config file** | krusty integration + `kdex-preview.yaml`. | ~2 days | Kustomize overlay tree works; config file equivalence with flags. |
| **5. Distribution v1** | goreleaser config, brew formula, npm optional-deps package, container images, release docs. v1 ships with `kdex preview` GA and `kdex codegen go` marked experimental in `--help`. | ~3 days | `brew install` and `npm i -g` both produce a working binary on the four target platforms. |
| **6. Codegen MVP** | Parse, analyze, emit (scaffold templates), ogen-as-library integration, preserve check, manifest. Parity reaches ≥50% of fngogen `test-fixtures/`. | ~1 week | `kdex codegen go --spec X --target Y` produces a buildable project from at least 4 of fngogen's fixtures with byte-identical (post-normalization) output. |
| **7. Codegen parity** | Close remaining parity gaps; gate CI on parity. | ~3–5 days | All fngogen fixtures pass parity diff. |
| **8. Cluster cutover** | Confidence period elapsed (1 week of dev usage). Update `knative-deployer`'s helm chart to call `kdex codegen go` via the `ghcr.io/kdex-tech/kdex` image instead of kdex-fngogen. Archive kdex-fngogen repo. | ~1 day | Cluster path runs `kdex codegen go`; fngogen retired. |

**Total v1 calendar:** ~4 weeks (phases 0–5; `kdex` GA-ships with preview + dir-supervised function-proxy, codegen experimental). Phase 3 grew from ~3 days to ~5 days to absorb function-source restart logic alongside CR/theme/app reload.
**Total to cluster cutover:** ~5.5–6.5 weeks (phases 0–8).

## 12. Open questions deferred to implementation

- **Reconcile-drain detection** (preview). Counter vs. fixed delay vs. callback. Phase-0 spike picks the simplest workable approach.
- **`KDexFunction` reconciler handling** (preview). Phase-0 spike resolved: skip the reconciler entirely and populate `HostHandler` proxy routes directly from `KDexFunction` CR data + `--fn` overrides (§4.5). Mirrors the spike's recommended pattern for `KDexInternalHostReconciler`.
- **`KDexInternalPackageReferences` reconciler handling** (preview). Register-and-no-op vs. skip-registration. Phase-0 spike confirms in Phase 2.
- **ogen library API sufficiency** (codegen). Phase-0 spike validates; subprocess fallback is the contingency.
- **`go.mod` regeneration policy** (codegen). Initially "preserve after first emit," but if the embedded deps list drifts (e.g., we change a runtime library version), do we ask the user to rerun with `--force` or do we update only the version pins while preserving user-added deps? Decide before phase 6 ships.
- **Brew tap repo** (distribution). Verify whether `kdex-tech/homebrew-tap` exists; create during phase 5 if not.
- **Linter for the manager-boundary import restriction** (structure). Choose a tool (`go vet` rule, `depguard`, custom) before merging phase 1.

## 13. Migration narrative (one-sentence summary)

Add a unified `kdex` CLI to host-manager that subsumes the standalone preview tool and a fresh-port of fngogen's codegen logic. Ship preview (now including the function-proxy override that closes the editor→browser SDLC loop) to GA and codegen as experimental in v1. Keep kdex-fngogen running the cluster path until parity is reached; then cut the cluster over and archive fngogen.

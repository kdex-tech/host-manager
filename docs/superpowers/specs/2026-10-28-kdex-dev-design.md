# `kdex dev` — Local Function Development Design Spec

**Date:** 2026-10-28
**Status:** Draft, pending implementation plan
**Repo:** kdex-tech/host-manager (in-tree, under the unified `kdex` CLI)
**Amends:** [2026-05-31-kdex-unified-cli-design.md](2026-05-31-kdex-unified-cli-design.md). It promotes `kdex preview --fn` from v2 into v1 and makes it a first-class subcommand.
**Contract:** [kdex-crds `FUNCTION_CONTRACT.md`](https://github.com/kdex-tech/kdex-crds/blob/main/FUNCTION_CONTRACT.md) (the host side of that contract is what this command emulates)

## 1. Why

Developer velocity on platforms like Cloudflare Workers comes mostly from rarely needing to deploy. `wrangler dev` runs your code locally, behind the platform's real request handling, with emulated bindings, and reloads on save. You deploy to share work, not to test it.

KDex has no equivalent today. A function only sees real requests behind host-manager, because host-manager owns:
- routing by `basePath`;
- the entitlement gate and `x-entitlement-binding`;
- `claimMappings`;
- minting the Function Access Token (FAT);
- the PASETO bridge;
- token exchange.

So every iteration that touches auth or routing needs a cluster round trip: build, push, deployer Job, Knative rollout. The `kdex preview` design deliberately stubs exactly these routes with `501`s (2026-05-19 spec §6). It is a page and theme tool, not a function tool.

`kdex dev` closes that gap.

> **Edit a handler or the function's `spec.api`, and within about 2 seconds `curl` or the browser hits it through a local host-manager that authenticates, gates, binds, mints the FAT and proxies, exactly as the cluster would.**

## 2. Scope

### In scope (v1)
- A local host built from CRs on disk (the `preview` foundation), with the **function routes live**: proxy, `/-/openapi`, login, `/-/token`, `/-/apitokens/*`, `/.well-known/{jwks,pks}.json`.
- Local identities from `subject` Secrets and KDexRole/KDexRoleBinding CRs in `--crs`.
- Running a function locally from a directory: codegen on `spec.api` change, rebuild and restart on source change.
- Attaching an already-running function by URL, e.g. one under a debugger.
- `spec.env` resolved from Secrets and ConfigMaps in `--crs`. `secretKeyRef` and `configMapKeyRef` work.

### Out of scope (v1, named to prevent creep)
- Knative semantics: scale-to-zero, cold starts, concurrency, revisions and traffic.
- `spec.volumes`, `serviceAccountName` and workload identity. These are reported as **not emulated** at startup. Use local credentials.
- `spec.backend.type=Service` functions, except through `--fn <name>=url:…`.
- Bindings (KV/SQL/objects/queues/cron). These are a later design. When they land, `kdex dev` is where their local emulation goes.
- Building or pushing images, and deploying (`kdex deploy`, a later spec).

## 3. CLI shape

```
kdex dev
  --crs <dir>                       # required; KDexHost, KDexFunction(s), pages, Secrets, roles…
  --host <name>                     # required if --crs holds >1 KDexHost
  --addr :8080                      # the local host's address; also its ISSUER
  --fn <name>=<dir>                 # repeatable; run function <name> from source in <dir>
  --fn <name>=url:<http://…>        # repeatable; attach an already-running function
  --config <path>                   # optional kdex-dev.yaml (flags win)
  # everything `kdex preview` accepts (--theme, --app, --missing-app) also applies
```

`kdex-dev.yaml` mirrors the flags. It adds a per-function `run:` for runtimes without a built-in driver (§5.3):

```yaml
host: knowdrive
functions:
  tenancy-service:   { dir: functions/tenancy-service }        # Go: built-in driver
  billing:           { dir: functions/billing, run: "npm run dev" }
  search:            { url: "http://127.0.0.1:9000" }          # attached
```

On startup `kdex dev` prints:
- the host URL;
- the local users (subject and roles);
- each function's state and URL;
- what is **not** emulated for the CRs it loaded (§7);
- the dev OAuth client's id and secret;
- a ready-to-paste `curl` that gets a token with the password grant and calls the first function.

## 4. Architecture

```
            ┌───────────────────────── kdex dev (one process) ─────────────────────────┐
  browser / │  CR loader ─▶ fake client ◀── reconcilers (preview foundation)           │
  curl ────▶│                   │                                                     │
            │                   ▼                                                     │
            │   HostHandler (UNCHANGED): mux, auth, gate+binding, FAT mint, proxy ────┼──▶ function process
            │     cache: InMemoryCacheManager   keys: LoadOrGenerateKeyPair           │    (AUDIENCE = its URL,
            │                   ▲                                                     │     JWKS_URL → this host)
            │   fnrunner ───────┘ writes KDexFunction.status {State: Ready, URL}      │
            │     ├─ codegen (fngogen local pipeline, library) on spec.api change     │
            │     ├─ build + start/restart on source change                           │
            │     └─ watchers (fsnotify, debounced)                                   │
            └─────────────────────────────────────────────────────────────────────────┘
```

**The key observation: the host code runs unchanged.**
- The host mounts every non-`internal` function whose `status.state` is `Ready` (`internal/host/host.go`).
- The proxy targets `status.url` and mints the FAT with `aud = status.url` (`internal/host/proxy.go`, `fatAudienceFor`).
- So if the function process gets `AUDIENCE = status.url`, routing, the gate, binding, `claimMappings`, FAT minting, the PASETO bridge and token exchange all work with **no dev-mode branches in host code**.
- `kdex dev` only has to replace the KDexFunction reconciler (build, deploy and observe) with a local runner that writes the same status the deployer and observer would.

This is the main difference from `preview`. `preview` stubs the proxy, openapi, login and apitoken routes. `kdex dev` registers them for real. The remaining stubs are the Sniffer and the feedback widget, which are designed for `devMode` hosts in a cluster.

### 4.1 Host services, locally
| Concern | Cluster | `kdex dev` |
|---|---|---|
| Session/caps/grant cache | Valkey | `cache.NewCacheManager("", …)`, the existing in-memory manager |
| Signing keys (JWT, PASETO) | `jwt-keys` Secret | Same loader. With no Secret in `--crs`, `LoadOrGenerateKeyPair` generates one per run |
| Identities | OIDC / LDAP / `subject` Secrets / http-lookup | `subject` Secrets in `--crs` (`sub`, `email`, `password`, other keys become claims) plus KDexRoleBinding. An `oidc-client` Secret in `--crs` enables real OIDC if the developer wants it |
| `ISSUER` | `<scheme>://<domains[0]>` | `http://localhost<addr>`. The loaded KDexHost's `routing` is overridden in memory and never written back |
| Token endpoint | `/-/token` | Same. The password grant gives `curl` a token with no browser. It needs an OAuth client, so `kdex dev` provisions an ephemeral dev client (an `auth-client` Secret in the fake client) unless `--crs` defines one, and prints its id and secret |

### 4.2 Why reuse the in-process host instead of a purpose-built emulator
An emulator would be a third implementation of the gate, binding, FAT projection and token exchange, after host-manager and the generators. The FUNCTION_CONTRACT work found that two copies of the one-off document builder had already drifted. Running the real `HostHandler` makes local behaviour equal cluster behaviour by construction. The cost is that `kdex dev` lives in host-manager's tree and inherits its dependencies, which the CLI spec already accepts for `preview`.

## 5. The function runner (`internal/preview/fnrunner`)

The KDexFunction reconciler is registered in **no-op mode**, as `preview` already plans (2026-05-19 §6). The runner owns every function in `--crs`.

### 5.1 Per-function state machine
| Mapping | Behaviour | `status` written |
|---|---|---|
| `--fn name=<dir>` | Codegen if needed, then build, start on a free port, wait for TCP accept | `Pending` → `Ready`, `url=http://127.0.0.1:<port>` |
| `--fn name=url:<u>` | Probe `u`, print the env the process must have (§5.2) | `Ready`, `url=<u>` |
| unmapped | Not run | `Pending`, Detail `not running locally: map it with --fn`. As in the cluster, a non-Ready function is not mounted, so its paths 404; the startup banner lists it |
| build/start failure | Previous process keeps serving if there is one; error printed and sent to the browser overlay | unchanged if a previous process exists, else `Pending` with Detail = the error |

**Zero-downtime swap.**
1. Start the new process on a **new** port.
2. When it accepts connections, update `status.url`. The host re-mounts on the status change, exactly as it does for a new Knative URL: `functionHostWatchPredicate` passes `Status.URL` changes through to the host reconcile (kdex-tech/host-manager#116).
3. Stop the old process with `SIGTERM`, honouring `SHUTDOWN_GRACE_SECONDS`.

Because the audience is the URL, the new process's `AUDIENCE` and the FATs minted for it change together. A request in flight to the old process carries a FAT for the old audience, so it still verifies there.

### 5.2 Environment given to the process
This is exactly FUNCTION_CONTRACT §4, with local values:
- **`AUDIENCE`** = `status.url`.
- **`ISSUER`** = the local host URL.
- **`JWKS_URL` / `PKS_URL`** = `<host>/.well-known/{jwks,pks}.json`.
- **`PASETO_TOKEN_PREFIX`** = the same resolver the host uses.
- **`FUNCTION_*`** identity.
- **`PORT`** = the allocated port.
- **`spec.env`**, resolved against Secrets and ConfigMaps in the fake client. An unresolved `secretKeyRef` fails the start, naming the missing key. It is never silently empty.

For `url:` mode the runner prints this block as `export …` lines, since the developer starts that process.

### 5.3 Drivers
- **Go (built in).** Detected by `go.mod` plus `cmd/` in `<dir>`. Build with `go build -o <tmp>/fn ./cmd`, run the binary, rebuild on `*.go` changes (debounced 250ms). Build errors go to the terminal and the overlay.
- **Custom.** `run:` in `kdex-dev.yaml` (e.g. `npm run dev`). The runner starts it with the §5.2 env and restarts it on `spec.api` or `spec.env` changes. Source watching is left to the command's own watcher (tsx, nodemon).
- **TypeScript (later).** A built-in fnnodejsgen driver once fnnodejsgen meets the contract (kdex-tech/fnnodejsgen#3).

### 5.4 Codegen on `spec.api` change
- **Trigger.** When a KDexFunction's `spec.api` changes in `--crs`, the runner renders the one-off document with `kdex.dev/crds/openapi` (`NewOneOffBuilder().BuildOneOff`, the same builder host-manager uses).
- **Go functions.** The runner runs the `fngogen local` pipeline in `<dir>`: SSE prepare, ogen as a library, templates. `cmd/custom*.go` is never overwritten, so an operation added or retyped in the spec becomes a **compile error** in the author's handler. That is the "stubs always map back to `spec.api`" guarantee, surfaced inside the dev loop.
- **Prerequisite.** fngogen's pipeline lives in `package main` (`cmd/local.go`). It must move to an importable package (e.g. `github.com/kdex-tech/fngogen/local`) so `kdex` links it, which the CLI spec requires: no PATH-installed tools. That move is small, and it also lets `kdex codegen go` wrap fngogen instead of re-implementing it (§9).

## 6. Using it

```sh
kdex dev --crs k8s/dev --fn tenancy-service=functions/tenancy-service
# → host on http://localhost:8080, users: alice (admin), bob (viewer)
# → tenancy-service Ready at http://127.0.0.1:41733 (Go, watching)

TOKEN=$(curl -s localhost:8080/-/token -u kdex-dev:<printed-secret> \
  -d grant_type=password -d username=alice -d password=dev | jq -r .access_token)
curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/v1/tenancy/stores/s1
```

Editing `functions/tenancy-service/cmd/custom.go` rebuilds and swaps. Editing the KDexFunction YAML regenerates `api/` and `cmd/{main,default}.go`, then rebuilds. Calling as `bob` exercises the real denial contract.

## 7. Fidelity

| Behaviour | Local | Notes |
|---|---|---|
| Routing by `basePath`, path not stripped | **real** | host mux + proxy |
| Entitlement gate, `x-entitlement-binding`, denial contract | **real** | |
| `claimMappings` (host + function), FAT projection | **real** | |
| PASETO API tokens, PAT bridge | **real** | `/-/apitokens/mint` works locally |
| Token exchange (`/-/token`, RFC 8693) | **real** | see §10 for target audiences |
| `internal: true` | **real** | not mounted on the host; reachable at its local URL |
| Pages/themes/apps composition | **real** | the `preview` foundation |
| Knative scaling, cold start, revisions | absent | |
| Volumes, service account / workload identity | absent | reported at startup per function |
| Network policy, cross-namespace Service backends | absent | |

## 8. Changes required

| Repo | Change |
|---|---|
| host-manager | `internal/preview/fnrunner` (new). `kdex dev` subcommand. Function routes registered rather than stubbed when running under `dev`. KDexFunction reconciler no-op mode (already planned for `preview`). In-memory cache and generated keys wired for the dev manager. |
| fngogen | Move the `local` pipeline out of `package main` into an importable package; keep the CLI as a thin wrapper. |
| kdex-crds | None. `kdex.dev/crds/openapi` (kdex-tech/kdex-crds#28) already provides the shared one-off builder. |

## 9. Effect on the unified CLI plan

- **Phase 0(b) (ogen-as-library spike) is answered.** `fngogen local` (kdex-tech/fngogen#17) already drives ogen v1.22.0 in-process and produces buildable output.
- **Reconsider `kdex codegen go` as a re-implementation.** The CLI spec plans a fresh port with a parity harness (§5, §8). Two implementations of the same codegen recreate the drift problem the shared one-off builder just removed. Recommended instead: once fngogen's pipeline is importable, have `kdex codegen go` call it. Parity then holds by construction, the "cluster cutover" phase becomes a version bump, and fngogen stays the single Go generator. Treat this as a proposal for the CLI spec's owners, not a decision made here.
- **Ordering.** `kdex dev` builds on the preview MVP (CLI phases 0–2). Insert it as phases 2a–2d below, ahead of preview kustomize and config (CLI phase 4). Function iteration is the larger velocity win.

## 10. Phasing

| Phase | Scope | Exit criterion |
|---|---|---|
| **2a. Real host routes + attach** | Register the function routes for real under `dev`. In-memory cache, generated keys, `subject` users. `--fn name=url:` only. | A hand-started fngogen function, given the printed env, serves a gated operation through `localhost:8080` with a password-grant token. A user without the entitlement gets the cluster's denial. |
| **2b. Go runner** | Build, start, swap, rebuild on `*.go` change. | Saving `custom.go` serves the new behaviour in under 2s, with no failed requests during the swap. |
| **2c. Codegen on spec change** | Importable fngogen pipeline. Regenerate on `spec.api` edit. | Adding an operation in the CR produces a compile error in `custom.go` naming the missing method; implementing it serves it. |
| **2d. Custom `run:`** | Generic driver for other runtimes. | An fnnodejsgen function runs under `npm run dev`. |

## 11. Open questions

- **Token exchange target audience.** A handler exchanges its FAT for one addressed to another function's `AUDIENCE`. In the cluster that is `http://<fn>.<ns>.svc.cluster.local`; locally it is a loopback URL that changes on every swap. Handlers need the target's audience from somewhere other than a hard-coded string. Proposal: the deployer and `kdex dev` both inject `FUNCTION_AUDIENCE_<NAME>` for the host's functions, added to FUNCTION_CONTRACT §4.1. Alternatively, keep loopback ports stable per function and only swap processes, not ports.
- **Status writes under the fake client.** The runner writes `status`, which the host's watch picks up. The preview phase-0 spike must confirm the status subresource behaves under the fake client, as it does for the other reconcilers.
- **Shared `--crs` with the cluster.** Teams keep CRs in `k8s/<env>/`. Overriding `routing` in memory is enough for the host. KDexFunction `origin` (git source, image) is ignored locally. Confirm no other field makes a cluster CR unusable as-is.
- **Conformance checks.** The runner could probe a running function with the contract's negative cases: no `exp`, wrong `aud`, unbound placeholder. That would turn `kdex dev --check` into the generator conformance harness FUNCTION_CONTRACT §11 tracks by hand today. Later, but cheap once 2a exists.

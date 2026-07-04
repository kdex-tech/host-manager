# Catch-all login sub-route — enabling (and documenting) client-side routing on the login page

- **Date:** 2026-07-04
- **Status:** design approved, ready for implementation plan
- **Component:** kdex-host-manager (`internal/host`)

## Summary

Register a second, wildcard route for the login page so that any sub-path under
`/-/login` serves the login page shell instead of 404ing:

```
GET /-/login              -> LoginGet   (exact, existing)
POST /-/login             -> LoginPost  (existing)
GET /-/login/{path...}    -> LoginGet   (NEW: catch-all subtree)
```

This is the **server-side enabler** for client-side routing between login views
(sign-in / forgot-password / register / MFA / …) following the `@kdex/ui` app
router pattern. Deep-links and reloads to a login sub-view resolve to the login
shell; the client router reads `location.pathname` and mounts the correct view.

The new route is **also registered in the host's OpenAPI document** (`/-/openapi`).
That is the whole point of documenting it: without a spec entry, the capability
to client-route the login page is utterly undiscoverable — a developer has no
way to learn it exists. The OpenAPI operation is the capability's documentation
surface.

**No CRD change. No client change in this work item. No behavior change to any
existing route.** One new route registration + its OpenAPI entry + tests.

## Background — why the login page can't do this today

The login page is a `KDexUtilityPage` of type `Login`. It is **not** routed like
a `KDexPage`:

- `KDexPage` handlers go through `addHandlerAndRegister`
  (`internal/host/handlers.go`), which honors the page's `patternPath` field and
  registers both `GET <patternPath>` and `GET /{l10n}<patternPath>`. This is how
  ordinary app-hosting pages (e.g. `/invitations/-/{path...}`) support client
  routing.
- **Utility pages have no routing knobs at all.** `KDexUtilityPageSpec`
  (kdex-crds) carries only `Type`, `ContentEntries`, and chrome override refs —
  no `basePath`, no `patternPath`. They are stored in an in-memory map keyed by
  type (`hh.utilityPages[LoginUtilityPageType]`, `internal/host/host.go`) and
  rendered inline by dedicated system handlers, never registered on the mux with
  a capturable path.
- The login route is a **fixed, exact** `/-/login` (`loginHandler`,
  `internal/host/handlers.go:494`). Go 1.22 ServeMux treats `GET /-/login`
  (no trailing slash, no wildcard) as an exact match, so `/-/login/anything`
  does not resolve to it — it falls through to a 404.

So a login sub-view URL is unreachable on reload/deep-link today.

## Why this shape — three verified facts

### Fact 1 — `LoginGet` already ignores path segments

`LoginGet` (`internal/host/login.go:14`) reads only the `return` **query**
param, resolves language via `GetLang`, and renders the login utility page. It
never reads path values. Therefore the same handler can serve every sub-path
with **zero handler changes** — each sub-path returns the identical login shell
(identical body, identical ETag), which is exactly what a client-rendered login
needs: the server ships the shell, the client router selects the view.

### Fact 2 — a catch-all is separator-agnostic; the app-router `/-/` separator collides with the login prefix

The stock `@kdex/ui` `AppRouter` derives `basepath()` by splitting the URL on the
**first** occurrence of its path separator, default `/-/`
(`kdex-ui/src/app-route.ts:170`, `currentAppRoute` at `:180`). This works for an
ordinary page whose base path contains no `/-/` (e.g. `/invitations`), but the
login page lives at `/-/login`, which **starts** with `/-/`. Verified against the
real router logic:

| URL | stock `basepath()` | parsed route | OK? |
|---|---|---|---|
| `/invitations/-/main/inv-app/x` | `/invitations` | viewport=main, app=inv-app, path=/x | yes |
| `/-/login/-/main/login-app/forgot` | `""` | viewport=**login**, app=`""`, path=/ | **no** |
| `/-/login/~/main/login-app/forgot` (custom sep `/~/`) | `/-/login` | viewport=main, app=login-app, path=/forgot | yes |

Consequence: a route that hardcodes the `/-/` separator (`/-/login/-/{path...}`)
would only ever work with a client that overrides `data-path-separator` to a
value **not** containing `/-/`. Rather than couple the server route to that
client decision, register a **separator-agnostic catch-all** `/-/login/{path...}`.
`{path...}` matches zero-or-more trailing segments, so it serves the login shell
for `/-/login/`, `/-/login/-/…`, `/-/login/~/…`, or any future scheme. The
server takes no position on the client's separator.

### Fact 3 — OpenAPI registration is independent of route wiring

`mux.HandleFunc(...)` wires the route; `hh.registerPath(...)`
(`internal/host/host.go:796`) only writes into the `registeredPaths` map that
feeds `/-/openapi`. They are independent. So documenting the capability is a
deliberate, separate `registerPath` call — and it is **required here**, because
the OpenAPI entry is the only discoverable signal that login client-routing is a
supported capability.

## Design

### 1. Route registration

In `loginHandler` (`internal/host/handlers.go`), gated by the existing
`IsAuthEnabled()` check, add the catch-all next to the existing exact route:

```go
const loginPath = "/-/login"
mux.HandleFunc("GET "+loginPath, hh.LoginGet)
mux.HandleFunc("POST "+loginPath, hh.LoginPost)

const loginClientRoutePath = "/-/login/{path...}"
mux.HandleFunc("GET "+loginClientRoutePath, hh.LoginGet)   // NEW
```

Precedence is by ServeMux specificity, not registration order: the exact
`/-/login` continues to win for the bare path; the wildcard only catches
`/-/login/…`. Both are gated behind `IsAuthEnabled()`, so when auth is off
neither registers (unchanged behavior).

### 2. Handler behavior — unchanged

`LoginGet` is reused verbatim. The captured `{path...}` is intentionally ignored
server-side. `POST` stays only at `/-/login` (the form action); sub-view POST
endpoints are out of scope.

### 3. OpenAPI documentation (the discoverability requirement)

Register the catch-all as its own path in the host OpenAPI document via
`hh.registerPath`, mirroring the base login GET (200 text/html, 303, 400, 404,
500; tags `system`, `login`, `auth`) but with:

- **operationId:** `login-clientroute-get` (unique within the spec).
- **A wildcard path parameter** `path`, described as the client-side route
  sub-path that is **consumed by the `@kdex/ui` app router, not the server**
  (use `ko.WildcardPathParam("path", …)`, `internal/openapi/openapi.go:773`).
- **The `return` query param**, matching the base login GET.
- **A description that names the capability explicitly**, e.g.:

  > Serves the login page shell for any sub-path beneath `/-/login`, enabling
  > client-side routing between login views (sign-in, forgot-password, etc.)
  > following the `@kdex/ui` app router pattern. The captured path is not
  > interpreted server-side; every sub-path returns the same shell and the
  > client router selects the active view from the URL. Because the login page
  > is mounted under the reserved `/-/` prefix (which is itself the app router's
  > default path separator), a client hosting a router here must configure a
  > `data-path-separator` that does not contain `/-/`.

This entry is what makes the capability learnable from `GET /-/openapi`
(filterable via `?type=system` or by the `/-/login` path).

### 4. No `/{l10n}` variant

The existing login route has no localized path variant — language is resolved by
`GetLang` from Accept-Language / query / cookie. The catch-all follows suit; no
`/{l10n}/-/login/{path...}` is registered.

## Testing

Extend existing host tests rather than adding a new file. Route-registration and
auth-gating assertions fit alongside `system_path_init_test.go` (which already
exercises `/-/login` registration); the OpenAPI assertion fits alongside
`openapi_test.go`.

1. `GET /-/login/-/main/foo/bar` → `200`, body byte-identical to `GET /-/login`.
2. `GET /-/login/anything` → `200`, same body.
3. `GET /-/login` (exact) still `200` and unaffected.
4. With auth **disabled**, neither `/-/login` nor `/-/login/{path...}` register → `404`.
5. `GET /-/openapi` contains the `/-/login/{path...}` path with operationId
   `login-clientroute-get` and the wildcard `path` parameter (asserts the
   capability is documented — the discoverability requirement).

## Scope boundaries

**In scope:** the catch-all route, its OpenAPI entry, tests.

**Explicitly out of scope (separate, downstream work):**

- The client-side login router and login sub-views. The utility archetype
  (`kdex-default-page-archetype-utility`) currently loads **no** `@kdex/ui`
  script; wiring a router onto the login page (via a script library, a custom
  element content entry, and/or a custom `data-path-separator`) is a follow-up.
- Sub-view POST endpoints.
- Generalizing sub-path routing to other utility pages (announcement, error) or
  adding a routing field to `KDexUtilityPageSpec` in kdex-crds. The catch-all
  pattern established here is the template if/when that is wanted.

## Blast radius / risks

- One new `mux.HandleFunc` line + one `registerPath` block + test additions.
- No change to `LoginGet`, `LoginPost`, existing routes, CRDs, or clients.
- `/-/login/{path...}` is under the reserved `/-/` prefix, so it cannot collide
  with any user-authored `KDexPage`/`KDexFunction` basePath, and the sniffer
  already skips `/-/`.
- Risk is minimal: the only observable change is that `/-/login/*` now returns
  the login shell (200) instead of 404.

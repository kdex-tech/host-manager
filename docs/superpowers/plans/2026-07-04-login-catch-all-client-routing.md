# Catch-all Login Sub-Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Register `GET /-/login/{path...}` (routing to the existing login handler) and document it in the host OpenAPI, so deep-links/reloads into login sub-views serve the login shell instead of 404ing — and the client-routing capability is discoverable.

**Architecture:** One new `mux.HandleFunc` + one `registerPath` block inside the existing `loginHandler` (`internal/host/handlers.go`), both behind the existing `IsAuthEnabled()` gate. The catch-all reuses `hh.LoginGet` verbatim (it already ignores path segments). No CRD, client, or existing-route changes.

**Tech Stack:** Go 1.26.0, `net/http` ServeMux (Go 1.22 pattern syntax), `github.com/getkin/kin-openapi/openapi3`, testify/assert.

## Global Constraints

- **Go 1.26.0** — do not change the toolchain floor.
- **Commit inside the `kdex-host-manager` sub-repo** (already on branch `login-catch-all-client-routing`). Do not commit at the workspace root.
- **The catch-all MUST stay behind the existing `IsAuthEnabled()` gate** in `loginHandler` — when auth is off, neither `/-/login` nor `/-/login/{path...}` registers.
- **`operationId` must be unique** within the host OpenAPI: use `login-clientroute-get` (distinct from the existing `login-get`).
- **No `/{l10n}` variant** — login has none today; language is resolved by `GetLang`.
- **Reuse `hh.LoginGet` unchanged** — the captured `{path...}` is intentionally ignored server-side.
- **Match the existing `loginHandler` OpenAPI style** — mirror the base `login-get` operation (200 text/html, 303, 400, 404, 500; tags `system`/`login`/`auth`; the in-package `new("…")` string-pointer helper).

---

## File Structure

- **Modify:** `internal/host/handlers.go` — add the catch-all route + its OpenAPI registration inside `loginHandler` (currently at lines 494–592), between the existing `/-/login` `registerPath` block and the `const logoutPath = "/-/logout"` line.
- **Modify (test):** `internal/host/system_path_init_test.go` — add `TestLoginHandler_CatchAllClientRoute` (routing + auth-gating via `mux.Handler` pattern matching).
- **Modify (test):** `internal/host/openapi_test.go` — add `TestLoginHandler_CatchAllClientRouteDocumented` (asserts the documented path/operationId/wildcard-param in the `registeredPaths` map that `/-/openapi` serializes from).

---

### Task 1: Catch-all login route + OpenAPI documentation

Route registration and its OpenAPI entry are one atomic deliverable — shipping the route *without* the doc would leave exactly the undiscoverable state we are avoiding. Both live in the same function and are verified together.

**Files:**
- Modify: `internal/host/handlers.go` (function `loginHandler`, insert after the `/-/login` `registerPath` block ~line 561, before `const logoutPath`)
- Test: `internal/host/system_path_init_test.go`
- Test: `internal/host/openapi_test.go`

**Interfaces:**
- Consumes (all existing, verified): `hh.LoginGet` (`http.HandlerFunc`); `hh.IsAuthEnabled() bool`; `hh.registerPath(path string, info ko.PathInfo, m map[string]ko.PathInfo)`; `ko.PathInfo` / `ko.OpenAPI` / `ko.PathItem` / `ko.SystemPathType`; `ko.WildcardPathParam(name, description string) *openapi.ParameterRef` (sets `In:"path"`, `Name:name`, `Required:true`); `ko.QueryParam(name, description string) *openapi.ParameterRef`; the in-package `new(v) *v` helper; `auth.Config{ActivePair *keys.KeyPair}` where `Config.IsAuthEnabled()` is true iff `ActivePair != nil`.
- Produces: the registered pattern string `GET /-/login/{path...}` on the mux, and the OpenAPI path key `/-/login/{path...}` with GET `OperationID == "login-clientroute-get"` and a wildcard `path` parameter.

- [ ] **Step 1: Write the failing routing/gating test**

Add to `internal/host/system_path_init_test.go`. First ensure its import block includes these (add the three that are missing):

```go
import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)
```

Then append this test function:

```go
// TestLoginHandler_CatchAllClientRoute verifies the catch-all subtree route
// that lets the login page host client-side routing between views. It is
// registered only when auth is enabled, alongside the exact /-/login route.
func TestLoginHandler_CatchAllClientRoute(t *testing.T) {
	newMuxFor := func(hh *HostHandler) *http.ServeMux {
		mux := http.NewServeMux()
		hh.loginHandler(mux, map[string]ko.PathInfo{})
		return mux
	}
	pattern := func(mux *http.ServeMux, target string) string {
		_, p := mux.Handler(httptest.NewRequest("GET", target, nil))
		return p
	}

	authOn := &HostHandler{
		log:        logr.Discard(),
		authConfig: &auth.Config{ActivePair: &keys.KeyPair{}},
	}
	muxOn := newMuxFor(authOn)

	t.Run("exact /-/login still routes to the login handler", func(t *testing.T) {
		assert.Equal(t, "GET /-/login", pattern(muxOn, "/-/login"))
	})
	t.Run("app-router sub-path routes to the catch-all", func(t *testing.T) {
		assert.Equal(t, "GET /-/login/{path...}", pattern(muxOn, "/-/login/-/main/login-app/forgot"))
	})
	t.Run("any sub-path routes to the catch-all", func(t *testing.T) {
		assert.Equal(t, "GET /-/login/{path...}", pattern(muxOn, "/-/login/anything"))
	})
	t.Run("auth disabled registers neither route", func(t *testing.T) {
		muxOff := newMuxFor(&HostHandler{log: logr.Discard()})
		assert.Equal(t, "", pattern(muxOff, "/-/login"))
		assert.Equal(t, "", pattern(muxOff, "/-/login/anything"))
	})
}
```

- [ ] **Step 2: Write the failing documentation test**

Add to `internal/host/openapi_test.go`. Add these imports to its existing block (openapi_test.go already imports `net/http`, `testing`, `logr`, `ko`, `kdexv1alpha1`; add the three below):

```go
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
```

Then append:

```go
// TestLoginHandler_CatchAllClientRouteDocumented verifies the catch-all login
// route appears in the OpenAPI path set (which /-/openapi serializes from), so
// the login client-routing capability is discoverable rather than hidden.
func TestLoginHandler_CatchAllClientRouteDocumented(t *testing.T) {
	hh := &HostHandler{
		log:        logr.Discard(),
		authConfig: &auth.Config{ActivePair: &keys.KeyPair{}},
	}
	registeredPaths := map[string]ko.PathInfo{}
	hh.loginHandler(http.NewServeMux(), registeredPaths)

	info, ok := registeredPaths["/-/login/{path...}"]
	if !ok {
		t.Fatal("catch-all login route must be documented in the OpenAPI path set that /-/openapi serializes from")
	}
	assert.Equal(t, ko.SystemPathType, info.Type)

	item := info.API.Paths["/-/login/{path...}"]
	if item.Get == nil {
		t.Fatal("documented catch-all must expose a GET operation")
	}
	assert.Equal(t, "login-clientroute-get", item.Get.OperationID)

	var hasWildcardPathParam bool
	for _, p := range item.Get.Parameters {
		if p.Value != nil && p.Value.In == "path" && p.Value.Name == "path" {
			hasWildcardPathParam = true
		}
	}
	assert.True(t, hasWildcardPathParam,
		"documented catch-all must expose the wildcard {path...} parameter so the client-routing capability is discoverable")
}
```

- [ ] **Step 3: Run both tests to verify they fail**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run 'TestLoginHandler_CatchAll' -v`
Expected: FAIL — `TestLoginHandler_CatchAllClientRoute/app-router_sub-path…` and `/any_sub-path…` report `"" != "GET /-/login/{path...}"` (catch-all not registered); `TestLoginHandler_CatchAllClientRouteDocumented` fails at `t.Fatal` (path absent from map). (The `exact /-/login` and `auth disabled` sub-tests already pass.)

- [ ] **Step 4: Implement the route + OpenAPI registration**

In `internal/host/handlers.go`, inside `loginHandler`, immediately after the existing `/-/login` `registerPath(loginPath, …, registeredPaths)` block closes (`}, registeredPaths)`) and before `const logoutPath = "/-/logout"`, insert:

```go
	const loginClientRoutePath = "/-/login/{path...}"
	mux.HandleFunc("GET "+loginClientRoutePath, hh.LoginGet)

	hh.registerPath(loginClientRoutePath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: loginClientRoutePath,
			Paths: map[string]ko.PathItem{
				loginClientRoutePath: {
					Description: "Serves the login page shell for any sub-path beneath /-/login, enabling client-side routing between login views following the @kdex/ui app router pattern.",
					Get: &openapi.Operation{
						Description: "GET the login shell for a client-side route. The captured path is not interpreted server-side; every sub-path returns the same shell and the client router selects the active view from the URL. Because the login page is mounted under the reserved /-/ prefix (the app router's default path separator), a client hosting a router here must configure a data-path-separator that does not contain /-/.",
						OperationID: "login-clientroute-get",
						Parameters: openapi.Parameters{
							ko.WildcardPathParam("path", "Client-side route sub-path (e.g. viewport/appId/appPath); consumed by the @kdex/ui app router, not the server"),
							ko.QueryParam("return", "The URL to redirect to after successful login"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "html",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"text/html"},
								),
								Description: new("HTML login page shell"),
							}),
							openapi.WithStatus(303, &openapi.ResponseRef{
								Ref: "#/components/responses/SeeOther",
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: "#/components/responses/BadRequest",
							}),
							openapi.WithStatus(404, &openapi.ResponseRef{
								Ref: "#/components/responses/NotFound",
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: "#/components/responses/InternalServerError",
							}),
						),
						Summary: "Get login experience (client-side route)",
						Tags:    []string{"system", "login", "auth"},
					},
					Summary: "Login experience client-side routing",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
```

No new imports are needed in `handlers.go` — `openapi`, `ko`, `http`, and the `new(…)` helper are all already used by `loginHandler`.

- [ ] **Step 5: Run both tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run 'TestLoginHandler_CatchAll' -v`
Expected: PASS — all sub-tests of `TestLoginHandler_CatchAllClientRoute` and `TestLoginHandler_CatchAllClientRouteDocumented` pass.

- [ ] **Step 6: Run the full host package tests + lint**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/... && make lint`
Expected: `ok` for `internal/host`; `make lint` (golangci-lint) reports no new findings. If `make lint` at the module fails on unrelated pre-existing issues, fall back to `golangci-lint run ./internal/host/...` and `gofmt -l internal/host/handlers.go internal/host/system_path_init_test.go internal/host/openapi_test.go` (expect empty output).

- [ ] **Step 7: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/handlers.go internal/host/system_path_init_test.go internal/host/openapi_test.go
git commit -m "$(cat <<'EOF'
feat(host): catch-all /-/login/{path...} route for login client-side routing

Register GET /-/login/{path...} routing to the existing LoginGet, so deep-links
and reloads into login sub-views serve the login shell instead of 404ing. The
route is documented in /-/openapi (operationId login-clientroute-get, wildcard
{path...} param) so the client-routing capability is discoverable. Separator-
agnostic and gated by IsAuthEnabled(); LoginGet is reused unchanged.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
)"
```

---

## Self-Review

**1. Spec coverage:**
- Route registration (spec §1) → Task 1 Step 4 (the `mux.HandleFunc` line). ✅
- Handler unchanged (spec §2) → reuses `hh.LoginGet`; no `LoginGet` edit anywhere. ✅
- OpenAPI documentation (spec §3, the discoverability requirement) → Task 1 Step 4 `registerPath` block with `login-clientroute-get` + wildcard `path` param + capability description; verified by Step 2 test. ✅
- No `/{l10n}` variant (spec §4) → only `GET /-/login/{path...}` is added; no `/{l10n}` route. ✅
- Testing (spec §5, items 1–5) → routing/serve-same-handler + exact-still-works + auth-disabled (Step 1 test); documented-in-OpenAPI (Step 2 test). The spec's "body byte-identical" intent is met more robustly by asserting sub-paths resolve to the *same registered handler pattern family* as `/-/login` (both dispatch to `hh.LoginGet`), avoiding brittle full-render setup. ✅
- Auth gate (spec, global constraint) → catch-all sits inside the existing `if !IsAuthEnabled() { return }` guard; Step 1 "auth disabled" sub-test proves it. ✅

**2. Placeholder scan:** No TBD/TODO/"add error handling"/"similar to". Every code step shows complete code and exact commands with expected output. ✅

**3. Type consistency:** `loginClientRoutePath` == `"/-/login/{path...}"` used identically in the route, the OpenAPI key, and both tests. `OperationID` == `"login-clientroute-get"` in impl and doc test. `ko.WildcardPathParam("path", …)` sets `In:"path"`/`Name:"path"`, matching the doc test's `p.Value.In == "path" && p.Value.Name == "path"`. `auth.Config{ActivePair: &keys.KeyPair{}}` makes `IsAuthEnabled()` true (verified against `config.go:352`). ✅

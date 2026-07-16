# Requirement Binder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Teach host-manager's gate to bind `{param}` requirements from the request, so an op declaring `vector_stores:{vector_store_id}:read` is verified against the store actually being addressed rather than a wildcard that any single-store grant satisfies.

**Architecture:** Binding specs parse once per route at mux-build (beside the existing `ParseRequirements` call in `reverseProxyHandler`) and cache on `KDexFunctionHandler`. Per request, the gate resolves each placeholder from its declared source chain, calls `BindRequirements`, then verifies. Path placeholders bind by identity match against the route pattern; every non-path source must be declared via an `x-entitlement-binding` operation extension. A binder that cannot resolve a value fails like an unbound placeholder — it never widens.

**Tech Stack:** Go 1.26.0, `github.com/kdex-tech/entitlements/go` v0.4.0, kin-openapi v0.133.0, `net/http.ServeMux`, **testify** (`assert` / `require`).

**Spec:** `docs/superpowers/specs/2026-07-16-requirement-binding-sources-design.md`

## Global Constraints

- **Go 1.26.0** — pinned across kdex-crds / kdex-host-manager / kdex-nexus-manager. Do not change.
- **`github.com/kdex-tech/entitlements/go` v0.4.0** — the floor. Currently `v0.3.0` (`go.mod:95`); Task 1 bumps it. The `go/` tag prefix is required for Go subdir module resolution.
- **Tests use testify** (`github.com/stretchr/testify/assert`, `.../require`). This package has **no gomega**. Match the surrounding file.
- **Never widen.** A binder that cannot resolve a value MUST fail like an unbound placeholder. Do NOT port knowdb's `system` / `*` defaults — those are knowdb policy, not binder behavior.
- **Never infer a header.** host-manager is generic across every `KDexFunction`. A non-path source binds only from an explicit `x-entitlement-binding` declaration. Undeclared is an error, not a guess.
- **`r.PathValue` does not work at the gate.** `patternMux` is built with empty handlers and consulted via `Handler(r)`, which returns the matched pattern but never populates path values. Path params MUST be extracted by re-matching the pattern against `r.URL.Path`.
- **Additive only.** With no CR declaring a `{param}`, behavior must be identical to today. Every task preserves this.
- **Run `make lint` from the workspace root** (`/home/rotty/projects/kdex/workspace`) after code changes — it formats and lints every module.

## Key Facts Discovered During Planning

Read these before starting; each one invalidates an obvious-looking approach.

1. **`authChecker` is an anonymous interface**, not a concrete type — `internal/host/types.go:64-70`. Calling `authChecker.BindRequirements(...)` does **not** compile until the interface gains the method. That is Task 2, and it is mandatory before Task 6.
2. **Nine types implement it**: the real `auth.AuthorizationChecker` (`internal/auth/authorization.go:118`) plus eight test fakes — `mockAuthChecker` (cache_test.go:169), `mockApitokenAuthChecker` (apitoken_test.go:308), `checkAuthChecker` (check_test.go:115), `snifferGateChecker` (feedback_authgate_test.go:51), `pageMockAuthChecker` (page_test.go:37), `panickingAuthChecker` (rebuildmux_locksafety_test.go:51), `entitlementGateChecker` (proxy_pat_test.go:70), `e2eEntitlementGateChecker` (mcp_oauth2_e2e_test.go:114). All nine need the new method.
3. **`AuthorizationChecker` wraps the real checker**: `ec *entitlements.EntitlementsChecker`, built by `auth.NewAuthorizationChecker(anonymousEntitlements []string, log logr.Logger)`.
4. **`runProxy` (proxy_test.go:31) cannot test the gate** — it builds a `HostHandler` with a nil `authChecker`, so the whole gate block is skipped and it asserts 200 unconditionally. Gate tests need their own fixture with a real `AuthorizationChecker`.
5. **The handler is built by `reverseProxyHandler`** (`proxy.go:110`); the mux-build loop is at `proxy.go:324-344` and the `fh` literal at `proxy.go:346`.
6. **`ParsedRequirements.hasPlaceholder` is unexported with no accessor.** To ask "does this set contain a placeholder?", probe with `BindRequirements(reqs, nil)` and test for `ErrUnboundPlaceholder`. Task 7 relies on this.

## File Structure

| file | responsibility |
|---|---|
| `internal/host/binding.go` *(new)* | Pure functions: path-param extraction by pattern re-match, `x-entitlement-binding` parsing, source-chain resolution. |
| `internal/host/binding_test.go` *(new)* | Table-driven unit tests for the above. No fixtures, no envtest. |
| `internal/auth/authorization.go` | Add `BindRequirements` delegating to `ac.ec`. |
| `internal/host/types.go:64-70, 189-205` | Extend the `authChecker` interface; add `bindingSpecs` to `KDexFunctionHandler`. |
| `internal/host/proxy.go:324-344, 500-513` | Parse specs at mux-build; bind before verify at the gate. |
| `internal/host/binder_gate_test.go` *(new)* | Gate integration tests with a real `AuthorizationChecker`. |
| `internal/host/check.go:84-96` | Exclude instance-scoped requirements from the instance-free `/-/check`. |

Binding lives in its own file because it is pure and independently testable; `proxy.go` is already ~600 lines and doing several jobs.

---

## Task 1: Bump the entitlements dependency to v0.4.0

**Files:**
- Modify: `go.mod:95`, `go.sum`

**Interfaces:**
- Consumes: nothing.
- Produces: `entitlements.Binding` (`map[string]string`); `(*EntitlementsChecker).BindRequirements(ParsedRequirements, Binding) (ParsedRequirements, error)`; `entitlements.ErrUnboundPlaceholder`, `ErrWildcardRequirement`, `ErrInvalidBoundValue`.

v0.4.0 is additive: strict mode defaults **false**, and no existing requirement string contains `{`. The bump alone must change no behavior.

- [ ] **Step 1: Bump the dependency**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
go get github.com/kdex-tech/entitlements/go@v0.4.0
go mod tidy
```

- [ ] **Step 2: Verify the pin landed**

Run: `rg -n "kdex-tech/entitlements/go" go.mod`
Expected: `github.com/kdex-tech/entitlements/go v0.4.0`

- [ ] **Step 3: Verify the suite passes unchanged**

Run: `make test`
Expected: PASS. If anything fails, v0.4.0's additivity claim is wrong — **stop and report** rather than adapting tests.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: bump entitlements/go to v0.4.0 for requirement binding

Additive: strict defaults false and no existing requirement contains '{',
so behavior is identical. Unlocks BindRequirements for the gate binder."
```

---

## Task 2: Extend the authChecker interface with BindRequirements

**Files:**
- Modify: `internal/auth/authorization.go`, `internal/host/types.go:64-70`
- Modify (fakes): `internal/host/cache_test.go`, `apitoken_test.go`, `check_test.go`, `feedback_authgate_test.go`, `page_test.go`, `rebuildmux_locksafety_test.go`, `proxy_pat_test.go`, `mcp_oauth2_e2e_test.go`

**Interfaces:**
- Consumes: `entitlements.Binding`, `BindRequirements` (Task 1).
- Produces: `BindRequirements(entitlements.ParsedRequirements, entitlements.Binding) (entitlements.ParsedRequirements, error)` on the `authChecker` interface — Task 6 calls this.

Pure plumbing: no behavior change, no new tests. It exists because `authChecker` is an interface (see Key Fact 1) and Task 6 cannot compile without it. Doing it as its own task keeps the security-critical Task 6 diff readable.

- [ ] **Step 1: Add the method to the real checker**

In `internal/auth/authorization.go`, after `ParseRequirements`:

```go
// BindRequirements substitutes each {placeholder} resourceName in reqs with its
// bound value. Delegates to the entitlements checker; see its doc comment for
// the error contract (ErrUnboundPlaceholder / ErrInvalidBoundValue /
// ErrWildcardRequirement).
func (ac *AuthorizationChecker) BindRequirements(
	reqs entitlements.ParsedRequirements,
	binding entitlements.Binding,
) (entitlements.ParsedRequirements, error) {
	return ac.ec.BindRequirements(reqs, binding)
}
```

- [ ] **Step 2: Add it to the interface**

In `internal/host/types.go`, inside the anonymous `authChecker` interface (keep the existing alphabetical-ish ordering — insert after `CheckAccess`):

```go
		BindRequirements(entitlements.ParsedRequirements, entitlements.Binding) (entitlements.ParsedRequirements, error)
```

- [ ] **Step 3: Verify it fails to compile, and see exactly which fakes need updating**

Run: `go build ./... && go vet ./internal/host/`
Expected: FAIL — each fake reported as not implementing `BindRequirements`. Use this list to drive Step 4; it is authoritative over the list in Key Fact 2.

- [ ] **Step 4: Add a pass-through to each of the eight fakes**

For each fake, add the method with a receiver matching that type's existing style (some are pointer receivers, some value — copy the neighbouring `ParseRequirements` method's receiver exactly). The canned behavior is "return the input unchanged, no error" — these fakes do not exercise binding:

```go
func (m *mockAuthChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}
```

Adapt the receiver name/type per file:
- `internal/host/cache_test.go` → `(m *mockAuthChecker)`
- `internal/host/apitoken_test.go` → `(m *mockApitokenAuthChecker)`
- `internal/host/check_test.go` → `(m *checkAuthChecker)`
- `internal/host/feedback_authgate_test.go` → `(m *snifferGateChecker)`
- `internal/host/page_test.go` → `(m *pageMockAuthChecker)`
- `internal/host/rebuildmux_locksafety_test.go` → `(p *panickingAuthChecker)`
- `internal/host/proxy_pat_test.go` → `(entitlementGateChecker)` — value receiver, matching its `ParseRequirements`
- `internal/host/mcp_oauth2_e2e_test.go` → `(g *e2eEntitlementGateChecker)`

> **`check_test.go` exception:** Task 7 needs `checkAuthChecker` to report `ErrUnboundPlaceholder` for a placeholder-bearing set. Give it the trivial pass-through **now**; Task 7 changes it.

- [ ] **Step 5: Verify it compiles and the suite is green**

Run: `go build ./... && make test`
Expected: PASS — no behavior changed.

- [ ] **Step 6: Commit**

```bash
git add internal/auth/authorization.go internal/host/
git commit -m "refactor: add BindRequirements to the authChecker interface

Plumbing only, no behavior change. authChecker is an anonymous interface, so
the gate cannot call BindRequirements until every implementation has it: the
real AuthorizationChecker (delegating to ec) plus eight test fakes."
```

---

## Task 3: Path-param extraction by pattern re-match

**Files:**
- Create: `internal/host/binding.go`
- Test: `internal/host/binding_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func pathParamFromMatch(pattern, uriPath, paramName string) (string, bool)`; helpers `splitPath(string) []string`, `percentDecode(string) string` (Task 6 reuses `splitPath`).

Ports knowdb's `path_param_from_match` (`multi-modal-store/src/auth/entitlements.rs:358`). The trailing-catch-all case is load-bearing: Go's `ServeMux` supports `{name...}` wildcards absorbing one-or-more segments, so an exact segment-count check fails on those routes and reports "not found" — which per the never-widen rule becomes a denial rather than a hole, but breaks legitimate routes. knowdb hit exactly this (its issue #347).

- [ ] **Step 1: Write the failing test**

Create `internal/host/binding_test.go`:

```go
package host

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathParamFromMatch(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		uriPath   string
		param     string
		wantVal   string
		wantFound bool
	}{
		{"simple", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs_abc", "vector_store_id", "vs_abc", true},
		{"middle segment", "/v1/vector_stores/{vector_store_id}/files", "/v1/vector_stores/vs_abc/files", "vector_store_id", "vs_abc", true},
		{"two params picks the right one", "/v1/vector_stores/{vector_store_id}/files/{file_id}", "/v1/vector_stores/vs_abc/files/f_1", "file_id", "f_1", true},
		{"param absent from pattern", "/v1/ingest", "/v1/ingest", "vector_store_id", "", false},
		{"segment count mismatch", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs_abc/files", "vector_store_id", "", false},
		{"percent-decoded", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs%2Fabc", "vector_store_id", "vs/abc", true},
		{"catch-all: earlier param still found", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores/vs_abc/path/content/a/b/c.md", "vector_store_id", "vs_abc", true},
		{"catch-all is never a target", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores/vs_abc/path/content/a/b", "uri", "", false},
		{"catch-all with too-short uri", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores", "vector_store_id", "", false},
		{"empty value is not found", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/", "vector_store_id", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotFound := pathParamFromMatch(tt.pattern, tt.uriPath, tt.param)
			assert.Equal(t, tt.wantVal, gotVal)
			assert.Equal(t, tt.wantFound, gotFound)
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/host/ -run TestPathParamFromMatch -v`
Expected: FAIL — `undefined: pathParamFromMatch`

- [ ] **Step 3: Write the implementation**

Create `internal/host/binding.go`:

```go
package host

import (
	"net/url"
	"strings"
)

// pathParamFromMatch extracts a path parameter's value by re-matching the route
// pattern against the concrete URI path.
//
// It exists because r.PathValue does NOT work at the gate: fh.patternMux is
// built with empty handlers and consulted via Handler(r), which returns the
// matched pattern but never populates the request's path values. So the gate
// must re-match the pattern itself.
//
// A trailing Go ServeMux catch-all ({name...}) absorbs one-or-more segments, so
// the concrete URI has AT LEAST as many segments as the fixed prefix; an exact
// length comparison would fail and drop the earlier params. Match the fixed
// prefix positionally instead. The catch-all itself is never a lookup target --
// it is a path remainder, not an identity. (knowdb hit the same case; see
// multi-modal-store issue #347.)
func pathParamFromMatch(pattern, uriPath, paramName string) (string, bool) {
	patternSegs := splitPath(pattern)
	uriSegs := splitPath(uriPath)
	needle := "{" + paramName + "}"

	if n := len(patternSegs); n > 0 {
		last := patternSegs[n-1]
		if strings.HasPrefix(last, "{") && strings.HasSuffix(last, "...}") {
			fixed := patternSegs[:n-1]
			if len(uriSegs) < len(fixed) {
				return "", false
			}
			return matchPrefix(fixed, uriSegs, needle)
		}
	}

	if len(patternSegs) != len(uriSegs) {
		return "", false
	}
	return matchPrefix(patternSegs, uriSegs, needle)
}

func matchPrefix(patternSegs, uriSegs []string, needle string) (string, bool) {
	for i, ps := range patternSegs {
		if ps == needle {
			v := percentDecode(uriSegs[i])
			if v == "" {
				return "", false
			}
			return v, true
		}
	}
	return "", false
}

func splitPath(p string) []string {
	raw := strings.Split(p, "/")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// percentDecode returns the decoded segment, or the raw segment when it is not
// valid percent-encoding. Never an error: a value that fails to decode is still
// a value, and treating it as absent would be a widen-by-accident.
func percentDecode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/host/ -run TestPathParamFromMatch -v`
Expected: PASS — all 10 subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/host/binding.go internal/host/binding_test.go
git commit -m "feat(binder): extract path params by re-matching the route pattern

r.PathValue does not work at the gate: patternMux has empty handlers and is
consulted via Handler(r), which returns the pattern but never populates path
values. Handles a trailing {name...} catch-all, which absorbs one-or-more
segments and would defeat an exact segment-count check (knowdb #347)."
```

---

## Task 4: Parse the `x-entitlement-binding` extension

**Files:**
- Modify: `internal/host/binding.go`, `internal/host/binding_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `type bindingSource struct { In string; Name string }` — `In` ∈ {`path`, `query`, `header`}
  - `type bindingSpec map[string][]bindingSource`
  - `func parseBindingSpec(ext map[string]any) (bindingSpec, error)`

The extension is authored beside `security` on the operation and reaches us via `op.Extensions` (kin-openapi's `UnmarshalJSON` dumps every unknown `x-*` key there; `spec.api` carries `PreserveUnknownFields` so the apiserver keeps it). Shape:

```yaml
x-entitlement-binding:
  vector_store_id:
    - { in: header, name: X-Vector-Store-Id }
```

A malformed spec is an **error**, not a skip. Silently ignoring a typo'd source leaves the placeholder unbound and produces a runtime denial whose cause is invisible.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/binding_test.go`:

```go
func TestParseBindingSpec(t *testing.T) {
	t.Run("absent extension yields nil spec and no error", func(t *testing.T) {
		got, err := parseBindingSpec(map[string]any{})
		assert.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("single header source", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "header", "name": "X-Vector-Store-Id"}},
		}}
		got, err := parseBindingSpec(ext)
		assert.NoError(t, err)
		assert.Equal(t, []bindingSource{{In: "header", Name: "X-Vector-Store-Id"}}, got["vector_store_id"])
	})

	t.Run("ordered chain preserves order", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{
				map[string]any{"in": "query", "name": "vector_store_id"},
				map[string]any{"in": "header", "name": "X-Vector-Store-Id"},
			},
		}}
		got, err := parseBindingSpec(ext)
		assert.NoError(t, err)
		assert.Equal(t, []bindingSource{
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}, got["vector_store_id"])
	})

	t.Run("rejects an AS-unreadable location", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "body", "name": "vector_store_id"}},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "header", "name": ""}},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects an empty chain", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects a non-object extension", func(t *testing.T) {
		_, err := parseBindingSpec(map[string]any{"x-entitlement-binding": "nonsense"})
		assert.Error(t, err)
	})
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/host/ -run TestParseBindingSpec -v`
Expected: FAIL — `undefined: parseBindingSpec`

- [ ] **Step 3: Write the implementation**

Append to `internal/host/binding.go` (add `"fmt"` to the imports):

```go
// bindingExtensionKey is the operation-level OpenAPI extension declaring where
// a requirement placeholder's value comes from. It sits beside `security` and
// `x-required-entitlement` so an author reads all three together.
const bindingExtensionKey = "x-entitlement-binding"

// bindingSource is one link in a placeholder's precedence chain.
// In is one of: path, query, header.
type bindingSource struct {
	In   string
	Name string
}

// bindingSpec maps a placeholder key to its ordered source chain, mirroring the
// BACKEND's own precedence -- first match wins.
//
// Only sources the AS can read are expressible, and that is the point: an op
// whose backend resolves the identity from a request body or a database row
// must not declare a placeholder at all (the design doc's legality rule),
// because deriving a lower-precedence fallback is not deriving the target.
type bindingSpec map[string][]bindingSource

func parseBindingSpec(ext map[string]any) (bindingSpec, error) {
	raw, ok := ext[bindingExtensionKey]
	if !ok {
		return nil, nil
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object mapping a placeholder key to a source chain", bindingExtensionKey)
	}

	spec := make(bindingSpec, len(obj))
	for key, v := range obj {
		list, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("%s.%s must be an array of sources", bindingExtensionKey, key)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s.%s must declare at least one source", bindingExtensionKey, key)
		}
		chain := make([]bindingSource, 0, len(list))
		for i, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s.%s[%d] must be an object with 'in' and 'name'", bindingExtensionKey, key, i)
			}
			in, _ := m["in"].(string)
			name, _ := m["name"].(string)
			switch in {
			case "path", "query", "header":
			default:
				return nil, fmt.Errorf("%s.%s[%d]: 'in' must be path, query, or header (got %q) -- a source the AS cannot read must not be declared", bindingExtensionKey, key, i, in)
			}
			if name == "" {
				return nil, fmt.Errorf("%s.%s[%d]: 'name' must not be empty", bindingExtensionKey, key, i)
			}
			chain = append(chain, bindingSource{In: in, Name: name})
		}
		spec[key] = chain
	}
	return spec, nil
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/host/ -run TestParseBindingSpec -v`
Expected: PASS — all 7 subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/host/binding.go internal/host/binding_test.go
git commit -m "feat(binder): parse the x-entitlement-binding operation extension

Declares a placeholder's ordered source chain beside security. Rides the
existing PreserveUnknownFields -> Operation.Extensions path, so no CRD change.
Only path/query/header are expressible: a source the AS cannot read must not
be declared. A malformed spec is an error, not a silent skip."
```

---

## Task 5: Resolve a request's bindings

**Files:**
- Modify: `internal/host/binding.go`, `internal/host/binding_test.go`

**Interfaces:**
- Consumes: `pathParamFromMatch`, `splitPath` (Task 3); `bindingSpec`, `bindingSource` (Task 4).
- Produces:
  - `func resolveBinding(r *http.Request, pattern string, spec bindingSpec, keys []string) entitlements.Binding`
  - `func placeholderKeys(spec bindingSpec, pattern string) []string`

Per key: the declared chain if the op has one, else a path identity match. An unresolvable key is **absent** from the map — `BindRequirements` then returns `ErrUnboundPlaceholder`, which is the contract working. Never insert a default, a `*`, or an empty string.

`placeholderKeys` returns a superset (declared keys ∪ pattern `{...}` names). That is safe and cheap: `BindRequirements` ignores keys matching no placeholder, and `ParsedRequirements` does not expose its placeholder names (Key Fact 6).

- [ ] **Step 1: Write the failing test**

Append to `internal/host/binding_test.go` (add `"net/http/httptest"` to imports):

```go
func TestResolveBinding(t *testing.T) {
	t.Run("path identity match with no spec", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/vector_stores/vs_abc", nil)
		got := resolveBinding(r, "/v1/vector_stores/{vector_store_id}", nil, []string{"vector_store_id"})
		assert.Equal(t, "vs_abc", got["vector_store_id"])
	})

	t.Run("declared header source", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_abc")
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_abc", got["vector_store_id"])
	})

	t.Run("chain: first link wins", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/search?vector_store_id=vs_query", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_header")
		spec := bindingSpec{"vector_store_id": {
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}}
		got := resolveBinding(r, "/v1/search", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_query", got["vector_store_id"], "query must outrank header")
	})

	t.Run("chain: falls through to the second link", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/search", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_header")
		spec := bindingSpec{"vector_store_id": {
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}}
		got := resolveBinding(r, "/v1/search", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_header", got["vector_store_id"])
	})

	t.Run("unresolvable key is ABSENT, never defaulted", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "unresolved key must be absent so BindRequirements errors")
	})

	t.Run("blank header is absent, not empty", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		r.Header.Set("X-Vector-Store-Id", "   ")
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "a blank value would be ErrInvalidBoundValue; it must not bind")
	})

	t.Run("resolves only requested keys", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/vector_stores/vs_abc/files/f_1", nil)
		got := resolveBinding(r, "/v1/vector_stores/{vector_store_id}/files/{file_id}", nil, []string{"vector_store_id"})
		_, present := got["file_id"]
		assert.False(t, present)
	})

	t.Run("no keys yields a nil binding", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/ingest", nil)
		assert.Nil(t, resolveBinding(r, "/v1/ingest", nil, nil))
	})
}

func TestPlaceholderKeys(t *testing.T) {
	t.Run("union of declared keys and pattern params, deduped", func(t *testing.T) {
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := placeholderKeys(spec, "/v1/vector_stores/{vector_store_id}/files/{file_id}")
		assert.ElementsMatch(t, []string{"vector_store_id", "file_id"}, got)
	})

	t.Run("catch-all is not a key", func(t *testing.T) {
		got := placeholderKeys(nil, "/v1/vector_stores/{vector_store_id}/path/content/{uri...}")
		assert.ElementsMatch(t, []string{"vector_store_id"}, got)
	})

	t.Run("no spec and no params yields empty", func(t *testing.T) {
		assert.Empty(t, placeholderKeys(nil, "/v1/ingest"))
	})
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/host/ -run 'TestResolveBinding|TestPlaceholderKeys' -v`
Expected: FAIL — `undefined: resolveBinding`, `undefined: placeholderKeys`

- [ ] **Step 3: Write the implementation**

Append to `internal/host/binding.go` (add `"net/http"` and `entitlements "github.com/kdex-tech/entitlements/go"` to imports):

```go
// resolveBinding builds the per-request Binding for the placeholder keys a
// requirement set may need.
//
// Per key: the declared chain if the op has one, else a path identity match
// against the route pattern (a {vector_store_id} in `security` matching a
// {vector_store_id} in the path is not a convention -- it is an identity match
// against a pattern present in the CR).
//
// A key that cannot be resolved is ABSENT from the result, never defaulted.
// BindRequirements then returns ErrUnboundPlaceholder and the gate denies. That
// is the contract working: a binder that cannot resolve a value must fail like
// an unbound placeholder rather than widen. Do NOT add a `system` or `*`
// fallback here -- those are knowdb's policy, not the binder's.
func resolveBinding(r *http.Request, pattern string, spec bindingSpec, keys []string) entitlements.Binding {
	if len(keys) == 0 {
		return nil
	}
	b := make(entitlements.Binding, len(keys))
	for _, key := range keys {
		if v, ok := resolveKey(r, pattern, spec, key); ok {
			b[key] = v
		}
	}
	return b
}

func resolveKey(r *http.Request, pattern string, spec bindingSpec, key string) (string, bool) {
	if chain, ok := spec[key]; ok {
		for _, src := range chain {
			if v, ok := readSource(r, pattern, src); ok {
				return v, true
			}
		}
		return "", false
	}
	// Undeclared: the only legal implicit source is the path, where the pattern
	// itself names the param. A header is NEVER inferred -- host-manager is
	// generic across every function and must not guess the header spelling of a
	// backend it does not control.
	return pathParamFromMatch(pattern, r.URL.Path, key)
}

func readSource(r *http.Request, pattern string, src bindingSource) (string, bool) {
	var v string
	switch src.In {
	case "path":
		pv, ok := pathParamFromMatch(pattern, r.URL.Path, src.Name)
		if !ok {
			return "", false
		}
		v = pv
	case "query":
		v = r.URL.Query().Get(src.Name)
	case "header":
		v = r.Header.Get(src.Name)
	default:
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// placeholderKeys returns the placeholder names worth resolving for a route:
// every key the op declares a chain for, plus every {name} segment in the route
// pattern. ParsedRequirements does not expose its placeholder names, so this is
// a superset -- safe and cheap, because BindRequirements ignores binding keys
// that match no placeholder.
func placeholderKeys(spec bindingSpec, pattern string) []string {
	seen := make(map[string]struct{}, len(spec)+2)
	keys := make([]string, 0, len(spec)+2)
	add := func(k string) {
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range spec {
		add(k)
	}
	for _, seg := range splitPath(pattern) {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(seg, "{"), "}")
		if strings.HasSuffix(name, "...") {
			continue // a catch-all is a path remainder, not an identity
		}
		add(name)
	}
	return keys
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/host/ -run 'TestResolveBinding|TestPlaceholderKeys' -v`
Expected: PASS — all 11 subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/host/binding.go internal/host/binding_test.go
git commit -m "feat(binder): resolve a request's placeholder bindings

Declared chain first (first link wins, mirroring the backend's precedence),
else a path identity match. An unresolvable key is absent, never defaulted --
BindRequirements then errors, which is the contract working. No system/*
fallback: that is knowdb policy, not binder behavior."
```

---

## Task 6: Wire the binder into the gate

**Files:**
- Modify: `internal/host/types.go` (`KDexFunctionHandler`), `internal/host/proxy.go:315-352` and `:500-513`
- Create: `internal/host/binder_gate_test.go`

**Interfaces:**
- Consumes: `resolveBinding`, `placeholderKeys` (Task 5); `parseBindingSpec` (Task 4); `BindRequirements` on the interface (Task 2).
- Produces: `KDexFunctionHandler.bindingSpecs map[string]bindingSpec`, keyed identically to `parsedRequirements` (`method + " " + pattern`). Task 7 does not consume it.

The security-critical task. Bind **after** the authContext enrichment invariant (#142, `proxy.go:496-498`) and **immediately before** `VerifyResourceParsedEntitlements`. A bind error denies and must never fall through to verify.

`runProxy` cannot test this (Key Fact 4), so this task brings its own fixture using a real `auth.NewAuthorizationChecker`.

- [ ] **Step 1: Write the failing test**

Create `internal/host/binder_gate_test.go`:

```go
package host

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// binderFixture builds a reverse-proxy handler for fn with a REAL
// AuthorizationChecker, and returns the handler plus a flag reporting whether
// the upstream was reached (i.e. the gate passed).
func binderFixture(t *testing.T, fn *kdexv1alpha1.KDexFunction) (http.Handler, *bool) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	reached := new(bool)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	fn.Status.URL = upstream.URL

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cacheManager, _ := cache.NewCacheManager("", "binder-test", nil)

	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authChecker:  auth.NewAuthorizationChecker(nil, logr.Discard()),
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: privateKey},
		},
	}
	return hh.reverseProxyHandler(fn, "https://test-host.example.com"), reached
}

// scopedStoreFn is a function whose GET op is path-scoped and declares a
// {vector_store_id} placeholder -- the shape the CR migration will adopt.
func scopedStoreFn() *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-stores", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/api/v1/vector_stores",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/api/v1/vector_stores/{vector_store_id}": {
						Get: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "getStore",
							"security": [{"bearer": [
								"functions:/api/v1/vector_stores:read",
								"vector_stores:{vector_store_id}:read"
							]}]
						}`)},
					},
				},
			},
		},
	}
}

// requestAs drives one request through the handler carrying `held` entitlements.
func requestAs(t *testing.T, h http.Handler, method, path string, held []string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ac := auth.AuthContext{}
	ac.SetEntitlements(held)
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// The entitlements#4 regression: a caller holding ONE store must not pass a
// {vector_store_id} gate while addressing a DIFFERENT store. Pre-binding, the
// requirement was vector_stores:*:read and any single grant satisfied it.
func TestGate_BindsPathPlaceholder_DeniesOtherStore(t *testing.T) {
	h, reached := binderFixture(t, scopedStoreFn())
	held := []string{"functions:/api/v1/vector_stores:read", "vector_stores:vs_alice:all"}

	code := requestAs(t, h, "GET", "/api/v1/vector_stores/vs_alice", held, nil)
	assert.Equal(t, http.StatusOK, code, "own store must pass")
	assert.True(t, *reached)

	*reached = false
	code = requestAs(t, h, "GET", "/api/v1/vector_stores/vs_bob", held, nil)
	assert.NotEqual(t, http.StatusOK, code, "another store must DENY -- this is entitlements#4")
	assert.False(t, *reached, "upstream must not be reached")
}

// An unbound placeholder must DENY even for a wildcard holder. Without the
// bind-error branch this silently admits every wildcard holder, because an
// unbound placeholder is an ordinary literal and a wildcard matches any literal.
func TestGate_UnboundPlaceholderDenies(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-ingest", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/api/v1/ingest",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/api/v1/ingest": {
						Post: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "ingest",
							"security": [{"bearer": [
								"functions:/api/v1/ingest:create",
								"vector_stores:{vector_store_id}:write"
							]}],
							"x-entitlement-binding": {
								"vector_store_id": [{"in": "header", "name": "X-Vector-Store-Id"}]
							}
						}`)},
					},
				},
			},
		},
	}
	h, reached := binderFixture(t, fn)
	held := []string{"functions:/api/v1/ingest:create", "vector_stores::all"} // wildcard holder

	code := requestAs(t, h, "POST", "/api/v1/ingest", held, nil) // no header -> unbound
	assert.NotEqual(t, http.StatusOK, code, "unbound placeholder must deny even a wildcard holder")
	assert.False(t, *reached)

	*reached = false
	code = requestAs(t, h, "POST", "/api/v1/ingest", held, map[string]string{"X-Vector-Store-Id": "vs_abc"})
	assert.Equal(t, http.StatusOK, code, "a bound header must pass for a wildcard holder")
}

// Additivity: a CR with no {param} must behave exactly as before.
func TestGate_NoPlaceholderIsUnchanged(t *testing.T) {
	fn := scopedStoreFn()
	fn.Spec.API.Paths["/api/v1/vector_stores/{vector_store_id}"] = kdexv1alpha1.PathItem{
		Get: &runtime.RawExtension{Raw: []byte(`{
			"operationId": "getStore",
			"security": [{"bearer": ["functions:/api/v1/vector_stores:read"]}]
		}`)},
	}
	h, _ := binderFixture(t, fn)
	held := []string{"functions:/api/v1/vector_stores:read"}
	assert.Equal(t, http.StatusOK, requestAs(t, h, "GET", "/api/v1/vector_stores/vs_bob", held, nil))
}
```

> **Implementer note:** `auth.AuthContext` construction and `SetEntitlements` are guesses at the API — read `internal/host/proxy_enriched_ac_test.go:117` (`auth.SetAuthContext(t.Context(), auth.AuthContext{...})`) and `internal/auth/`'s `AuthContext` definition, and match the real constructor. The *assertions* are the specification; adapt only the setup.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/host/ -run 'TestGate_' -v`
Expected: FAIL — `fh.bindingSpecs undefined`, and once that compiles, `vs_bob` returns 200 (the unbound placeholder is a literal that the `vs_alice` grant's wildcard verb matches).

- [ ] **Step 3: Add the cache field**

In `internal/host/types.go`, inside `KDexFunctionHandler` after `parsedRequirements`:

```go
	// bindingSpecs holds each route's x-entitlement-binding declaration, keyed
	// identically to parsedRequirements (method + " " + pattern). Parsed once at
	// mux-build, not per request. A route with no declaration is absent, and its
	// placeholders (if any) bind by path identity match. See
	// docs/superpowers/specs/2026-07-16-requirement-binding-sources-design.md.
	bindingSpecs map[string]bindingSpec
```

- [ ] **Step 4: Populate it at mux-build**

In `internal/host/proxy.go` (inside `reverseProxyHandler`, at 315-344), replace the loop:

```go
	patternMux := http.NewServeMux()
	parsedRequirements := make(map[string]entitlements.ParsedRequirements)
	bindingSpecs := make(map[string]bindingSpec)

	acceptsAPIKey := false

	for p, item := range fn.Spec.API.Paths {
		// Use empty handler, we only care about the pattern match
		patternMux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {})

		for _, method := range []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"} {
			op := item.GetOp(method)
			if op == nil {
				continue
			}
			key := method + " " + p

			// Parse the binding declaration even when the op has no security
			// block: a malformed declaration is an authoring error worth
			// surfacing wherever it appears.
			if spec, err := parseBindingSpec(op.Extensions); err != nil {
				hh.log.Error(err, "invalid x-entitlement-binding; placeholders on this route will not bind",
					"function", fn.Name, "route", key)
			} else if spec != nil {
				bindingSpecs[key] = spec
			}

			if op.Security != nil {
				raw := make([]kdexv1alpha1.SecurityRequirement, 0, len(*op.Security))
				for _, s := range *op.Security {
					sr := kdexv1alpha1.SecurityRequirement(s)
					raw = append(raw, sr)
					for scheme := range sr {
						if isAPIKeyScheme(scheme) {
							acceptsAPIKey = true
						}
					}
				}
				parsedRequirements[key] = hh.authChecker.ParseRequirements(raw)
			}
		}
	}
```

Add to the `fh := &KDexFunctionHandler{...}` literal (`proxy.go:346`):

```go
		bindingSpecs:       bindingSpecs,
```

> **Implementer note:** `hh.log` is used above. Confirm it is the logger this function already has in scope; if `reverseProxyHandler` uses a different one, match it. Do not add a package-level logger.

- [ ] **Step 5: Bind at the gate**

In `internal/host/proxy.go`, inside `if authChecker != nil {` (at ~500), between the requirement lookup and `VerifyResourceParsedEntitlements`:

```go
			// Bind {param} requirements from the request before verifying, so the
			// gate checks the store actually being addressed rather than a
			// wildcard any single-store grant satisfies (entitlements#4).
			//
			// A bind error DENIES and must never fall through to Verify: an
			// unbound placeholder is an ordinary literal there, and a held
			// wildcard matches any literal, so falling through would silently
			// admit every wildcard holder. The error is the invariant enforcing
			// itself -- it means the CR declared an identity this layer cannot
			// supply. See the design doc's legality rule.
			spec := fh.bindingSpecs[key]
			binding := resolveBinding(r, pattern, spec, placeholderKeys(spec, pattern))
			boundReqs, bindErr := authChecker.BindRequirements(reqs, binding)
			if bindErr != nil {
				log.Error(bindErr, "requirement binding failed; denying",
					"function", fn.Name, "route", key)
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			reqs = boundReqs
```

`BindRequirements` is a no-op for placeholder-free sets, so this is safe to call unconditionally — no guard needed.

- [ ] **Step 6: Run to verify they pass**

Run: `go test ./internal/host/ -run 'TestGate_' -v`
Expected: PASS — all three.

- [ ] **Step 7: Run the full suite**

Run: `make test`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/host/types.go internal/host/proxy.go internal/host/binder_gate_test.go
git commit -m "feat(binder): bind {param} requirements at the gate before verifying

Closes entitlements#4 at the AS tier for path-scoped ops: a caller holding
vector_stores:vs_alice:all no longer passes a vector_stores:{vector_store_id}:read
gate while addressing vs_bob.

A bind error denies and never falls through to Verify -- an unbound placeholder
is an ordinary literal there, and a held wildcard matches any literal, so
falling through would silently admit every wildcard holder.

Specs parse once per route at mux-build, matching parsedRequirements' lifecycle."
```

---

## Task 7: Keep `/-/check` honest about instance-scoped requirements

**Files:**
- Modify: `internal/host/check.go:84-96`, `internal/host/check_test.go`

**Interfaces:**
- Consumes: `entitlements.ErrUnboundPlaceholder` (Task 1); `BindRequirements` on the interface (Task 2).
- Produces: nothing.

`/-/check` is a **second consumer** of `parsedRequirements` (`check.go:88`) with no target request to bind from — its check strings (`functions:/api/v1/foo:delete`) name a function and a verb, never a store instance. So an instance-scoped requirement is *not applicable* to the question asked, and excluding it is correct rather than a compromise.

Without this, a `{param}`-bearing route reached via `/-/check` verifies with an **unbound** placeholder: with strict off it is an ordinary literal, so a wildcard holder matches and a specific holder does not — the endpoint would tell a caller who *would* pass the real request that they would not.

> **Pre-existing quirk, NOT in scope:** `check.go:87` builds its key as `strings.ToUpper(verb) + " " + resourceName` where `verb` is an *entitlement* verb (`read`/`write`/`create`/`delete`), while `proxy.go` keys by **HTTP method**. The lookup therefore only hits when the verb happens to spell an HTTP method — i.e. `delete`, by accident. Every other verb misses and falls back to empty requirements (`check.go:93`). Do not fix it here; file it separately. It is why the test below uses the `delete` verb — it is the only one that reaches the code path.

- [ ] **Step 1: Write the failing test**

Add to `internal/host/check_test.go`, and give `checkAuthChecker` a real placeholder-aware `BindRequirements` (replacing Task 2's pass-through) so the probe has something to report:

```go
// checkAuthChecker's BindRequirements must behave like the real one for this
// test: report ErrUnboundPlaceholder when the set has a placeholder and the
// binding does not cover it. Delegate to a real checker rather than faking it.
func (m *checkAuthChecker) BindRequirements(reqs entitlements.ParsedRequirements, b entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return m.real.BindRequirements(reqs, b)
}
```

```go
func TestCheck_ExcludesInstanceScopedRequirements(t *testing.T) {
	// A DELETE op declaring vector_stores:{vector_store_id}:own. `delete` is the
	// only verb whose uppercased form matches an HTTP method, so it is the only
	// one that reaches check.go's parsedRequirements lookup at all.
	//
	// The caller holds the function grant plus ONE specific store. The check
	// names no store, so the instance-scoped requirement is not applicable and
	// must be excluded -- the caller passes on the function gate.
	//
	// Without the fix the unbound {vector_store_id} verifies as a literal, the
	// specific holder fails to match it, and the endpoint wrongly reports
	// "not passed" for a request the caller would actually be allowed to make.
	held := []string{"functions:/api/v1/vector_stores:delete", "vector_stores:vs_alice:own"}
	// ... build the HostHandler + functionHandlers entry via check_test.go's
	// existing harness, POST {"checks":["functions:/api/v1/vector_stores:delete"]} ...
	assert.Contains(t, resp.Passed, "functions:/api/v1/vector_stores:delete")
}
```

> **Implementer note:** read `internal/host/check_test.go` first — reuse its existing harness for building `HostHandler`, `functionHandlers`, and issuing the request. `m.real` above assumes you give `checkAuthChecker` an embedded real `*auth.AuthorizationChecker`; if the fake is structured differently, adapt. The assertion is the specification.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/host/ -run TestCheck_ExcludesInstanceScoped -v`
Expected: FAIL — the check is reported as not passed.

- [ ] **Step 3: Write the implementation**

In `internal/host/check.go`, replace the `case "functions":` block (84-96):

```go
		case "functions":
			// Try to find the function handler to get pre-parsed requirements
			if fh, ok := hh.functionHandlers[resourceName]; ok {
				key := strings.ToUpper(verb) + " " + resourceName
				if pr, ok := fh.parsedRequirements[key]; ok {
					// /-/check asks an instance-FREE question: its check strings
					// name a function and a verb, never a store. So an
					// instance-scoped ({param}) requirement is not applicable
					// here -- we have no request to bind it from. Probe with an
					// empty binding: a placeholder-free set returns unchanged; a
					// placeholder-bearing one reports ErrUnboundPlaceholder.
					//
					// Exclude rather than fail: failing would hide UI a caller
					// can legitimately use. The gate still enforces the instance
					// check on the real request.
					if _, err := hh.authChecker.BindRequirements(pr, nil); errors.Is(err, entitlements.ErrUnboundPlaceholder) {
						requirements = hh.authChecker.ParseRequirements(nil)
					} else {
						requirements = pr
					}
					found = true
				} else {
					// Default to empty requirements for the function identity check
					requirements = hh.authChecker.ParseRequirements(nil)
					found = true
				}
			}
```

Add `"errors"` to the import block.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/host/ -run TestCheck_ExcludesInstanceScoped -v`
Expected: PASS

- [ ] **Step 5: Run the full suite + lint**

Run: `make test`, then `make lint` from `/home/rotty/projects/kdex/workspace`
Expected: PASS, clean.

- [ ] **Step 6: Commit**

```bash
git add internal/host/check.go internal/host/check_test.go
git commit -m "fix(check): exclude instance-scoped requirements from /-/check

/-/check asks an instance-free question -- its check strings name a function and
a verb, never a store -- so it has no request to bind a {param} from. An unbound
placeholder verifies as a literal, which a wildcard holder matches and a
specific holder does not, so the endpoint would tell a caller who WOULD pass the
real request that they would not.

Excluding rather than failing: failing would hide UI the caller can legitimately
use. The gate still enforces the instance check on the real request."
```

---

## Task 8: Mark the design doc implemented

**Files:**
- Modify: `docs/superpowers/specs/2026-07-16-requirement-binding-sources-design.md`

- [ ] **Step 1: Add an implementation-status note under `## Resolution`**

```markdown
> **Implemented** 2026-07-16 in `internal/host/binding.go` + `internal/host/proxy.go`.
> Binding specs parse at mux-build and cache on `KDexFunctionHandler.bindingSpecs`;
> the gate binds immediately before `VerifyResourceParsedEntitlements`. `/-/check`
> excludes instance-scoped requirements (it has no request to bind from). No CR
> declares a `{param}` yet, so the change is inert until the migration.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-07-16-requirement-binding-sources-design.md
git commit -m "docs(spec): mark the binder implemented"
```

---

## Verification (whole branch)

- [ ] `make test` in `kdex-host-manager` — PASS
- [ ] `make lint` from `/home/rotty/projects/kdex/workspace` — clean
- [ ] **Additivity:** every pre-existing test passes untouched. Only `check_test.go`'s fake gains a real `BindRequirements`; no existing assertion changes.
- [ ] **The #4 regression:** held `vector_stores:vs_alice:all`, required `vector_stores:{vector_store_id}:read` → PASS on `vs_alice`, **DENY** on `vs_bob`.
- [ ] **Never widens:** an unbound placeholder denies a `vector_stores::all` wildcard holder.

## Deliberately NOT in this plan

- **CR migration.** No knowdrive-site changes. The binder is inert until a CR declares a `{param}`; migrating the 12 path-scoped paths is the next track.
- **The 4 body-overridable ops.** Blocked on knowdb #360 — they must not adopt `{param}` first (today a wildcard holder omitting the header is defaulted to `system` and succeeds; under the binder they would be denied).
- **`check.go`'s verb/method key mismatch.** Pre-existing; file separately.
- **Strict mode.** Stays default-off until v1.0.0.
- **An authoring-time lint check.** Still open (design doc, *Authoring-time enforcement*).

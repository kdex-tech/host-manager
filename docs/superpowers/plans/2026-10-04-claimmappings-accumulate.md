# claimMappings Accumulate-by-Default Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `claimMappings` rule whose target already holds a list accumulates (order-preserving set-union) instead of replacing it, with a per-rule `merge: Replace` opt-out — closing host-manager#229.

**Architecture:** The semantics live in `kdex-tech/dmapper` (`Mapper.Execute`). kdex-crds embeds `dmapper.MappingRule` in `KDexHost.spec.auth.claimMappings` and `KDexFunction.spec.claimMappings`, so the new field reaches the CRD schema by bumping dmapper there. host-manager needs no production change (it copies mapper output over the context, and that output now already contains the existing list) — only the dependency bumps and regression tests. Then crds + nexus + host-manager release in lockstep and infra repins.

**Tech Stack:** Go 1.26, CEL (`github.com/google/cel-go`), kubebuilder/controller-gen markers, envtest, testify.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-10-04-claimmappings-accumulate-design.md`

## Global Constraints

- Field: `Merge MergeStrategy \`json:"merge,omitempty"\``; values exactly `Accumulate` and `Replace`; empty means `Accumulate`.
- Only list-onto-list accumulates (`[]string`/`[]any` on either side). Maps and scalars replace.
- Union, not concat: existing list first, then each result item not already present. Existing list's own duplicates are preserved untouched.
- Element equality: string fast path via a set; otherwise `reflect.DeepEqual`.
- Result shape: `[]string` when every merged element is a string, else `[]any`.
- Unknown `merge` value → `NewMapper` returns an error.
- `Execute` must never mutate the caller's input.
- host-manager code stays claim-agnostic: no claim name special-cased; tests use an arbitrary example source claim (`extra_grants`, `extra_roles`).
- dmapper release: **v0.2.0**. host-manager release: **v0.20.0** (minor). crds: patch via `./updateCrdUsage.sh -t`. nexus: released too (v0.5.20).
- A CRD change releases host-manager AND nexus-manager; run each actor's `make test`, not just `go build`.
- Never hand-edit the `replace kdex.dev/crds` directives; `./updateCrdUsage.sh` does it.
- Commit inside each sub-repo, never at the workspace root. Rebase + `--ff-only`, never merge commits.
- After code changes run `make lint` in the touched repo (per-task agents tend to skip golangci-lint — don't).

## Review Focus

1. **Running the mapper twice over its own output** (`EnrichAuthContext` then `Project`) — expected: no duplicates, no growth, for a non-`entitlements` list claim where `entitlements.Compact` can't mask it. Pinned in Task 2 (`AccumulateIsIdempotent`) and Task 6 (`EnrichThenProjectNoGrowth`).
2. **Mixed list shapes** (`[]any` from JWT decoding on one side, `[]string` from CEL on the other) — expected: merged correctly, all-string result comes back `[]string`. Pinned in Task 2 (`AccumulateShapes`).
3. **A filtering rule** (`self.roles.filter(...)`) — expected: without `Replace` it can no longer remove items (documented hazard), with `Replace` it narrows. Pinned in Task 2 (`ReplaceNarrows`) and Task 6.
4. **Nested target path** (`auth.groups`) with an existing list — expected: accumulates the same as a top-level target. Pinned in Task 2 (`AccumulateNestedPath`).
5. **Rule result of a different shape than the existing value** (list existing, scalar result; map existing) — expected: replace, as today. Pinned in Task 2 (`NonListReplaces`).

---

## File Structure

| File | Responsibility |
|---|---|
| `kdex-dmapper/dmapper.go` | `MergeStrategy` type + `Merge` field; validate in `compileMappers`; apply in `Execute` via `getNestedPath` + `accumulate` |
| `kdex-dmapper/merge.go` (create) | `accumulate`, `asList`, `narrow`, `getNestedPath` — the merge helpers, kept out of the mapper core |
| `kdex-dmapper/dmapper_merge_test.go` (create) | All merge-semantics tests |
| `kdex-dmapper/README.md` | "Merge semantics" section |
| `kdex-crds/go.mod`, `go.sum` | dmapper v0.2.0 |
| `kdex-crds/api/v1alpha1/kdexhost_types.go`, `kdexfunction_types.go` | Rewrite `claimMappings` descriptions |
| `kdex-crds/config/crd/bases/*.yaml` (generated) | `merge` enum appears |
| `kdex-host-manager/go.mod`, `go.sum` | dmapper v0.2.0 + crds pin |
| `kdex-host-manager/internal/sign/sign_accumulate_test.go` (create) | #229 regression tests through the real signer |
| `kdex-nexus-manager/go.mod`, `go.sum` | crds pin (dmapper indirect) |
| `RSI/infra` (Makefile, `kcnas/crds/*`, `terraform/kcnas.tf`, `terraform/variables.tf`, `fleet/platform/components/kcnas-operator.yaml`, `tests/*`) | lockstep repin, same file set as infra `8320cd1` |

---

### Task 1: dmapper `MergeStrategy` field and validation

**Files:**
- Modify: `kdex-dmapper/dmapper.go:16-38` (MappingRule), `:137-158` (compileMappers)
- Create: `kdex-dmapper/dmapper_merge_test.go`

**Interfaces:**
- Produces: `type MergeStrategy string`; `const MergeAccumulate MergeStrategy = "Accumulate"`; `const MergeReplace MergeStrategy = "Replace"`; field `MappingRule.Merge MergeStrategy`.

- [ ] **Step 1: Write the failing test** — create `kdex-dmapper/dmapper_merge_test.go`:

```go
package dmapper_test

import (
	"testing"

	"github.com/kdex-tech/dmapper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMapper_MergeStrategyValidation pins that only the empty value,
// Accumulate and Replace compile; anything else is an error, never a silent
// fallback. See kdex-tech/host-manager#229.
func TestNewMapper_MergeStrategyValidation(t *testing.T) {
	for _, ok := range []dmapper.MergeStrategy{"", dmapper.MergeAccumulate, dmapper.MergeReplace} {
		_, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: "self.a", TargetPropPath: "b", Merge: ok}})
		assert.NoErrorf(t, err, "merge %q must compile", ok)
	}
	_, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: "self.a", TargetPropPath: "b", Merge: "append"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"append"`)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd kdex-dmapper && go test ./... -run TestNewMapper_MergeStrategyValidation -v`
Expected: FAIL — compile error `undefined: dmapper.MergeStrategy`.

- [ ] **Step 3: Implement** — in `dmapper.go`, add above `MappingRule`:

```go
// MergeStrategy controls how a rule's result combines with a value already
// present at its targetPropPath.
type MergeStrategy string

const (
	// MergeAccumulate (the default when empty): when both the existing value
	// and the result are lists, the result is the existing list followed by
	// the result's items not already present. Any other shape pair replaces.
	MergeAccumulate MergeStrategy = "Accumulate"
	// MergeReplace: the result always replaces the existing value. Use it for
	// a rule that filters or narrows a list.
	MergeReplace MergeStrategy = "Replace"
)
```

Add the field as the FIRST field of `MappingRule` (fields are alphabetical by JSON name):

```go
	// merge controls how the rule's result combines with a value already at
	// targetPropPath. Accumulate (the default when empty): when both the
	// existing value and the result are lists, the result is the existing list
	// followed by the result's items not already present (order-preserving
	// set-union), so restating self.<target> is harmless and idempotent. Any
	// other shape pair (scalar, map, list vs non-list) replaces. Replace: the
	// result always replaces — use it for a rule that filters or narrows a
	// list.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Accumulate;Replace
	Merge MergeStrategy `json:"merge,omitempty"`
```

In `compileMappers`, at the top of the `for _, rule := range rules` loop:

```go
		switch rule.Merge {
		case "", MergeAccumulate, MergeReplace:
		default:
			return nil, fmt.Errorf("rule targeting %q: unknown merge strategy %q (want %q or %q)",
				rule.TargetPropPath, rule.Merge, MergeAccumulate, MergeReplace)
		}
```

- [ ] **Step 4: Run tests**

Run: `cd kdex-dmapper && go test ./... -v`
Expected: PASS (all existing tests still pass — no behaviour change yet).

- [ ] **Step 5: Commit**

```bash
cd kdex-dmapper
git add dmapper.go dmapper_merge_test.go
git commit -m "feat: add MappingRule.merge (Accumulate|Replace) with validation (host-manager#229)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: dmapper accumulate semantics in `Execute` + README

**Files:**
- Create: `kdex-dmapper/merge.go`
- Modify: `kdex-dmapper/dmapper.go:91-106` (after `val` is computed, before `setNestedPath`)
- Modify: `kdex-dmapper/dmapper_merge_test.go`
- Modify: `kdex-dmapper/README.md`

**Interfaces:**
- Consumes: `MergeStrategy`, `MergeReplace` (Task 1).
- Produces: unexported `accumulate(existing, result any) any`, `getNestedPath(m map[string]any, path string) (any, bool)`.

- [ ] **Step 1: Write the failing tests** — append to `dmapper_merge_test.go`:

```go
// TestMapper_Execute_AccumulateIssue229 pins the three rows of
// kdex-tech/host-manager#229: every natural way to write "also add these"
// keeps the existing list.
func TestMapper_Execute_AccumulateIssue229(t *testing.T) {
	input := map[string]any{
		"entitlements": []string{"static:a"},
		"extra_grants": []string{"extra:b"},
	}
	tests := []struct {
		name  string
		rules []dmapper.MappingRule
	}{
		{"A: rule omits self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"B: rule restates self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements + self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"C: identity rule then omitting rule", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements", TargetPropPath: "entitlements"},
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := dmapper.NewMapper(tt.rules)
			require.NoError(t, err)
			got, err := m.Execute(input)
			require.NoError(t, err)
			assert.Equal(t, []string{"static:a", "extra:b"}, got["entitlements"])
		})
	}
	assert.Equal(t, []string{"static:a"}, input["entitlements"], "input must not be mutated")
}

// TestMapper_Execute_AccumulateIsIdempotent pins that re-running the mapper
// over its own merged output adds nothing (host-manager enriches the auth
// context, then Project runs the same mapper over the enriched context).
func TestMapper_Execute_AccumulateIsIdempotent(t *testing.T) {
	m, err := dmapper.NewMapper([]dmapper.MappingRule{
		{SourceExpression: "self.roles + self.extra_roles", TargetPropPath: "roles"},
	})
	require.NoError(t, err)
	in := map[string]any{"roles": []any{"admin"}, "extra_roles": []any{"auditor"}}
	first, err := m.Execute(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "auditor"}, first["roles"])

	in["roles"] = first["roles"]
	second, err := m.Execute(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "auditor"}, second["roles"])
}

// TestMapper_Execute_ReplaceNarrows pins the opt-out: a filtering rule only
// narrows with merge: Replace; under the default it cannot remove items.
func TestMapper_Execute_ReplaceNarrows(t *testing.T) {
	in := map[string]any{"roles": []string{"keep", "drop"}}
	filter := "self.roles.filter(r, r != 'drop')"

	acc, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: filter, TargetPropPath: "roles"}})
	require.NoError(t, err)
	got, err := acc.Execute(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"keep", "drop"}, got["roles"], "Accumulate cannot narrow")

	rep, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: filter, TargetPropPath: "roles", Merge: dmapper.MergeReplace}})
	require.NoError(t, err)
	got, err = rep.Execute(in)
	require.NoError(t, err)
	assert.Equal(t, []string{"keep"}, got["roles"])
}

// TestMapper_Execute_AccumulateShapes pins mixed []any/[]string inputs and
// non-string elements.
func TestMapper_Execute_AccumulateShapes(t *testing.T) {
	m, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: "self.extra", TargetPropPath: "list"}})
	require.NoError(t, err)

	got, err := m.Execute(map[string]any{"list": []any{"a", "b"}, "extra": []string{"b", "c", "c"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, got["list"], "all-string union narrows to []string; result-internal dupes collapse")

	got, err = m.Execute(map[string]any{"list": []string{"a", "a"}, "extra": []string{"b"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "a", "b"}, got["list"], "existing list's own duplicates are preserved")

	got, err = m.Execute(map[string]any{"list": []any{int64(1)}, "extra": []any{int64(1), int64(2)}})
	require.NoError(t, err)
	assert.Equal(t, []any{int64(1), int64(2)}, got["list"], "non-string elements compare by deep equality; mixed result stays []any")
}

// TestMapper_Execute_AccumulateNestedPath pins that a dotted target accumulates.
func TestMapper_Execute_AccumulateNestedPath(t *testing.T) {
	m, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: "self.more", TargetPropPath: "auth.groups"}})
	require.NoError(t, err)
	got, err := m.Execute(map[string]any{
		"auth": map[string]any{"groups": []string{"g1"}},
		"more": []string{"g2"},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"groups": []string{"g1", "g2"}}, got["auth"])
}

// TestMapper_Execute_NonListReplaces pins that scalars, maps and mismatched
// shapes still replace.
func TestMapper_Execute_NonListReplaces(t *testing.T) {
	tests := []struct {
		name string
		expr string
		in   any
		want any
	}{
		{"scalar onto scalar", "'pro'", "free", "pro"},
		{"scalar onto list", "'solo'", []string{"a"}, "solo"},
		{"list onto scalar", "['a']", "solo", []string{"a"}},
		{"map onto map", "{'k': 'new'}", map[string]any{"k": "old", "other": "x"}, map[string]any{"k": "new"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := dmapper.NewMapper([]dmapper.MappingRule{{SourceExpression: tt.expr, TargetPropPath: "t"}})
			require.NoError(t, err)
			got, err := m.Execute(map[string]any{"t": tt.in})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got["t"])
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd kdex-dmapper && go test ./... -run 'Accumulate|ReplaceNarrows|NonListReplaces' -v`
Expected: FAIL — `AccumulateIssue229` rows A and C get `[extra:b]`; `ReplaceNarrows` Accumulate half gets `[keep]`; `AccumulateShapes`/`NestedPath` lose the existing items. `NonListReplaces` PASSES already (it pins unchanged behaviour).

- [ ] **Step 3: Implement** — create `kdex-dmapper/merge.go`:

```go
package dmapper

import (
	"reflect"
	"strings"
)

// accumulate returns existing followed by each item of result not already
// present (order-preserving set-union) when both are lists; otherwise result,
// i.e. replace. The existing list's own duplicates are preserved; the result's
// are collapsed. The merged list is []string when every element is a string,
// else []any. existing is never mutated. See kdex-tech/host-manager#229.
func accumulate(existing, result any) any {
	ex, ok := asList(existing)
	if !ok {
		return result
	}
	res, ok := asList(result)
	if !ok {
		return result
	}

	merged := make([]any, 0, len(ex)+len(res))
	merged = append(merged, ex...)
	seen := make(map[string]struct{}, len(merged))
	for _, e := range merged {
		if s, ok := e.(string); ok {
			seen[s] = struct{}{}
		}
	}
	for _, r := range res {
		if s, ok := r.(string); ok {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
		} else if containsDeepEqual(merged, r) {
			continue
		}
		merged = append(merged, r)
	}
	return narrow(merged)
}

// asList views v as a list. []string and []any are lists; nothing else is.
func asList(v any) ([]any, bool) {
	switch l := v.(type) {
	case []any:
		return l, true
	case []string:
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// narrow returns l as []string when every element is a string, else l.
func narrow(l []any) any {
	out := make([]string, len(l))
	for i, e := range l {
		s, ok := e.(string)
		if !ok {
			return l
		}
		out[i] = s
	}
	return out
}

func containsDeepEqual(l []any, v any) bool {
	for _, e := range l {
		if reflect.DeepEqual(e, v) {
			return true
		}
	}
	return false
}

// getNestedPath reads the value at a dot-separated path, reporting whether
// every segment resolved.
func getNestedPath(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = mm[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}
```

In `dmapper.go` `Execute`, immediately after the `if val == nil { val = out.Value() }` block and before `setNestedPath(resultClaims, …)`:

```go
		// Accumulate (the default): a list result is unioned onto a list
		// already at the target in the chained self, so a rule that forgets to
		// restate self.<target> cannot silently drop what is there. Replace
		// opts out. See kdex-tech/host-manager#229.
		if rule.Merge != MergeReplace {
			if existing, ok := getNestedPath(self, rule.TargetPropPath); ok {
				val = accumulate(existing, val)
			}
		}
```

Also update the `Execute` doc comment block (lines 49-54) to append: `List targets accumulate by default (see MergeStrategy).`

- [ ] **Step 4: Run the full suite**

Run: `cd kdex-dmapper && make test && make lint`
Expected: PASS, lint clean. If an existing `TestMapper_Execute` table case now fails, read it: it is only legitimate if that case relied on list-onto-list replacement — report it rather than "fixing" the test.

- [ ] **Step 5: README** — add a `## Merge semantics` section to `kdex-dmapper/README.md` after the usage section:

````markdown
## Merge semantics

Rules apply in order, and each rule sees earlier rules' output in `self`. A
rule's result is then combined with whatever is already at its
`targetPropPath`, according to `merge`:

- `Accumulate` (default): when both the existing value and the result are
  lists, the result is the existing list followed by the result's items that
  are not already present. Restating `self.<target>` is harmless. Any other
  shape pair replaces.
- `Replace`: the result always replaces. Use it to filter or narrow a list.

With `entitlements: [static:a]` and `extra_grants: [extra:b]`:

| Rules (all target `entitlements`) | Result |
|---|---|
| `self.extra_grants` | `[static:a extra:b]` |
| `self.entitlements + self.extra_grants` | `[static:a extra:b]` |
| `self.entitlements`, then `self.extra_grants` | `[static:a extra:b]` |

A filter must opt out, or it cannot remove anything:

```yaml
- sourceExpression: self.roles.filter(r, r != 'guest')
  targetPropPath: roles
  merge: Replace
```

Before v0.2.0 every rule replaced its target.
````

- [ ] **Step 6: Commit**

```bash
cd kdex-dmapper
git add merge.go dmapper.go dmapper_merge_test.go README.md
git commit -m "feat!: list targets accumulate by default; merge: Replace opts out (host-manager#229)

A rule whose target already holds a list now unions its list result onto it
(existing first, new items not already present), so a rule that forgets to
restate self.<target> no longer silently drops what is there. Re-running a
mapper over its own output is idempotent. Scalars and maps still replace.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Release dmapper v0.2.0

**Files:** none (git/tag only).

- [ ] **Step 1: Push main** — `cd kdex-dmapper && git fetch origin && git rebase origin/main && git push origin main`
- [ ] **Step 2: Wait for CI green** — `gh run list --branch main --limit 1` then `gh run watch <id> --exit-status`. Expected: success.
- [ ] **Step 3: Tag** — `git tag -a v0.2.0 -m "v0.2.0: list targets accumulate by default; merge: Replace" && git push origin v0.2.0`
- [ ] **Step 4: Verify the module proxy serves it** — `GOFLAGS=-mod=mod go list -m github.com/kdex-tech/dmapper@v0.2.0`. Expected: `github.com/kdex-tech/dmapper v0.2.0`. If the proxy lags, retry after a minute; do not proceed until it resolves.

---

### Task 4: kdex-crds picks up dmapper v0.2.0 and documents the semantics

**Files:**
- Modify: `kdex-crds/go.mod`, `go.sum`
- Modify: `kdex-crds/api/v1alpha1/kdexhost_types.go` (the `ClaimMappings` doc comment, directly above line 211)
- Modify: `kdex-crds/api/v1alpha1/kdexfunction_types.go:156-163`
- Generated: `kdex-crds/config/crd/bases/*.yaml`, docs

- [ ] **Step 1: Bump** — `cd kdex-crds && go get github.com/kdex-tech/dmapper@v0.2.0 && go mod tidy`
- [ ] **Step 2: Rewrite the KDexHost description.** Read the current comment block above `ClaimMappings []dmapper.MappingRule` in `kdexhost_types.go`; keep its existing first sentence(s) describing purpose, and append:

```go
	// Rules apply in order and each sees earlier rules' output in `self`. A
	// rule whose target already holds a list ACCUMULATES by default: its list
	// result is unioned onto the existing list (existing items first, then new
	// items not already present), so a rule such as `self.extra_grants`
	// targeting `entitlements` adds to the static grants rather than replacing
	// them, and restating `self.entitlements` is harmless. Scalars and maps
	// replace. Set `merge: Replace` on a rule that must narrow a list (e.g. a
	// filter).
```

- [ ] **Step 3: Same for KDexFunction** — append the identical paragraph to the `claimMappings` comment in `kdexfunction_types.go` (after "...strip_customer_id, etc. to the FAT.").
- [ ] **Step 4: Regenerate and check the schema**

Run: `make manifests generate && rg -n -A6 '^\s+merge:' config/crd/bases/kdex.dev_kdexhosts.yaml config/crd/bases/kdex.dev_kdexfunctions.yaml`
Expected: a `merge:` property with `enum: [Accumulate, Replace]` and the description, in both files (host under `spec.auth.claimMappings.items`, function under `spec.claimMappings.items`).

- [ ] **Step 5: Run envtest + lint** — `make test lint docs`. Expected: PASS. (envtest installs the CRDs into a real apiserver, which is what catches schema/CEL-cost problems.)
- [ ] **Step 6: Commit (do NOT tag — Task 5's script tags)**

```bash
git add -A
git commit -m "feat: claimMappings merge (Accumulate|Replace) via dmapper v0.2.0 (host-manager#229)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Tag crds and propagate to nexus + host-manager

**Files:** `kdex-nexus-manager/go.mod`/`go.sum`, `kdex-host-manager/go.mod`/`go.sum` (script-edited).

- [ ] **Step 1: Run from the workspace root** — `./updateCrdUsage.sh -t -n`. It runs `make test lint docs` in kdex-crds, pushes kdex-crds main and the new patch tag (expected `v0.14.249`), and rewrites both actors' `replace kdex.dev/crds` lines without committing (`-n`).
- [ ] **Step 2: Verify** — `git -C kdex-crds describe --tags --abbrev=0` → `v0.14.249`; `rg -n 'kdex-crds v0.14.249' kdex-nexus-manager/go.mod kdex-host-manager/go.mod` → one hit each. If kdex-crds main was pre-committed and the script reports nothing to commit, confirm `git -C kdex-crds status -sb` shows no `ahead`; push by hand if it does.

---

### Task 6: host-manager regression tests + dmapper bump

**Files:**
- Create: `kdex-host-manager/internal/sign/sign_accumulate_test.go`
- Modify: `kdex-host-manager/go.mod`, `go.sum` (dmapper v0.2.0; crds pin already set by Task 5)

**Interfaces:**
- Consumes: `testSignerWithMapper(t, rules)` (`internal/sign/sign_test.go:39`), `auth.EnrichAuthContext(ac auth.AuthContext, mapper *dmapper.Mapper)` (`internal/auth/config.go:142`), `dmapper.MergeReplace` (Task 1).

- [ ] **Step 1: Write the failing tests (no `Merge` field yet — still on dmapper v0.1.2)** — create `sign_accumulate_test.go`:

```go
package sign_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asStrings flattens a []string / []any claim for comparison.
func asStrings(t *testing.T, v any) []string {
	t.Helper()
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, len(l))
		for i, e := range l {
			s, ok := e.(string)
			require.Truef(t, ok, "non-string element %T", e)
			out[i] = s
		}
		return out
	}
	t.Fatalf("unexpected claim type %T", v)
	return nil
}

// TestSigner_Project_ClaimMappingsAccumulate pins kdex-tech/host-manager#229
// through the real signer: a claimMappings rule that does not restate
// self.entitlements must not strip the static grants from the token. The
// source claim (extra_grants) is an arbitrary example — no claim is special-cased.
func TestSigner_Project_ClaimMappingsAccumulate(t *testing.T) {
	ctx := jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []any{"pages:home:read"},
		"extra_grants": []any{"functions:/api/x:read"},
	}
	tests := []struct {
		name  string
		rules []dmapper.MappingRule
	}{
		{"A: rule omits self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"B: rule restates self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements + self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"C: identity rule then omitting rule", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements", TargetPropPath: "entitlements"},
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := testSignerWithMapper(t, tt.rules).Project(ctx)
			require.NoError(t, err)
			assert.Equal(t, []string{"pages:home:read", "functions:/api/x:read"}, asStrings(t, p["entitlements"]))
		})
	}
}

// TestSigner_EnrichThenProjectNoGrowth pins that the production double run —
// EnrichAuthContext over the auth context, then Project over the enriched
// context with the SAME mapper — neither duplicates nor grows a list claim.
// roles is used because entitlements.Compact would mask duplicates in
// entitlements.
func TestSigner_EnrichThenProjectNoGrowth(t *testing.T) {
	rules := []dmapper.MappingRule{{SourceExpression: "self.extra_roles", TargetPropPath: "roles"}}
	m, err := dmapper.NewMapper(rules)
	require.NoError(t, err)

	ac := auth.AuthContext{"sub": "alice", "roles": []any{"admin"}, "extra_roles": []any{"auditor"}}
	auth.EnrichAuthContext(ac, m)
	assert.Equal(t, []string{"admin", "auditor"}, asStrings(t, ac["roles"]))

	p, err := testSignerWithMapper(t, rules).Project(jwt.MapClaims(ac))
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "auditor"}, asStrings(t, p["roles"]))
}
```

- [ ] **Step 2: Run to verify they fail on v0.1.2**

Run: `cd kdex-host-manager && go test ./internal/sign/ -run 'ClaimMappingsAccumulate|EnrichThenProjectNoGrowth' -v`
Expected: FAIL — rows A and C get `[functions:/api/x:read]`; `EnrichThenProjectNoGrowth` gets `[auditor]`. Row B passes.

- [ ] **Step 3: Bump dmapper** — `go get github.com/kdex-tech/dmapper@v0.2.0 && go mod tidy`
- [ ] **Step 4: Re-run** — same command. Expected: PASS with no production code change. If it does not pass, stop and read `sign.Project` / `EnrichAuthContext` — do not special-case a claim.
- [ ] **Step 5: Add the Replace case** — append to `sign_accumulate_test.go`:

```go
// TestSigner_Project_ClaimMappingsReplaceNarrows pins the opt-out through the
// signer: merge: Replace lets a filtering rule narrow a list claim.
func TestSigner_Project_ClaimMappingsReplaceNarrows(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{{
		SourceExpression: "self.roles.filter(r, r != 'guest')",
		TargetPropPath:   "roles",
		Merge:            dmapper.MergeReplace,
	}})
	p, err := s.Project(jwt.MapClaims{"sub": "alice", "roles": []any{"admin", "guest"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, asStrings(t, p["roles"]))
}
```

Run: `go test ./internal/sign/ -run ClaimMappingsReplaceNarrows -v` → PASS.

- [ ] **Step 6: Full suite + lint** — `make test && make lint`. Expected: PASS. If any existing test fails, it relied on list-onto-list replacement: report it with the test name before changing it.
- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/sign/sign_accumulate_test.go
git commit -m "fix(auth): claimMappings list targets accumulate instead of replacing (#229)

Picks up dmapper v0.2.0 and kdex-crds v0.14.249 (claimMappings merge:
Accumulate|Replace). A rule that does not restate self.entitlements no
longer strips the static grants from every token the host signs; merge:
Replace keeps the old behaviour for filtering rules.

Fixes #229

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: nexus-manager picks up the crds pin

**Files:** `kdex-nexus-manager/go.mod`, `go.sum` (already edited by Task 5).

- [ ] **Step 1:** `cd kdex-nexus-manager && go mod tidy && rg -n 'dmapper' go.mod` → `v0.2.0 // indirect`.
- [ ] **Step 2:** `make test && make lint` → PASS.
- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: kdex-crds v0.14.249 (claimMappings merge field, host-manager#229)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Release host-manager v0.20.0 and nexus v0.5.20

- [ ] **Step 1: Push both mains** — in each repo: `git fetch origin && git rebase origin/main && git log --merges origin/main..HEAD` (must print nothing) `&& git push origin main`. host-manager's push also carries the spec + plan docs commits.
- [ ] **Step 2: Wait for main CI green** in both (`gh run watch <id> --exit-status`).
- [ ] **Step 3: Tag** — host-manager `v0.20.0`, nexus `v0.5.20` (`git tag -a <v> -m <v> && git push origin <v>`).
- [ ] **Step 4: Verify artifacts** — tag CI green in both; charts and multi-arch images exist: `oras manifest fetch ghcr.io/kdex-tech/charts/host-manager:0.20.0`, `docker manifest inspect ghcr.io/kdex-tech/host-manager:0.20.0` (expect amd64 + arm64); same for `kcnas-operator` 0.5.20. Negative control: the next version (0.20.1 / 0.5.21) must be absent.
- [ ] **Step 5:** `gh issue view 229` shows CLOSED (closed by the `Fixes #229` commit); if not, `gh issue close 229 -c "Fixed in v0.20.0 (dmapper v0.2.0, kdex-crds v0.14.249)."`.

---

### Task 9: Fleet repin (infra) — lockstep

**Files (`/home/rotty/projects/RSI/infra`, same set as commit `8320cd1`):** `Makefile` (CRD version), `kcnas/crds/*` (re-vendored install.yaml), `terraform/kcnas.tf` (CRD comment + nexus `version`), `terraform/variables.tf` (`host_manager_version`), `fleet/platform/components/kcnas-operator.yaml` (nexus `targetRevision` + host-manager `version`), `tests/users_db_test.go`, `tests/kdexhost_relocation_test.go`.

- [ ] **Step 1:** `git show 8320cd1` to see exactly how each file was edited; mirror it for crds v0.14.249 / nexus 0.5.20 / host-manager 0.20.0. Prune history comments to the last three entries, as `df15106` did. The new comment line names #229 and that token contents change only for hosts with a rule that omits `self.<target>` (none in this fleet).
- [ ] **Step 2:** Re-vendor the CRDs via the Makefile target `8320cd1` changed; `git diff --stat kcnas/crds` must show the `merge` property added to the KDexHost and KDexFunction CRDs and nothing unexpected.
- [ ] **Step 3:** `go vet ./tests/... && tofu fmt -check -recursive terraform` and `go test ./tests/ -run 'ClaimMappings|UsersDB|Relocation'` where they run locally.
- [ ] **Step 4: Commit + push** (`--ff-only` discipline), then tell the user the pipeline number: deploy and stage2-deploy are MANUAL clicks.
- [ ] **Step 5 (after the user deploys):** `kubectl get deploy -A -o jsonpath=…` shows `host-manager:0.20.0` in dev and prod; on dev, a token for a user with the knowdrive-site default rule still carries both static and `vs_entitlements` grants (unchanged output).

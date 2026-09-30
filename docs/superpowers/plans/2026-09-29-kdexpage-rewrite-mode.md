# KDexPage Rewrite Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third `KDexPage` operating mode, `spec.rewrite`, that serves another KDexPage's or KDexFunction's response from the same host without a 3xx.

**Architecture:**
- **kdex-crds:** gains a `RewriteSpec` field and CEL rules that make the mode exclusive.
- **host-manager's page controller:** validates the target statically (existence, one hop only, not internal, placeholders).
- **host-manager's route rebuild:** resolves each rewrite page's target.
- **Request time:** a small `rewriteHandler` runs the alias page's own gate under `hh.mu.RLock`. It **releases the lock**, then re-dispatches a cloned request into the same mux snapshot, so the target's own gate and handler run as usual.

**Tech Stack:** Go 1.26.0, controller-runtime / kubebuilder (envtest, Ginkgo/Gomega), `net/http.ServeMux` patterns, kin-openapi, testify.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-09-29-kdexpage-rewrite-mode-design.md` (host-manager#217, folds in #201). Read it before starting.

> **Superseded by #220 (exact page paths).** The Task 4 and Task 7 snippets below predate #220 and show the old slash forms: an HTML target's `exact` as `basePath + "/"`, `GET /docs/v3/{$}`, and alias requests like `/bots/`. After #220, pages register at their exact `basePath`, `exact` is the `basePath` for every target, and a rewrite follows every redirect route its target path lands on (any page's legacy slash 301, the default-language 301, ServeMux's trailing-slash redirect) internally, bounded at 3 hops, rather than sending it to the client. The spec §3 is authoritative.

## Global Constraints

- Go is pinned at **1.26.0** across kdex-crds / host-manager / nexus-manager.
- **Never edit a `replace kdex.dev/crds => …` directive by hand.** Local pre-release testing uses a *scratch* `GOWORK` file outside every repo (Task 2). CRD propagation uses `./updateCrdUsage.sh`.
- Commit **inside the sub-repo** that owns the change. Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- host-manager work happens on branch **`feat/217-rewrite-mode`**. Integrating it into `main` is a rebase plus `git merge --ff-only`, never a merge commit.
- **Do not push anything** except through the explicit user checkpoints in Tasks 3 and 10.
- Search with `rg`, not `grep`. YAML uses 2-space indent, one resource per file.
- Kind strings are exact: `KDexPage`, `KDexFunction`. `targetRef.kind` is **required, never defaulted**.
- `targetRef.namespace` is ignored. Targets resolve in the page's own namespace.
- Only `GET` routes are registered for rewrite pages.
- The rewrite handler **must not hold `hh.mu` while dispatching.**
- Condition reasons are controller-local constants (same pattern as `routeCollisionConditionReason`): `RewriteTargetIsRewrite`, `RewriteTargetInternal`, `RewriteUnknownPlaceholder`.
- A CRD serialization or validation change means **releasing both host-manager and nexus-manager** and running each one's `make test`, not just `go build`.

## Review Focus

These five inputs aren't covered by any spec example but are the likeliest to bite a real user. Each has a test in the task that owns the code.

1. **Percent-encoded traversal in a path parameter** (`/u/a%2F..%2F..%2Fsecret`): it must never reach the target. `ServeMux` cleans the decoded path and redirects before any handler runs. The handler's own guard must still answer **400** for an unsafe value that reaches it. Tests are in Task 4 (`Target`) and Task 7 (end to end, plus a direct handler call).
2. **The target changes after the alias reconciled.** If the target page is deleted, or switches to rewrite mode, before the alias re-reconciles, the next route rebuild must serve **404**, not loop, 500 or 508. Test is in Task 7 (`resolveRewriteTarget` returns not-found for a rewrite-mode page).
3. **Alias is public, target is gated.** The target's own gate must still deny: a non-HTML anonymous caller gets **401** from the target. Test is in Task 7.
4. **A query string with encoded characters** (`?q=a%26b&x=1`) must reach the target byte-for-byte (`RawQuery` preserved). Test is in Task 7.
5. **A reconcile's `SetHost` running concurrently** with rewrite requests must not deadlock. Test is in Task 7, a bounded-deadline race test.

---

### Task 0: Branch and scratch workspace setup

**Files:** none in any repo. Creates a scratch `go.work` outside the repos.

- [ ] **Step 1: Create the host-manager feature branch**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git status -s            # expect clean
git switch -c feat/217-rewrite-mode
```

- [ ] **Step 2: Confirm kdex-crds and nexus-manager are clean on `main`**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-crds && git status -s && git branch --show-current
cd /home/rotty/projects/kdex/workspace/kdex-nexus-manager && git status -s && git branch --show-current
```
Expected: no output from `status -s`, and branch `main` for both.

- [ ] **Step 3: Write the scratch GOWORK file** (used only in Task 2, never committed)

Create `$SCRATCH/go.work`, where `$SCRATCH` is the session scratchpad directory:

```
go 1.26.0

use /home/rotty/projects/kdex/workspace/kdex-host-manager

replace kdex.dev/crds => /home/rotty/projects/kdex/workspace/kdex-crds
```

Verify:

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
GOWORK=$SCRATCH/go.work go list -m -f '{{.Dir}}' kdex.dev/crds
```
Expected: `/home/rotty/projects/kdex/workspace/kdex-crds`.

---

### Task 1: kdex-crds — `RewriteSpec`, mode CEL, #201 fixes

**Files:**
- Modify: `kdex-crds/api/v1alpha1/kdexpage_types.go` (spec-level XValidation markers, new field)
- Modify: `kdex-crds/api/v1alpha1/types.go`: add `RewriteSpec` after `Paths`, and fix the `BasePath` / `PatternPath` doc comments (currently lines ~1242–1249)
- Test: `kdex-crds/api/v1alpha1/kdexpage_types_test.go`
- Generated (by `make manifests generate docs`): `config/crd/bases/kdex.dev_kdexpages.yaml`, `api/v1alpha1/zz_generated.deepcopy.go`, `CRD_REFERENCE.md`

**Interfaces:**
- Produces: `kdexv1alpha1.RewriteSpec{TargetRef KDexObjectReference; Path string; Canonical bool}` and `KDexPageSpec.Rewrite *RewriteSpec`. Tasks 2, 4, 5, 7 and 8 use these exact names.

- [ ] **Step 1: Write the failing schema and decode tests**

Append to `kdexpage_types_test.go`:

```go
// TestKDexPageSpec_RewriteDecodes pins the rewrite-mode field shape (#217).
func TestKDexPageSpec_RewriteDecodes(t *testing.T) {
	specYaml := `
hostRef: { name: test-host }
label: docs latest
basePath: /docs/latest
patternPath: /docs/latest/{rest...}
rewrite:
  targetRef: { kind: KDexPage, name: docs-v3 }
  path: "{rest}"
  canonical: true
`
	var spec KDexPageSpec
	require.NoError(t, yaml.Unmarshal([]byte(specYaml), &spec))
	require.NotNil(t, spec.Rewrite)
	assert.Equal(t, "KDexPage", spec.Rewrite.TargetRef.Kind)
	assert.Equal(t, "docs-v3", spec.Rewrite.TargetRef.Name)
	assert.Equal(t, "{rest}", spec.Rewrite.Path)
	assert.True(t, spec.Rewrite.Canonical)
	assert.Empty(t, spec.ContentEntries)

	raw, err := json.Marshal(KDexPageSpec{})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "rewrite", "an unset rewrite must not serialize")
}

// TestKDexPageGeneratedSchema_RewriteMode pins the rewrite property and the
// mode-exclusion CEL in the generated CRD (#217, #201).
func TestKDexPageGeneratedSchema_RewriteMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd", "bases", "kdex.dev_kdexpages.yaml"))
	require.NoError(t, err)

	var crd struct {
		Spec struct {
			Versions []struct {
				Schema struct {
					OpenAPIV3Schema struct {
						Properties struct {
							Spec struct {
								Properties struct {
									Rewrite struct {
										Required   []string `json:"required"`
										Properties struct {
											Path struct {
												MaxLength int    `json:"maxLength"`
												Pattern   string `json:"pattern"`
											} `json:"path"`
											Canonical struct {
												Type string `json:"type"`
											} `json:"canonical"`
										} `json:"properties"`
									} `json:"rewrite"`
								} `json:"properties"`
								XKubernetesValidations []struct {
									Rule string `json:"rule"`
								} `json:"x-kubernetes-validations"`
							} `json:"spec"`
						} `json:"properties"`
					} `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &crd))
	spec := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties.Spec

	assert.Contains(t, spec.Properties.Rewrite.Required, "targetRef")
	assert.Equal(t, 512, spec.Properties.Rewrite.Properties.Path.MaxLength)
	assert.Equal(t, `^[^:?#]*$`, spec.Properties.Rewrite.Properties.Path.Pattern)
	assert.Equal(t, "boolean", spec.Properties.Rewrite.Properties.Canonical.Type)

	rules := make([]string, 0, len(spec.XKubernetesValidations))
	for _, r := range spec.XKubernetesValidations {
		rules = append(rules, r.Rule)
	}
	assert.Contains(t, rules, `has(self.mimeType) || has(self.rewrite) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))`)
	assert.Contains(t, rules, `!(has(self.rewrite) && has(self.mimeType))`)
	assert.Contains(t, rules, `!has(self.rewrite) || !(has(self.contentEntries) || has(self.pageArchetypeRef) || has(self.overrideHeaderRef) || has(self.overrideFooterRef) || has(self.overrideNavigationRefs) || has(self.scriptLibraryRef))`)
	assert.Contains(t, rules, `!(has(self.mimeType) && has(self.patternPath))`)
}
```

Also update the existing assertion in `TestKDexPageGeneratedSchema` (the old main-slot rule text changes):

```go
	assert.Contains(t, rules, `has(self.mimeType) || has(self.rewrite) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))`,
		"main-slot-unless-text-or-rewrite-page CEL must be present")
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run 'TestKDexPageSpec_RewriteDecodes|TestKDexPageGeneratedSchema' -v`
Expected: a compile FAIL, `spec.Rewrite undefined`.

- [ ] **Step 3: Add the type and markers**

In `types.go`, directly after the `Paths` struct:

```go
// RewriteSpec makes a KDexPage an internal alias of another KDexPage or
// KDexFunction on the same host: the page's routes serve the target's response
// without a redirect. See kdex-tech/host-manager#217.
type RewriteSpec struct {
	// targetRef names the KDexPage or KDexFunction whose response this page serves. It is resolved in the page's own namespace; namespace is ignored.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:XValidation:rule="self.name.size() > 0",message="rewrite.targetRef.name must not be empty"
	// +kubebuilder:validation:XValidation:rule=`self.kind == "KDexPage" || self.kind == "KDexFunction"`,message="'kind' must be either KDexPage or KDexFunction"
	TargetRef KDexObjectReference `json:"targetRef" protobuf:"bytes,1,req,name=targetRef"`

	// path is joined to the target's basePath with exactly one '/'. {name} placeholders are substituted from this page's patternPath wildcards. Empty means the target's own registered route.
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^[^:?#]*$`
	// +kubebuilder:validation:XValidation:rule="!self.contains('//') && !self.matches('(^|/)[.][.]?(/|$)')",message="rewrite.path must not contain '//', '.' or '..' segments"
	// +kubebuilder:validation:Optional
	Path string `json:"path,omitempty" protobuf:"bytes,2,opt,name=path"`

	// canonical, when true, adds `Link: <target URL>; rel="canonical"` so the alias does not compete with the target in search indexes.
	// +kubebuilder:validation:Optional
	Canonical bool `json:"canonical,omitempty" protobuf:"varint,3,opt,name=canonical"`
}
```

Fix the two stale doc comments in `Paths` (#201). Replace them with:

```go
	// basePath is the shortest path by which the page may be accessed. It must not contain path parameters. This path will be used in site navigation. For a localized page (the default) it is also registered under a literal "/<lang>" prefix for every non-default language.
```
```go
	// patternPath, which must be prefixed by BasePath, is an extension of basePath that adds pattern matching as defined by https://pkg.go.dev/net/http#hdr-Patterns-ServeMux. For a localized page it is also registered under a literal "/<lang>" prefix for every non-default language. Not allowed on a text page (mimeType set).
```

In `kdexpage_types.go`, replace the second existing spec-level marker and add three more. The resulting marker block above `type KDexPageSpec struct` is:

```go
// +kubebuilder:validation:XValidation:rule="has(self.mimeType) == has(self.body)",message="mimeType and body must be set together"
// +kubebuilder:validation:XValidation:rule="has(self.mimeType) || has(self.rewrite) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))",message="an HTML page (no mimeType, no rewrite) must declare contentEntries with a 'main' slot"
// +kubebuilder:validation:XValidation:rule="!(has(self.rewrite) && has(self.mimeType))",message="rewrite and mimeType are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!has(self.rewrite) || !(has(self.contentEntries) || has(self.pageArchetypeRef) || has(self.overrideHeaderRef) || has(self.overrideFooterRef) || has(self.overrideNavigationRefs) || has(self.scriptLibraryRef))",message="a rewrite page must not set contentEntries, pageArchetypeRef, override*Refs or scriptLibraryRef"
// +kubebuilder:validation:XValidation:rule="!(has(self.mimeType) && has(self.patternPath))",message="a text page (mimeType set) must not set patternPath"
```

Add the field at the end of `KDexPageSpec`, after `Body`:

```go
	// rewrite, when set, makes this page an internal alias of another KDexPage or KDexFunction on the same host. Mutually exclusive with contentEntries and mimeType/body.
	// +kubebuilder:validation:Optional
	Rewrite *RewriteSpec `json:"rewrite,omitempty" protobuf:"bytes,17,opt,name=rewrite"`
```

- [ ] **Step 4: Regenerate and run the full module tests**

Run: `cd kdex-crds && make manifests generate && make test`
Expected: PASS, including both new tests. `git status` shows the regenerated CRD YAML and deepcopy.

- [ ] **Step 5: Lint and docs**

Run: `cd kdex-crds && make lint docs`
Expected: clean lint. `CRD_REFERENCE.md` gains `RewriteSpec`.

- [ ] **Step 6: Commit (kdex-crds `main`, do not push)**

```bash
cd kdex-crds
git add api/v1alpha1/types.go api/v1alpha1/kdexpage_types.go api/v1alpha1/kdexpage_types_test.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases/kdex.dev_kdexpages.yaml CRD_REFERENCE.md
git commit -m "feat: KDexPage rewrite mode (spec.rewrite) + mode-exclusion CEL

Adds RewriteSpec (targetRef KDexPage|KDexFunction, bounded path template,
canonical) for kdex-tech/host-manager#217, and folds in #201: a text page
may not set patternPath, and the BasePath/PatternPath doc comments no
longer describe the retired /{l10n} wildcard.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: host-manager — envtest proof of the CEL, pre-release

Decode tests can't catch CEL that fails the apiserver cost budget, which makes the whole CRD fail to install. This task installs the **local** kdex-crds into host-manager's envtest through the scratch GOWORK, before anything is tagged.

**Files:**
- Test: `kdex-host-manager/internal/controller/kdexpage_rewrite_cel_test.go` (new)

**Interfaces:**
- Consumes: `kdexv1alpha1.RewriteSpec`, `KDexPageSpec.Rewrite` (Task 1).

- [ ] **Step 1: Write the admission tests**

```go
package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage rewrite-mode admission (CEL)", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	rewritePage := func(name string, mutate func(*kdexv1alpha1.KDexPageSpec)) *kdexv1alpha1.KDexPage {
		p := &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				HostRef: corev1.LocalObjectReference{Name: "some-host"},
				Label:   "alias",
				Paths:   kdexv1alpha1.Paths{BasePath: "/alias"},
				Rewrite: &kdexv1alpha1.RewriteSpec{
					TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "target"},
				},
			},
		}
		if mutate != nil {
			mutate(&p.Spec)
		}
		return p
	}

	It("accepts a minimal rewrite page with no contentEntries", func() {
		Expect(k8sClient.Create(ctx, rewritePage("ok-min", nil))).To(Succeed())
	})

	It("accepts a KDexFunction target with a placeholder path", func() {
		Expect(k8sClient.Create(ctx, rewritePage("ok-fn", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PatternPath = "/alias/{id}"
			s.Rewrite.TargetRef.Kind = "KDexFunction"
			s.Rewrite.Path = "{id}"
		}))).To(Succeed())
	})

	It("rejects rewrite together with contentEntries", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-content", func(s *kdexv1alpha1.KDexPageSpec) {
			s.ContentEntries = []kdexv1alpha1.ContentEntry{{
				ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<p>x</p>"},
				Slot:               "main",
			}}
		}))).NotTo(Succeed())
	})

	It("rejects rewrite together with mimeType/body", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-text", func(s *kdexv1alpha1.KDexPageSpec) {
			s.MimeType = "txt"
			s.Body = "x"
		}))).NotTo(Succeed())
	})

	It("rejects rewrite together with pageArchetypeRef", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-arch", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PageArchetypeRef = &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "a"}
		}))).NotTo(Succeed())
	})

	It("rejects a targetRef kind other than KDexPage/KDexFunction", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-kind", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite.TargetRef.Kind = "KDexApp"
		}))).NotTo(Succeed())
	})

	DescribeTable("rejects unsafe rewrite.path values",
		func(p string) {
			Expect(k8sClient.Create(ctx, rewritePage("bad-path", func(s *kdexv1alpha1.KDexPageSpec) {
				s.Rewrite.Path = p
			}))).NotTo(Succeed())
		},
		Entry("double slash", "a//b"),
		Entry("dot-dot segment", "a/../b"),
		Entry("leading dot-dot", "../b"),
		Entry("dot segment", "./b"),
		Entry("scheme", "https:x"),
		Entry("query", "a?b"),
		Entry("fragment", "a#b"),
	)

	It("rejects a text page that sets patternPath (#201)", func() {
		p := rewritePage("bad-text-pattern", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite = nil
			s.MimeType = "txt"
			s.Body = "x"
			s.PatternPath = "/alias/{x}"
		})
		Expect(k8sClient.Create(ctx, p)).NotTo(Succeed())
	})

	It("still rejects an HTML page without a main slot", func() {
		p := rewritePage("bad-html", func(s *kdexv1alpha1.KDexPageSpec) { s.Rewrite = nil })
		Expect(k8sClient.Create(ctx, p)).NotTo(Succeed())
	})
})
```

- [ ] **Step 2: Run against the local kdex-crds through the scratch GOWORK**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
make setup-envtest
KUBEBUILDER_ASSETS="$(bin/setup-envtest use $(go list -m -f '{{ .Version }}' k8s.io/api | awk -F'[v.]' '{printf "1.%d", $3}') --bin-dir bin -p path)" \
  GOWORK=$SCRATCH/go.work go test ./internal/controller/ -ginkgo.focus "rewrite-mode admission" -v
```
Expected: PASS, and the suite's `BeforeSuite` CRD install succeeds (this is the cost-budget check). If the install fails with a CEL cost error, add bounds in Task 1 and amend that commit.

- [ ] **Step 3: Confirm the tests fail without the local crds**

Run the same command **without** `GOWORK=…`.
Expected: compile FAIL (`Rewrite` undefined against the pinned v0.14.246). This proves the tests are wired to the new schema.

- [ ] **Step 4: Commit (feature branch)**

```bash
git add internal/controller/kdexpage_rewrite_cel_test.go
git commit -m "test: envtest admission coverage for KDexPage rewrite mode (#217)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: CHECKPOINT — release kdex-crds and repin both actors

> **STOP: get the user's explicit go-ahead before Step 1.** It pushes kdex-crds `main` and a new tag to GitHub.

**Files:** `kdex-host-manager/go.mod`, `go.sum`; `kdex-nexus-manager/go.mod`, `go.sum`.

- [ ] **Step 1: Tag and propagate without auto-committing the actors**

```bash
cd /home/rotty/projects/kdex/workspace
./updateCrdUsage.sh -t -n
```
Expected:
- kdex-crds `make test lint docs` passes.
- kdex-crds `main` and tag `v0.14.247` are pushed.
- host-manager and nexus-manager have uncommitted `go.mod`/`go.sum` changes pinning `v0.14.247`.

- [ ] **Step 2: Commit the host-manager pin on the feature branch and run the envtest without GOWORK**

```bash
cd kdex-host-manager
git add go.mod go.sum
git commit -m "chore: bump kdex-crds to v0.14.247 (KDexPage rewrite mode)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
make test
```
Expected: PASS, including the Task 2 admission specs, now running against the released tag.

- [ ] **Step 3: Commit the nexus-manager pin on `main` (no push) and run its tests**

```bash
cd ../kdex-nexus-manager
git add go.mod go.sum
git commit -m "chore: bump kdex-crds to v0.14.247 (KDexPage rewrite mode)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
make test
```
Expected: PASS. If a test pins the old "an HTML page (no mimeType) must declare…" message, update it to the new message text from Task 1 and fold that change into this commit.

---

### Task 4: `internal/rewrite` — pure path helpers

**Files:**
- Create: `kdex-host-manager/internal/rewrite/rewrite.go`
- Test: `kdex-host-manager/internal/rewrite/rewrite_test.go`

**Interfaces:**
- Produces:
  - `rewrite.Placeholders(tmpl string) []string`
  - `rewrite.UnknownPlaceholders(tmpl, patternPath string) []string`
  - `rewrite.Target(basePath, exact, tmpl string, value func(string) string) (string, error)`
  - `rewrite.ErrUnsafe`
- Task 5 uses `UnknownPlaceholders`; Task 7 uses `Target` and `ErrUnsafe`.

- [ ] **Step 1: Write the failing tests**

```go
package rewrite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlaceholders(t *testing.T) {
	assert.Equal(t, []string{"user", "rest"}, Placeholders("u/{user}/x/{rest}"))
	assert.Empty(t, Placeholders("static/path"))
	assert.Empty(t, Placeholders(""))
}

func TestUnknownPlaceholders(t *testing.T) {
	assert.Empty(t, UnknownPlaceholders("{rest}", "/docs/latest/{rest...}"))
	assert.Empty(t, UnknownPlaceholders("{a}/{b}", "/x/{a}/{b}/{$}"))
	assert.Equal(t, []string{"id"}, UnknownPlaceholders("{id}", "/alias/{user}"))
	assert.Equal(t, []string{"id"}, UnknownPlaceholders("{id}", ""))
	assert.Empty(t, UnknownPlaceholders("", ""))
}

func vals(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestTarget(t *testing.T) {
	cases := []struct {
		name, base, exact, tmpl string
		v                       map[string]string
		want                    string
	}{
		{"empty path uses exact form", "/docs/v3", "/docs/v3/", "", nil, "/docs/v3/"},
		{"one slash at the seam", "/docs/v3", "/docs/v3/", "{rest}", map[string]string{"rest": "a/b"}, "/docs/v3/a/b"},
		{"base trailing slash collapsed", "/docs/v3/", "/docs/v3/", "/{rest}", map[string]string{"rest": "a"}, "/docs/v3/a"},
		{"author trailing slash kept", "/profile", "/profile/", "{user}/", map[string]string{"user": "bob"}, "/profile/bob/"},
		{"empty rest value", "/docs/v3", "/docs/v3/", "{rest}", map[string]string{"rest": ""}, "/docs/v3/"},
		{"function target", "/api/downloads", "/api/downloads", "{id}", map[string]string{"id": "42"}, "/api/downloads/42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Target(c.base, c.exact, c.tmpl, vals(c.v))
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestTarget_RefusesUnsafeSubstitutions(t *testing.T) {
	for name, v := range map[string]string{
		"dot-dot":          "..",
		"embedded dot-dot": "a/../../etc",
		"dot":              ".",
		"double slash":     "a//b",
		"leading slash":    "/abs", // would create "//" at the seam
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Target("/docs/v3", "/docs/v3/", "{rest}", vals(map[string]string{"rest": v}))
			assert.ErrorIs(t, err, ErrUnsafe)
		})
	}
	_, err := Target("/profile", "/profile/", "a/{x}/b", vals(map[string]string{"x": ""}))
	assert.ErrorIs(t, err, ErrUnsafe, "an empty mid-path value produces '//'")
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/rewrite/ -v`
Expected: compile FAIL (package has no non-test files).

- [ ] **Step 3: Implement**

```go
// Package rewrite holds the pure path logic behind KDexPage rewrite mode
// (kdex-tech/host-manager#217), shared by the page controller's static
// placeholder check and the host's request-time dispatch.
package rewrite

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// ErrUnsafe reports a dispatch path that would contain '//' or a '.'/'..'
// segment after substitution. The CRD's CEL constrains the author's template;
// this guards the request-supplied values substituted into it.
var ErrUnsafe = errors.New("rewrite: substituted path is unsafe")

var (
	placeholderRE = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// wildcardRE matches net/http ServeMux wildcards: {name} and {name...}.
	// {$} has no name and is deliberately not matched.
	wildcardRE = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(?:\.\.\.)?\}`)
)

// Placeholders returns the {name} placeholders in a rewrite path template, in order.
func Placeholders(tmpl string) []string {
	var names []string
	for _, m := range placeholderRE.FindAllStringSubmatch(tmpl, -1) {
		names = append(names, m[1])
	}
	return names
}

// UnknownPlaceholders returns the placeholders in tmpl that are not wildcard
// names in patternPath -- they could never be substituted at request time.
func UnknownPlaceholders(tmpl, patternPath string) []string {
	var known []string
	for _, m := range wildcardRE.FindAllStringSubmatch(patternPath, -1) {
		known = append(known, m[1])
	}
	var unknown []string
	for _, name := range Placeholders(tmpl) {
		if !slices.Contains(known, name) {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// Target builds the path a rewrite dispatches to. An empty tmpl returns exact,
// the target's registered form, so the mux never answers with a slash redirect
// that would expose the target URL. Otherwise each {name} is replaced by
// value(name) and the result is joined to basePath with exactly one '/'.
func Target(basePath, exact, tmpl string, value func(string) string) (string, error) {
	if tmpl == "" {
		return exact, nil
	}
	// Strip only the AUTHOR's leading '/', before substitution: a leading '/'
	// produced by a substituted value must survive so safe() sees the '//'.
	suffix := placeholderRE.ReplaceAllStringFunc(strings.TrimPrefix(tmpl, "/"), func(m string) string {
		return value(m[1 : len(m)-1])
	})
	p := strings.TrimSuffix(basePath, "/") + "/" + suffix
	if !safe(p) {
		return "", ErrUnsafe
	}
	return p, nil
}

func safe(p string) bool {
	if strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/rewrite/ -v`
Expected: PASS. The "leading slash" case returns `ErrUnsafe`: `{rest}` with `rest="/abs"` joins to `/docs/v3//abs`, which `safe` rejects.

- [ ] **Step 5: Commit**

```bash
git add internal/rewrite/
git commit -m "feat(rewrite): pure placeholder/target-path helpers for KDexPage rewrite mode (#217)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Page controller — static target validation and watches

**Files:**
- Create: `kdex-host-manager/internal/controller/kdexpage_rewrite.go`
- Modify: `kdex-host-manager/internal/controller/kdexpage_controller.go`: branch into `reconcileRewrite` right after the "Reconciling" `SetConditions` block (currently line ~150), and add two `Watches` in `SetupWithManager`
- Test: `kdex-host-manager/internal/controller/kdexpage_rewrite_test.go` (new)

**Interfaces:**
- Consumes: `rewrite.UnknownPlaceholders` (Task 4); `ResolveKDexObjectReference`, `ResolvePage` (existing, `resolver_common.go`).
- Produces: a Ready rewrite page stored as `pages.PageHandler{Name, Page: &page.Spec, Status: &page.Status}` with **no** archetype, content or navigation fields. Task 7 relies on `ph.Page.Rewrite != nil` to pick the rewrite handler.

- [ ] **Step 1: Write the failing envtest specs**

```go
package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage rewrite-mode reconcile", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	htmlPage := func(name, basePath string) *kdexv1alpha1.KDexPage {
		return &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				ContentEntries: []kdexv1alpha1.ContentEntry{{
					ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<h1>t</h1>"},
					Slot:               "main",
				}},
				HostRef:          corev1.LocalObjectReference{Name: focalHost},
				Label:            name,
				PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "rw-archetype"},
				Paths:            kdexv1alpha1.Paths{BasePath: basePath},
			},
		}
	}
	aliasPage := func(name string, ref kdexv1alpha1.KDexObjectReference, pattern, path string) *kdexv1alpha1.KDexPage {
		return &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				HostRef: corev1.LocalObjectReference{Name: focalHost},
				Label:   name,
				Paths:   kdexv1alpha1.Paths{BasePath: "/" + name, PatternPath: pattern},
				Rewrite: &kdexv1alpha1.RewriteSpec{TargetRef: ref, Path: path},
			},
		}
	}
	degradedReason := func(name string) func() string {
		return func() string {
			var p kdexv1alpha1.KDexPage
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &p); err != nil {
				return ""
			}
			c := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
			if c == nil || c.Status != metav1.ConditionTrue {
				return ""
			}
			return c.Reason
		}
	}
	// seedArchetype seeds what an HTML target page needs to reach Ready: its
	// archetype and the focal internal host (same fixture shape as the
	// existing "with parent page reference" spec).
	seedArchetype := func() {
		addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
			ObjectMeta: metav1.ObjectMeta{Name: "rw-archetype", Namespace: namespace},
			Spec:       kdexv1alpha1.KDexPageArchetypeSpec{Content: "<h1>x</h1>"},
		})
		addOrUpdateInternalHost(ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: focalHost, Namespace: namespace},
			Spec: kdexv1alpha1.KDexInternalHostSpec{
				KDexHostSpec: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DevMode:      true,
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing:      kdexv1alpha1.Routing{Domains: []string{"example.com"}},
				},
			},
		})
	}

	It("becomes Ready once its KDexPage target is Ready, and waits while it is missing", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, aliasPage("latest",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "docs-v3"}, "", ""))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "latest", namespace, &kdexv1alpha1.KDexPage{}, false)

		Expect(k8sClient.Create(ctx, htmlPage("docs-v3", "/docs/v3"))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "latest", namespace, &kdexv1alpha1.KDexPage{}, true)
	})

	It("is Degraded(RewriteTargetIsRewrite) when the target is itself a rewrite page", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, htmlPage("real", "/real"))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("hop1",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "real"}, "", ""))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("hop2",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "hop1"}, "", ""))).To(Succeed())
		Eventually(degradedReason("hop2"), 10*time.Second).Should(Equal("RewriteTargetIsRewrite"))
	})

	It("is Degraded(RewriteTargetInternal) when the target function is internal", func() {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "internal-fn", Namespace: namespace},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				HostRef:  corev1.LocalObjectReference{Name: focalHost},
				Internal: true,
				API:      kdexv1alpha1.API{BasePath: "/api/internal"},
			},
		}
		Expect(k8sClient.Create(ctx, fn)).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("to-internal",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "internal-fn"}, "", ""))).To(Succeed())
		Eventually(degradedReason("to-internal"), 10*time.Second).Should(Equal("RewriteTargetInternal"))
	})

	It("is Degraded(RewriteUnknownPlaceholder) when path uses a name patternPath lacks", func() {
		Expect(k8sClient.Create(ctx, aliasPage("bad-ph",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "whatever"}, "/bad-ph/{user}", "{id}"))).To(Succeed())
		Eventually(degradedReason("bad-ph"), 10*time.Second).Should(Equal("RewriteUnknownPlaceholder"))
	})

	It("re-reconciles when the target switches into rewrite mode", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, htmlPage("real2", "/real2"))).To(Succeed())
		Expect(k8sClient.Create(ctx, htmlPage("mid", "/mid"))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("front",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "mid"}, "", ""))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "front", namespace, &kdexv1alpha1.KDexPage{}, true)

		var mid kdexv1alpha1.KDexPage
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "mid", Namespace: namespace}, &mid)).To(Succeed())
		mid.Spec.ContentEntries = nil
		mid.Spec.PageArchetypeRef = nil
		mid.Spec.Rewrite = &kdexv1alpha1.RewriteSpec{TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "real2"}}
		Expect(k8sClient.Update(ctx, &mid)).To(Succeed())

		Eventually(degradedReason("front"), 10*time.Second).Should(Equal("RewriteTargetIsRewrite"))
	})
})
```

Before running, check that `KDexFunctionSpec` requires fields beyond `HostRef`/`API.BasePath`. Run `rg -n "kubebuilder:validation:Required" -A 1 ../kdex-crds/api/v1alpha1/kdexfunction_types.go` and add the minimum required values to `fn` (copy them from an existing `KDexFunction` fixture in `internal/controller/kdexfunction_controller_test.go`).

- [ ] **Step 2: Run the specs and confirm they fail**

Run: `make test TEST_ARGS='-ginkgo.focus "rewrite-mode reconcile"'`. If `TEST_ARGS` isn't honoured by the target, use the `KUBEBUILDER_ASSETS=… go test ./internal/controller/ -ginkgo.focus …` form from Task 2, without GOWORK.
Expected: FAIL. The alias never becomes Ready: it walks the archetype path and never sets the rewrite reasons.

- [ ] **Step 3: Implement `kdexpage_rewrite.go`**

```go
package controller

import (
	"context"
	"fmt"

	"github.com/kdex-tech/host-manager/internal/rewrite"
	pages "github.com/kdex-tech/host-manager/internal/page"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Rewrite-mode Degraded reasons (#217). Controller-local for the same reason
// as routeCollisionConditionReason: ConditionReason is a bare string type, so
// a kdex-crds constant would cost a release for strings only this controller
// emits.
const (
	rewriteTargetIsRewriteReason    kdexv1alpha1.ConditionReason = "RewriteTargetIsRewrite"
	rewriteTargetInternalReason     kdexv1alpha1.ConditionReason = "RewriteTargetInternal"
	rewriteUnknownPlaceholderReason kdexv1alpha1.ConditionReason = "RewriteUnknownPlaceholder"
)

// reconcileRewrite handles a KDexPage in rewrite mode. It has no archetype,
// header, footer, navigation, content or script library, so none of those are
// resolved; only the target (and parentPageRef, which navigation placement
// uses) are.
func (r *KDexPageReconciler) reconcileRewrite(ctx context.Context, page *kdexv1alpha1.KDexPage) (ctrl.Result, error) {
	rw := page.Spec.Rewrite

	if unknown := rewrite.UnknownPlaceholders(rw.Path, page.Spec.PatternPath); len(unknown) > 0 {
		setRewriteDegraded(page, rewriteUnknownPlaceholderReason, fmt.Sprintf(
			"rewrite.path placeholders %v are not wildcards of patternPath %q", unknown, page.Spec.PatternPath))
		return ctrl.Result{}, nil
	}

	// Targets resolve in the page's own namespace; targetRef.namespace is
	// deliberately ignored (cross-namespace targets would cross hosts).
	ref := kdexv1alpha1.KDexObjectReference{Kind: rw.TargetRef.Kind, Name: rw.TargetRef.Name}
	targetObj, shouldReturn, res, err := ResolveKDexObjectReference(
		ctx, r.Client, page, &page.Status.Conditions, &ref, r.RequeueDelay)

	// A static problem with a target that EXISTS outranks its readiness: it
	// will not clear when the target becomes Ready, so it must not hide behind
	// the resolver's generic "not ready" Degraded.
	if targetObj != nil {
		if reason, msg := rewriteTargetProblem(targetObj); reason != "" {
			setRewriteDegraded(page, reason, msg)
			return ctrl.Result{}, nil
		}
	}
	if shouldReturn {
		return res, err
	}
	page.Status.Attributes["rewrite.target.generation"] = fmt.Sprintf("%d", targetObj.GetGeneration())

	parentPageObj, shouldReturn, res, err := ResolvePage(
		ctx, r.Client, page, &page.Status.Conditions, page.Spec.ParentPageRef, r.RequeueDelay)
	if shouldReturn {
		return res, err
	}
	if parentPageObj != nil {
		page.Status.Attributes["parent.page.generation"] = fmt.Sprintf("%d", parentPageObj.GetGeneration())
	}

	r.HostHandler.Pages.Set(pages.PageHandler{
		Name:   page.Name,
		Page:   &page.Spec,
		Status: &page.Status,
	})

	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)
	return ctrl.Result{}, nil
}

// rewriteTargetProblem reports a static reason the resolved target can never
// serve as a rewrite target, or "" when it can.
func rewriteTargetProblem(obj client.Object) (kdexv1alpha1.ConditionReason, string) {
	switch t := obj.(type) {
	case *kdexv1alpha1.KDexPage:
		if t.Spec.Rewrite != nil {
			return rewriteTargetIsRewriteReason, fmt.Sprintf(
				"rewrite target KDexPage %s is itself a rewrite page; only one hop is allowed", t.Name)
		}
	case *kdexv1alpha1.KDexFunction:
		if t.Spec.Internal {
			return rewriteTargetInternalReason, fmt.Sprintf(
				"rewrite target KDexFunction %s is internal and is not served by the host", t.Name)
		}
	}
	return "", ""
}

func setRewriteDegraded(page *kdexv1alpha1.KDexPage, reason kdexv1alpha1.ConditionReason, msg string) {
	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		reason,
		msg,
	)
}
```

- [ ] **Step 4: Wire it into `Reconcile` and `SetupWithManager`**

In `kdexpage_controller.go`, immediately after the "Reconciling" `kdexv1alpha1.SetConditions(...)` call and before `backendRefs := …`:

```go
	if page.Spec.Rewrite != nil {
		return r.reconcileRewrite(ctx, &page)
	}
```

(The deferred status write and the `Pages.Delete` on not-Ready already cover rewrite pages, because they run for every return.)

In `SetupWithManager`, add these before `.WithEventFilter(enabledFilter)`:

```go
		Watches(
			&kdexv1alpha1.KDexPage{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.Rewrite.TargetRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexFunction{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.Rewrite.TargetRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
```

Add `// +kubebuilder:rbac:groups=kdex.dev,resources=kdexfunctions,verbs=get;list;watch` above `Reconcile` **only if** `rg -n "resources=kdexfunctions" internal/controller/` shows no existing get/list/watch marker for the manager role. The function controller normally grants it already.

- [ ] **Step 5: Run the specs and confirm they pass, then run the whole controller suite**

Run: the focused command from Step 2, then `make test`.
Expected: PASS for all five new specs. No regressions in the existing `KDexPage Controller` specs; HTML pages still take the unchanged path.

- [ ] **Step 6: Commit**

```bash
git add internal/controller/kdexpage_rewrite.go internal/controller/kdexpage_controller.go internal/controller/kdexpage_rewrite_test.go
git commit -m "feat(controller): reconcile KDexPage rewrite mode with static target checks (#217)

Resolves rewrite.targetRef in the page namespace, degrades with
RewriteTargetIsRewrite / RewriteTargetInternal / RewriteUnknownPlaceholder,
and watches KDexPage + KDexFunction targets so the alias re-settles when
its target appears, changes mode, or disappears.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Extract the page gate into `pageGateLocked` (pure refactor)

**Files:**
- Modify: `kdex-host-manager/internal/host/page.go`. The gate block starting `if hh.IsAuthEnabled() && hh.authChecker != nil && ph.ParsedRequirements != nil {` (currently line 37) through its closing brace just before the `// Per-page seed:` comment (currently line ~176) moves into a method.
- Test: existing `internal/host/page_denial_test.go`, `page_test.go`, `landing_test.go`, `subjectless_gate_test.go`, `authcheck_fault_test.go`, `page_denial_mode_test.go`. **No new test**: this task is behaviour-preserving, and those suites are the proof.

**Interfaces:**
- Produces: `func (hh *HostHandler) pageGateLocked(w http.ResponseWriter, r *http.Request, ph page.PageHandler, l language.Tag) bool`. **Caller must hold `hh.mu.RLock`.** Returns `true` when the request may proceed and `false` when a response has already been written. Task 7 calls it.

- [ ] **Step 1: Record the green baseline**

Run: `go test ./internal/host/ -run 'PageGate|PageHandlerFunc|Discover|Subjectless|AuthCheckFault|PageDenial' -count=1`
Expected: PASS. Note the test count.

- [ ] **Step 2: Move the block**

Cut the whole `if hh.IsAuthEnabled() && … {` … `}` block out of `pageHandlerFunc` and paste it into a new method at the bottom of `page.go`. Make exactly these edits to it:
- Wrap it as below.
- Replace every bare `return` inside it with `return false`.
- Keep every comment verbatim.
- The `// Locked: pageHandlerFunc holds hh.mu.RLock…` comment beside `Issuer: hh.issuerAddressLocked()` becomes `// Locked: pageGateLocked's caller holds hh.mu.RLock.`

```go
// pageGateLocked runs a page's authorization gate: the checker, the fault
// split (500), and the denial contract (login redirect / discovery redirect /
// 401 / 403). The caller MUST hold hh.mu.RLock -- discoverLandingPage and
// issuerAddressLocked read hh state. It returns true when the request may
// proceed, false when it has already written the response.
//
// Shared by pageHandlerFunc and the rewrite handler (#217), which runs it for
// the ALIAS page and then releases the lock before dispatching to the target.
func (hh *HostHandler) pageGateLocked(w http.ResponseWriter, r *http.Request, ph page.PageHandler, l language.Tag) bool {
	log := logf.FromContext(r.Context())

	if hh.IsAuthEnabled() && hh.authChecker != nil && ph.ParsedRequirements != nil {
		// ... the moved block, with `return` -> `return false` ...
	}
	return true
}
```

In `pageHandlerFunc`, where the block was:

```go
		if !hh.pageGateLocked(w, r, ph, l) {
			return
		}
```

Delete the now-unused `log := logf.FromContext(r.Context())` in `pageHandlerFunc` **only if** `go vet` reports it unused (the render path below it also logs, so it likely stays).

- [ ] **Step 3: Run the gate suites and the whole package**

Run: the Step 1 command, then `go test ./internal/host/ -count=1 -race`.
Expected: PASS with the same test count as Step 1, and no race reports.

- [ ] **Step 4: Commit**

```bash
git add internal/host/page.go
git commit -m "refactor(host): extract the page gate into pageGateLocked (#217 prep)

Behaviour-preserving: the rewrite handler needs to run an alias page's gate
and then release hh.mu before dispatching.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Host — target resolution, registration, `rewriteHandler`

> Pre-#220 snippets; see the note under **Spec** above.

**Files:**
- Create: `kdex-host-manager/internal/host/rewrite.go`
- Modify: `kdex-host-manager/internal/host/types.go`: the `pageRender` struct, currently line 330
- Modify: `kdex-host-manager/internal/host/host.go`: in `rebuildMuxSnapshot`, after the `renderedPages` loop (the one ending `renderedPages[basePath] = pageRender{ph: ph}`, currently line ~520)
- Modify: `kdex-host-manager/internal/host/handlers.go`: the handler construction inside `addHandlerAndRegister`'s language loop (currently line 262)
- Test: `kdex-host-manager/internal/host/rewrite_test.go` (new)

**Interfaces:**
- Consumes: `rewrite.Target`, `rewrite.ErrUnsafe` (Task 4); `hh.pageGateLocked` (Task 6); `kdexv1alpha1.RewriteSpec` (Task 1).
- Produces:
  - `type rewriteTarget struct{ basePath, exact string; localized bool }`
  - `func resolveRewriteTarget(ref kdexv1alpha1.KDexObjectReference, pagesByName map[string]page.PageHandler, functions []kdexv1alpha1.KDexFunction) (rewriteTarget, bool)`
  - `pageRender` gains `rewrite rewriteTarget` and `rewriteFound bool`
  - `func (hh *HostHandler) rewriteHandlerFunc(pr pageRender, lang language.Tag, mux *http.ServeMux) http.HandlerFunc`
  - Task 8 reads `pr.ph.Page.Rewrite` in `regFunc`.

- [ ] **Step 1: Write the failing tests**

```go
package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)
// ("strings" is used by Task 8's test in this same file; until Task 8 lands,
// drop it from this import block or the package will not compile.)

func aliasPH(name, basePath, pattern string, rw kdexv1alpha1.RewriteSpec) page.PageHandler {
	return page.PageHandler{
		Name: name,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label:   name,
			Paths:   kdexv1alpha1.Paths{BasePath: basePath, PatternPath: pattern},
			Rewrite: &rw,
		},
	}
}

func pageRef(name string) kdexv1alpha1.KDexObjectReference {
	return kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: name}
}

// registerRendersForTest registers every render onto ONE shared mux (unlike
// registerPageForTest's fresh mux per call), resolving rewrite targets the
// way rebuildMuxSnapshot does.
func (hh *HostHandler) registerRendersForTest(t *testing.T, fns []kdexv1alpha1.KDexFunction, phs ...page.PageHandler) *http.ServeMux {
	t.Helper()
	byName := map[string]page.PageHandler{}
	for _, ph := range phs {
		byName[ph.Name] = ph
	}
	mux := http.NewServeMux()
	routes := newRouteRegistry()
	for _, ph := range phs {
		pr := pageRender{ph: ph}
		if ph.Page.Rewrite != nil {
			pr.rewrite, pr.rewriteFound = resolveRewriteTarget(ph.Page.Rewrite.TargetRef, byName, fns)
		}
		require.NoError(t, hh.addHandlerAndRegister(mux, pr, hh.registeredPaths, &hh.Translations, routes))
	}
	hh.Mux = mux
	return mux
}

func TestResolveRewriteTarget(t *testing.T) {
	html := page.PageHandler{Name: "docs", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/docs/v3"}}}
	text := page.PageHandler{Name: "robots", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/robots.txt"}, MimeType: "txt"}}
	f := false
	unloc := page.PageHandler{Name: "unloc", Page: &kdexv1alpha1.KDexPageSpec{Paths: kdexv1alpha1.Paths{BasePath: "/u"}, Localized: &f}}
	hop := aliasPH("hop", "/hop", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("docs")})
	pages := map[string]page.PageHandler{"docs": html, "robots": text, "unloc": unloc, "hop": hop}
	fns := []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
		{ObjectMeta: metav1ObjectMeta("cold"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/cold"}}},
		{ObjectMeta: metav1ObjectMeta("inner"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/inner"}, Internal: true}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}

	got, ok := resolveRewriteTarget(pageRef("docs"), pages, fns)
	require.True(t, ok)
	assert.Equal(t, rewriteTarget{basePath: "/docs/v3", exact: "/docs/v3/", localized: true}, got, "HTML target's registered form has the trailing slash")

	got, ok = resolveRewriteTarget(pageRef("robots"), pages, fns)
	require.True(t, ok)
	assert.Equal(t, "/robots.txt", got.exact, "text target registers at its exact basePath")

	got, ok = resolveRewriteTarget(pageRef("unloc"), pages, fns)
	require.True(t, ok)
	assert.False(t, got.localized)

	_, ok = resolveRewriteTarget(pageRef("hop"), pages, fns)
	assert.False(t, ok, "a rewrite-mode target is never resolvable (one hop; Review Focus #2)")
	_, ok = resolveRewriteTarget(pageRef("gone"), pages, fns)
	assert.False(t, ok)

	got, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"}, pages, fns)
	require.True(t, ok)
	assert.Equal(t, rewriteTarget{basePath: "/api/downloads", exact: "/api/downloads"}, got)
	_, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "cold"}, pages, fns)
	assert.False(t, ok, "a function that is not Ready is not routable")
	_, ok = resolveRewriteTarget(kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "inner"}, pages, fns)
	assert.False(t, ok, "an internal function is never on the host mux")
}

func TestRewrite_ServesTextPageTargetWithoutRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	rr := doRequest(t, mux, "GET", "/bots/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "hello", rr.Body.String())
	assert.Empty(t, rr.Header().Get("Location"))
	assert.Empty(t, rr.Header().Get("Link"), "canonical is opt-in")
}

func TestRewrite_HTMLTargetDispatchesToRegisteredForm(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := page.PageHandler{Name: "docs", MainTemplate: "<html></html>", Page: &kdexv1alpha1.KDexPageSpec{Label: "docs", Paths: kdexv1alpha1.Paths{BasePath: "/docs/v3"}}}
	mux := hh.registerRendersForTest(t, nil, target)
	tgt, ok := resolveRewriteTarget(pageRef("docs"), map[string]page.PageHandler{"docs": target}, nil)
	require.True(t, ok)
	// The empty-path dispatch lands on the page's own {$} route, not on a
	// slash-redirect that would expose the target URL.
	assertMatches(t, mux, "GET", tgt.exact, "GET /docs/v3/{$}")
}

func TestRewrite_SubstitutesParamsAndKeepsRawQuery(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerRendersForTest(t, []kdexv1alpha1.KDexFunction{
		{ObjectMeta: metav1ObjectMeta("dl"), Spec: kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/api/downloads"}}, Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady}},
	}, aliasPH("get", "/get", "/get/{id}", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "dl"},
		Path:      "{id}",
	}))
	// Stand-in for the function proxy route rebuildMuxSnapshot registers.
	mux.HandleFunc("/api/downloads/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path + "?" + r.URL.RawQuery))
	})

	rr := doRequest(t, mux, "GET", "/get/42?q=a%26b&x=1")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "/api/downloads/42?q=a%26b&x=1", rr.Body.String(), "Review Focus #4")
}

func TestRewrite_RefusesEncodedTraversal(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("u", "/u", "/u/{rest...}", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots"), Path: "{rest}"})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	// End to end: ServeMux cleans a decoded "/u/a/../../secret" and
	// redirects BEFORE any handler runs, so the target is never served.
	rr := doRequest(t, mux, "GET", "/u/a%2F..%2F..%2Fsecret")
	assert.NotEqual(t, "hello", rr.Body.String(), "Review Focus #1: traversal must never reach the target")

	// The handler's own guard, for values the mux does not clean (defence in
	// depth -- e.g. a future pattern or a non-ServeMux caller).
	pr := pageRender{ph: alias}
	pr.rewrite, pr.rewriteFound = resolveRewriteTarget(pageRef("robots"),
		map[string]page.PageHandler{"robots": target}, nil)
	req := httptest.NewRequest("GET", "/u/x", nil)
	req.SetPathValue("rest", "../secret")
	w := httptest.NewRecorder()
	hh.rewriteHandlerFunc(pr, language.Make("en"), mux)(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code, "Review Focus #1")
}

func TestRewrite_LocalizedPageTargetKeepsLanguagePrefix(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "about", "/about.txt", "txt", "about")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("a", "/a", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("about")}))

	// /fr/a/ must dispatch to /fr/about.txt (registered for the localized
	// text target), not to the bare /about.txt.
	rr := doRequest(t, mux, "GET", "/fr/a/")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "about", rr.Body.String())
	assertMatches(t, mux, "GET", "/fr/about.txt", "GET /fr/about.txt")
}

func TestRewrite_CanonicalLinkHeader(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.host.Routing.Domains = []string{"example.com"}
	hh.scheme = "https"
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots"), Canonical: true}))

	rr := doRequest(t, mux, "GET", "/bots/")
	assert.Equal(t, `<https://example.com/robots.txt>; rel="canonical"`, rr.Header().Get("Link"))
}

func TestRewrite_MissingTargetIs404(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerRendersForTest(t, nil,
		aliasPH("orphan", "/orphan", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("gone")}))
	rr := doRequest(t, mux, "GET", "/orphan/")
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestRewrite_SecondHopIs508(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	alias := aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")})
	mux := hh.registerRendersForTest(t, nil, target, alias)

	req := httptest.NewRequest("GET", "/bots/", nil)
	req = req.WithContext(context.WithValue(req.Context(), rewriteMarkerKey{}, true))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusLoopDetected, rr.Code)
}

func TestRewrite_AliasGateAndTargetGateBothApply(t *testing.T) {
	target := newPage("keys", "Keys", "/keys.txt") // newPage sets ParsedRequirements, which arms the gate
	target.Page.MimeType, target.Page.Body = "txt", "secret"
	alias := aliasPH("k", "/k", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("keys")})
	alias.ParsedRequirements = &entitlements.ParsedRequirements{}

	// gatedHostFixture's auth wiring on top of newTestHostHandler, whose
	// Translations are populated -- addHandlerAndRegister registers one
	// route set per language, so an empty language list registers nothing.
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.authConfig = &auth.Config{AnonymousEntitlements: []string{"public"}, ActivePair: &keys.KeyPair{}}
	hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}

	// Alias public, target gated: the TARGET's gate must still deny (Review Focus #3).
	hh.authChecker = denyPath("/keys.txt")
	mux := hh.registerRendersForTest(t, nil, target, alias)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, anonReq("GET", "/k/", "application/json"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Alias gated: denied before any dispatch.
	hh.authChecker = denyPath("/k")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, anonReq("GET", "/k/", "application/json"))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRewrite_NoDeadlockUnderConcurrentWriter(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	mux := hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")}))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // a SetHost-shaped writer hammering hh.mu
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				hh.mu.Lock()
				hh.mu.Unlock() //nolint:staticcheck // deliberate empty critical section
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		for range 2000 {
			doRequest(t, mux, "GET", "/bots/")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("rewrite dispatch deadlocked against a concurrent writer (Review Focus #5)")
	}
	close(stop)
	wg.Wait()
}
```

Also add this tiny helper to the same file (fixtures above use it):

```go
func metav1ObjectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/host/ -run 'Rewrite|ResolveRewriteTarget' -count=1`
Expected: compile FAIL (`resolveRewriteTarget`, `rewriteTarget`, `rewriteMarkerKey`, `pageRender.rewrite` undefined).

- [ ] **Step 3: Implement `internal/host/rewrite.go`**

```go
package host

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/rewrite"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// rewriteTarget is a rewrite page's target as resolved for one mux snapshot
// (#217). basePath is the target's declared basePath; exact is the path its
// routes are registered at, used when rewrite.path is empty so the mux never
// slash-redirects to the target; localized is true only for a KDexPage target
// that registers per-language routes.
type rewriteTarget struct {
	basePath  string
	exact     string
	localized bool
}

// rewriteMarkerKey marks a request already re-dispatched by a rewrite, so a
// second rewrite hop answers 508 instead of looping. The page controller
// forbids that topology; this guards the window before it re-reconciles.
type rewriteMarkerKey struct{}

// resolveRewriteTarget finds ref among this snapshot's pages and functions.
// A rewrite-mode page, a missing page, and a function that is not Ready or is
// internal are all "not found": their routes are not servable as a target.
func resolveRewriteTarget(
	ref kdexv1alpha1.KDexObjectReference,
	pagesByName map[string]page.PageHandler,
	functions []kdexv1alpha1.KDexFunction,
) (rewriteTarget, bool) {
	switch ref.Kind {
	case "KDexPage":
		ph, ok := pagesByName[ref.Name]
		if !ok || ph.Page == nil || ph.Page.Rewrite != nil {
			return rewriteTarget{}, false
		}
		bp := ph.Page.BasePath
		exact := bp
		if ph.Page.MimeType == "" && !strings.HasSuffix(bp, "/") {
			exact = bp + "/"
		}
		return rewriteTarget{basePath: bp, exact: exact, localized: isLocalized(ph.Page.Localized)}, true
	case "KDexFunction":
		for _, f := range functions {
			if f.Name == ref.Name && !f.Spec.Internal && f.Status.State == kdexv1alpha1.KDexFunctionStateReady {
				return rewriteTarget{basePath: f.Spec.API.BasePath, exact: f.Spec.API.BasePath}, true
			}
		}
	}
	return rewriteTarget{}, false
}

// rewriteHandlerFunc serves a rewrite page registered for lang: it runs the
// alias page's own gate, builds the target path, and re-dispatches a clone of
// the request into mux -- the snapshot this handler was registered into, never
// hh.Mux, which a reconcile may have swapped since.
//
// LOCKING: the gate and the canonical base read hh state under hh.mu.RLock,
// and the lock is released BEFORE dispatch. The target's pageHandlerFunc takes
// hh.mu.RLock itself; holding it across the dispatch would read-lock twice on
// one goroutine, which deadlocks as soon as a SetHost writer queues between
// the two acquisitions.
func (hh *HostHandler) rewriteHandlerFunc(pr pageRender, lang language.Tag, mux *http.ServeMux) http.HandlerFunc {
	ph := pr.ph
	rw := ph.Page.Rewrite
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(rewriteMarkerKey{}) != nil {
			http.Error(w, http.StatusText(http.StatusLoopDetected), http.StatusLoopDetected)
			return
		}
		if !pr.rewriteFound {
			hh.serveError(w, r, http.StatusNotFound, "not found")
			return
		}

		hh.mu.RLock()
		allowed := hh.pageGateLocked(w, r, ph, lang)
		base := hh.issuerAddressLocked()
		defaultLang := hh.defaultLanguage
		hh.mu.RUnlock()
		if !allowed {
			return
		}

		target, err := rewrite.Target(pr.rewrite.basePath, pr.rewrite.exact, rw.Path, r.PathValue)
		if err != nil {
			if !errors.Is(err, rewrite.ErrUnsafe) {
				hh.log.Error(err, "rewrite target build failed", "page", ph.Name)
			}
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if pr.rewrite.localized && lang.String() != defaultLang {
			target = "/" + lang.String() + target
		}
		if rw.Canonical && base != "" {
			w.Header().Set("Link", "<"+base+target+`>; rel="canonical"`)
		}

		r2 := r.Clone(context.WithValue(r.Context(), rewriteMarkerKey{}, true))
		r2.URL.Path = target
		r2.URL.RawPath = ""
		mux.ServeHTTP(w, r2)
	}
}
```

In `types.go`, extend `pageRender`:

```go
type pageRender struct {
	ph page.PageHandler
	// rewrite / rewriteFound carry a rewrite-mode page's target as resolved
	// for this snapshot (#217); zero for every other page.
	rewrite      rewriteTarget
	rewriteFound bool
}
```

In `host.go` `rebuildMuxSnapshot`, directly after the loop that fills `renderedPages`:

```go
	// Resolve each rewrite page's target against THIS snapshot's pages and
	// functions (#217), so a target that moved, vanished, or changed mode is
	// reflected on the very rebuild that observed it.
	pagesByName := make(map[string]page.PageHandler, len(pageHandlers))
	for _, ph := range pageHandlers {
		pagesByName[ph.Name] = ph
	}
	for bp, pr := range renderedPages {
		if pr.ph.Page != nil && pr.ph.Page.Rewrite != nil {
			pr.rewrite, pr.rewriteFound = resolveRewriteTarget(pr.ph.Page.Rewrite.TargetRef, pagesByName, hh.functions)
			renderedPages[bp] = pr
		}
	}
```
(`page` is already imported in `host.go` for `page.PageHandler`. If not, add `"github.com/kdex-tech/host-manager/internal/page"`.)

In `handlers.go` `addHandlerAndRegister`, replace

```go
		handler := hh.pageHandlerFunc(pr.ph, translations, lang)
```
with

```go
		var handler http.HandlerFunc = hh.pageHandlerFunc(pr.ph, translations, lang)
		if pr.ph.Page != nil && pr.ph.Page.Rewrite != nil {
			handler = hh.rewriteHandlerFunc(pr, lang, mux)
		}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/host/ -run 'Rewrite|ResolveRewriteTarget' -count=1 -race`
Expected: PASS for all ten, with no race reports.

- [ ] **Step 5: Run the whole host package**

Run: `go test ./internal/host/ -count=1 -race`
Expected: PASS, including `route_collision_test.go` and `enumerated_l10n_test.go` unchanged.

- [ ] **Step 6: Commit**

```bash
git add internal/host/rewrite.go internal/host/rewrite_test.go internal/host/types.go internal/host/host.go internal/host/handlers.go
git commit -m "feat(host): serve KDexPage rewrite mode by re-dispatching into the mux snapshot (#217)

Resolves each rewrite page's target per rebuild, runs the alias page's own
gate under hh.mu.RLock and releases it before dispatch (no re-entrant
read lock), substitutes patternPath values into rewrite.path, keeps the
language prefix for localized page targets and the raw query, emits an
opt-in rel=canonical Link, 404s an unresolved target and 508s a second hop.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: OpenAPI — describe rewrite routes as aliases

**Files:**
- Modify: `kdex-host-manager/internal/host/handlers.go`: the `regFunc` closure inside `addHandlerAndRegister` (currently lines 113–178)
- Test: `kdex-host-manager/internal/host/rewrite_test.go` (append)

**Interfaces:**
- Consumes: `pr.ph.Page.Rewrite` (Task 1), and `registerRendersForTest` (Task 7).

- [ ] **Step 1: Write the failing test**

```go
func TestRewrite_OpenAPIDescribesAlias(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	target := textPageForTest(t, "robots", "/robots.txt", "txt", "hello")
	hh.registerRendersForTest(t, nil, target,
		aliasPH("bots", "/bots", "", kdexv1alpha1.RewriteSpec{TargetRef: pageRef("robots")}))

	found := 0
	for _, info := range hh.registeredPaths {
		for p, item := range info.API.Paths {
			if item.Get == nil || !strings.HasPrefix(item.Get.OperationID, "bots") {
				continue
			}
			found++
			assert.Contains(t, item.Get.Summary, "Alias of KDexPage/robots", p)
			resp := item.Get.Responses.Status(http.StatusOK)
			require.NotNil(t, resp, p)
			assert.Nil(t, resp.Value.Content, "%s: an alias must not claim text/html", p)
		}
	}
	assert.GreaterOrEqual(t, found, 2, "bare + /fr routes documented")
	ids := collectOperationIDs(t, hh)
	assert.Len(t, ids, len(uniqueStrings(ids)), "operationIds stay unique")
}

func uniqueStrings(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		m[s] = struct{}{}
	}
	return m
}
```
(Restore `"strings"` in the test imports if Task 7 dropped it.)

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/host/ -run TestRewrite_OpenAPIDescribesAlias -count=1`
Expected: FAIL. The summary is `Get bots…` and the 200 response has `text/html` content.

- [ ] **Step 3: Implement the alias branch in `regFunc`**

In `regFunc`, right after the `op := &openapi.Operation{…}` literal and before `hh.registerPath(…)`:

```go
		if rw := pr.ph.Page.Rewrite; rw != nil {
			alias := fmt.Sprintf("Alias of %s/%s%s", rw.TargetRef.Kind, rw.TargetRef.Name, langSuffix)
			op.Summary = alias
			op.Description = alias
			op.Responses.Set("200", &openapi.ResponseRef{
				Value: &openapi.Response{Description: new("Response of the target " + rw.TargetRef.Kind + "/" + rw.TargetRef.Name)},
			})
		}
```

Also make the `hh.registerPath` `PathItem.Description`/`Summary` for this route say `alias` rather than `HTML page`:

```go
		itemDesc := fmt.Sprintf("HTML page %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), langSuffix)
		if pr.ph.Page.Rewrite != nil {
			itemDesc = op.Description
		}
```
and use `itemDesc` for the `Description:` field of the `ko.PathItem` literal.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test ./internal/host/ -run 'Rewrite|OpenAPI|OperationID' -count=1`
Expected: PASS. The existing `TestOpenAPIOperationIDsAreUnique_AcrossLanguages` is still green.

- [ ] **Step 5: Commit**

```bash
git add internal/host/handlers.go internal/host/rewrite_test.go
git commit -m "feat(openapi): document rewrite routes as aliases of their target (#217)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Docs and spec amendment

**Files:**
- Create: `kdex-main-site/docs-app/content/src/en/031_Topics/030_Site Design/034_page-operating-modes.md`
- Modify: `/home/rotty/skills/kdex/skills/kdex-kcnas/SKILL.md`: the `KDexPage` bullet under `### Page composition` (currently line 187)
- Modify: `kdex-host-manager/docs/superpowers/specs/2026-09-29-kdexpage-rewrite-mode-design.md` (§2 and §3 wording)

- [ ] **Step 1: Write the site doc**

````markdown
---
title: "Page Operating Modes"
weight: 34
---

## Page Operating Modes

A `KDexPage` runs in exactly one of three modes, chosen by which fields it sets. The CRD rejects mixtures.

| Mode | Set | Served as |
|---|---|---|
| **HTML** | `contentEntries` (with a `main` slot) | the archetype-composed HTML page, with header, footer and navigation |
| **Text** | `mimeType` + `body` | `body` rendered through the `[[ ]]` template + translation pipeline, with the matching `Content-Type`. Registered at its exact `basePath` (`/robots.txt`, `/llms.txt`, `/sitemap.xml`); `patternPath` is not allowed. |
| **Rewrite** | `rewrite` | another `KDexPage` or `KDexFunction`'s response, served at this page's URL, with no redirect |

### Rewrite mode

A rewrite page is an internal alias. The browser keeps the alias URL, and the host serves the target's response.

```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexPage
metadata:
  name: docs-latest
spec:
  hostRef:
    name: my-host
  label: Docs (latest)
  basePath: /docs/latest
  patternPath: /docs/latest/{rest...}
  rewrite:
    targetRef:
      kind: KDexPage
      name: docs-v3
    path: "{rest}"
    canonical: true
```

- **`targetRef`**: a `KDexPage` or a `KDexFunction` in the same namespace. The rewrite follows the target if its `basePath` changes.
- **`path`**: optional. Joined to the target's `basePath`. Each `{name}` is replaced by the matching wildcard from this page's `patternPath`. Leave it empty to serve the target's own page.
- **`canonical`**: optional. Adds `Link: <target URL>; rel="canonical"` so search engines index the target instead of the alias.

Fronting a function's GET endpoint with a page-style URL:

```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexPage
metadata:
  name: download
spec:
  hostRef:
    name: my-host
  label: Download
  basePath: /download
  patternPath: /download/{id}
  rewrite:
    targetRef:
      kind: KDexFunction
      name: downloads
    path: "{id}"
```

**Behaviour to know:**
- **Both gates apply.** The alias page's `security` is checked first, then the target's own requirements. An alias never grants access the target doesn't.
- **One hop only.** A rewrite page can't target another rewrite page. The alias reports `Degraded` with reason `RewriteTargetIsRewrite`.
- **Other `Degraded` reasons:**
  - `RewriteTargetInternal`: the target is a function with `spec.internal: true`.
  - `RewriteUnknownPlaceholder`: `path` uses a `{name}` that `patternPath` doesn't define.
  - The generic not-found / not-ready condition: the target is missing or not Ready yet.
- **GET only.** Localized aliases keep their language: `/fr/docs/latest/…` serves the French target when the target page is localized.
- A rewrite page carries no content: `contentEntries`, `pageArchetypeRef`, the `override*Refs` and `scriptLibraryRef` are rejected. Its `label`, `navigationHints`, `parentPageRef` and `tags` still drive navigation as usual.
````

- [ ] **Step 2: Update the skill's KDexPage bullet**

Replace the `KDexPage` bullet under `### Page composition` with:

```markdown
- `KDexPage` — *host-bound.* `basePath`, `label`, `hostRef`, plus **exactly one operating mode**: **HTML** — `contentEntries[]` (each `appRef` or `rawHTML` with `slot`, a `main` slot required) with `overrideHeaderRef` / `overrideFooterRef` / `overrideNavigationRefs` / `pageArchetypeRef` / `scriptLibraryRef`; **text** — `mimeType` (`txt|json|yaml|markdown|xml`) + `body`, served at the exact `basePath` (robots.txt, llms.txt, sitemap.xml; no `patternPath`); **rewrite** — `rewrite{targetRef{kind: KDexPage|KDexFunction, name}, path?, canonical?}`, an internal alias that serves the target's response at this URL (no redirect, both gates apply, one hop only, GET only; `path` substitutes `{name}` from `patternPath` wildcards; host-manager#217). Common to all: `parentPageRef`, `navigationHints`, `tags`, `contact`, `security`, `localized`.
```

- [ ] **Step 3: Amend the spec to match what was built**

In the spec's §2, replace the paragraph starting "A target function that exists but is not Ready…" with:

```markdown
A target that exists but is not Ready yet (typically a KDexFunction still building) marks the rewrite page `Degraded` with the resolver's generic "referenced … is not ready" condition and requeues, exactly like every other page reference (`ResolveKDexObjectReference`). The static problems above are checked first, so they are never hidden behind readiness.
```

In §3's **Locking** paragraph, replace the first sentence with:

```markdown
**Locking (hard requirement).** `rewriteHandler` never holds `hh.mu` **across the dispatch**: it runs the alias page's gate (`pageGateLocked`, which needs the lock) under `hh.mu.RLock`, releases it, and only then dispatches.
```

and delete the sentence beginning "The shared gate helper therefore must not take `hh.mu` itself…". Replace it with: "The shared gate helper (`pageGateLocked`) requires its caller to hold the read lock; it never acquires it."

In §1's `Path` markers, change the rule description to "must not contain '//', '.' or '..' segments", matching the CEL that shipped.

- [ ] **Step 4: Commit in each repo**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-main-site
git add "docs-app/content/src/en/031_Topics/030_Site Design/034_page-operating-modes.md"
git commit -m "docs: KDexPage operating modes (HTML / text / rewrite)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"

cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add docs/superpowers/specs/2026-09-29-kdexpage-rewrite-mode-design.md
git commit -m "docs: align rewrite-mode spec with the implementation (#217)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

`/home/rotty/skills/kdex/skills/kdex-kcnas/SKILL.md` is not a git repo. The edit is saved in place, and syncing it to the installed copy follows the user's existing skill-sync process. Mention this in the final report.

---

### Task 10: CHECKPOINT — full verification and release

- [ ] **Step 1: Lint everything from the workspace root**

Run: `cd /home/rotty/projects/kdex/workspace && make lint`
Expected: clean across modules. Fix anything in the touched repos only.

- [ ] **Step 2: Full test suites for both actors**

Run: `cd kdex-host-manager && make test`, then `cd ../kdex-nexus-manager && make test`.
Expected: both PASS.

- [ ] **Step 3: Check live text pages for the new #201 rule**

The new CEL rejects a text page with `patternPath` on its next update. Check that no deployed CR has one:

```bash
kubectl get kdexpages -A -o json | jq -r '.items[] | select(.spec.mimeType and .spec.patternPath) | "\(.metadata.namespace)/\(.metadata.name)"'
```
Expected: no output. If there is output, report the CRs to the user before releasing.

- [ ] **Step 4: Integrate the feature branch**

```bash
cd kdex-host-manager
git switch main && git pull --ff-only
git switch feat/217-rewrite-mode && git rebase main
git switch main && git merge --ff-only feat/217-rewrite-mode
git log --merges origin/main..main   # must print nothing
```

- [ ] **Step 5: STOP. Report to the user and get an explicit go-ahead** before pushing host-manager `main`, nexus-manager `main` and kdex-main-site, and before cutting the host-manager and nexus-manager releases. Both actors must be released for this CRD change.

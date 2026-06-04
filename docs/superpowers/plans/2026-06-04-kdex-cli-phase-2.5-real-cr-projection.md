# kdex CLI — Phase 2.5 (Real-CR Projection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `kdex preview --crs <real-cluster-CR-dir>` work end-to-end against the user-facing KDex CR set (the form people actually author), not just the synthetic post-reconcile fixtures Phase 2 supports. Achieved by in-process projection of `KDexHost` → `KDexInternalHost`, `KDexTranslation` → `KDexInternalTranslation`, `KDexUtilityPage` → `KDexInternalUtilityPage` (replicating nexus-manager's projection rules), plus loader support for page-composition CRs.

**Architecture:** New `internal/preview/projector/` package implements the three projections as pure functions (Snapshot of user-facing CRs → post-reconcile CRs), mirroring `nexus-manager/internal/controller/kdexhost_controller.go:651-736` and `kdexhost_controller_util.go:36-181`. The loader scans into typed buckets, hands them to the projector, and returns a Snapshot containing only the Internal*/Cluster* forms (downstream `fakeclient`/`synth`/`server` are unchanged). The loader also gains support for the page-composition CRs (`KDexPageHeader`/`Footer`/`Navigation`/`ScriptLibrary` and their cluster-scoped siblings) which host-manager's page reconciler already consumes — so once seeded into the fake client, they "just work".

**Tech Stack:** Go 1.26, `sigs.k8s.io/yaml`, `kdex.dev/crds/api/v1alpha1`, controller-runtime `client/fake`. No new external deps.

**Research baseline:** `nexus-manager` only projects 3 kinds (KDexHost, KDexTranslation, KDexUtilityPage). KDexPageArchetype↔KDexClusterPageArchetype are **independent** kinds with no projection. Page-composition CRs are consumed directly by host-manager's `kdexpage_controller.go:135-352` — no projection needed. The `KDexHost` projection is **stateful** (it synthesizes `Spec.InternalTranslationRefs[]` and `Spec.{Announcement,Error,Login}Ref` from the host's TranslationRefs/UtilityPages lists, with names mangled as `<host>-<source>`).

**Spec reference:** Phase 2 plan at `2026-06-04-kdex-cli-phase-2-preview-mvp.md` for the upstream surfaces (loader Snapshot, fakeclient.Setup, etc.). Final-review report at session HEAD discusses the gap this plan closes.

---

## Out of scope (deferred)

- **Helm release behavior.** nexus-manager spins up a per-host host-manager Deployment via Helm; preview replaces that with the in-process fakeclient. This plan does not replicate the Helm install.
- **`kdex-default-translation` injection.** nexus-manager silently appends a hard-coded default translation to every host (`kdexhost_controller_util.go:217-246`). Preview will note its absence in the projection log but won't auto-inject one. Documented in Task C.10.
- **Default-utility-page short-circuit names.** nexus-manager's webhook defaulter knows magic names like `KDexDefaultUtilityPageLogin`; preview won't replicate that special case in v1. If the user's host references a "default" utility page that doesn't exist in the loaded CR set, the projection emits a warning and skips the ref.
- **Cluster-scoped overrides at runtime.** Phase 2's `ResolveOrDefaultPageArchetype` (in host-manager) prefers `kdex.dev/default=true` archetypes ordered by `CreationTimestamp`. Preview can't reproduce timestamps meaningfully; fallback ordering will be alphabetical-by-name.
- **`KDexRole` / `KDexRoleBinding`.** Orthogonal to rendering — keep the loader's silent-skip behavior.

---

## Phase 2.5 deliverable

After all tasks complete:

```
./bin/kdex preview \
  --crs /home/rotty/projects/RSI/knowdrive-site/k8s/dev \
  --addr :18080
```

- Boots without error against the user's actual cluster CR set (KDexHost, KDexTranslation, KDexUtilityPage, KDexPageArchetype, KDexPageHeader, KDexPageFooter, KDexPageNavigation, KDexScriptLibrary, KDexApp, KDexFunction, KDexPage, KDexTheme).
- `http://localhost:18080/` returns the composed home page from the projected KDexInternalHost + Page + Header/Footer/Navigation.
- Translations populate from the projected KDexInternalTranslations (with a logged warning that `kdex-default-translation` is absent).
- KDexRole/KDexRoleBinding are silently skipped.
- Errors reference the original user-facing CR by path + name (not the synthetic projected name).

---

## File structure (Phase 2.5 additions)

```
internal/preview/projector/
    projector.go              # Three pure projection functions + names helpers
    projector_test.go         # Behavioral tests against real-shape fixtures
    testdata/                 # Single-fixture tests
        host.yaml             # KDexHost with UtilityPages.{Announcement,Error,Login}Ref + TranslationRefs
        translation.yaml      # KDexTranslation (a partial — multiple in real life)
        utilitypage.yaml      # KDexUtilityPage (one per type in the test fixture set)

internal/preview/loader/
    loader.go                 # MODIFIED: load user-facing kinds into buckets, project, expose only Internal* in Snapshot
    loader_test.go            # MODIFIED: gain projection-end-to-end tests
    testdata/userfacing/      # NEW SUBDIR
        host.yaml
        translation.yaml
        utilitypage.yaml

internal/preview/fakeclient/
    fakeclient.go             # MODIFIED: register page-composition kinds + add WithStatusSubresource entries

internal/preview/server/
    server.go                 # No code changes (Run path unchanged); maybe doc-comment update
    testdata/
        knowdrive-mini/       # NEW SUBDIR (Task C.9): minimized projection of real CR set for the e2e test
            host.yaml
            theme.yaml
            page_archetype.yaml
            page.yaml
            translation.yaml
            utility_page_login.yaml
            page_header.yaml
            page_footer.yaml
```

The `Snapshot` external shape DOES NOT CHANGE. New typed buckets (`userHosts`, `userTranslations`, `userUtilityPages`) are internal to the loader; the projector consumes them and the loader returns the same `Snapshot` callers already use.

---

## Task C.1: Loader internal restructure — buffer all docs before projection

The current loader's `decodeOne` appends directly to `snap.InternalHosts`/etc. as it walks. Projection requires all KDexUtilityPages + KDexTranslations to be in scope when projecting a KDexHost (to synthesize the ref lists). Split the decode pass from the materialization pass.

**Files:**
- Modify: `internal/preview/loader/loader.go`

- [ ] **Step 1: Refactor `decodeOne` to write into a `rawBuckets` struct, not Snapshot**

Replace the current single-pass decode with two phases. Add a private struct:

```go
// rawBuckets holds all decoded CRs separated by kind. This is the loader's
// internal model; projection runs against this before the final Snapshot is
// returned. User-facing kinds (KDexHost, KDexTranslation, KDexUtilityPage)
// have their own buckets; the projector translates them into the post-reconcile
// kinds that downstream consumers expect.
type rawBuckets struct {
	// Post-reconcile kinds (passed through unchanged)
	internalHosts          []kdexv1alpha1.KDexInternalHost
	internalTranslations   []kdexv1alpha1.KDexInternalTranslation
	internalUtilityPages   []kdexv1alpha1.KDexInternalUtilityPage
	clusterPageArchetypes  []kdexv1alpha1.KDexClusterPageArchetype

	// Direct-consumption kinds (loader passes them through; host-manager
	// reconcilers consume them at fakeclient seed time)
	themes    []kdexv1alpha1.KDexTheme
	pages     []kdexv1alpha1.KDexPage
	apps      []kdexv1alpha1.KDexApp
	functions []kdexv1alpha1.KDexFunction

	// User-facing kinds (projected to Internal* in Task C.5)
	userHosts          []kdexv1alpha1.KDexHost
	userTranslations   []kdexv1alpha1.KDexTranslation
	userUtilityPages   []kdexv1alpha1.KDexUtilityPage
	userPageArchetypes []kdexv1alpha1.KDexPageArchetype // not projected (different shape), seeded as-is

	// Page-composition kinds (Task C.6 wires these into the loader)
	pageHeaders        []kdexv1alpha1.KDexPageHeader
	pageFooters        []kdexv1alpha1.KDexPageFooter
	pageNavigations    []kdexv1alpha1.KDexPageNavigation
	scriptLibraries    []kdexv1alpha1.KDexScriptLibrary
	clusterPageHeaders     []kdexv1alpha1.KDexClusterPageHeader
	clusterPageFooters     []kdexv1alpha1.KDexClusterPageFooter
	clusterPageNavigations []kdexv1alpha1.KDexClusterPageNavigation
	clusterScriptLibraries []kdexv1alpha1.KDexClusterScriptLibrary
}
```

(If kdex-crds doesn't expose all these types under `kdexv1alpha1`, comment out the unsupported ones and note the gap. Verify by `grep -h "^type KDex" /home/rotty/projects/kdex/workspace/kdex-crds/api/v1alpha1/*.go | sort -u` before adding to this struct.)

Replace `decodeOne` to populate `*rawBuckets` for the kinds already in scope (InternalHost, Theme, Page, App, Function, InternalTranslation, InternalUtilityPage, ClusterPageArchetype). Remove the error-cases for KDexHost et al. — those land in Task C.5 once projection exists.

Restructure `Load(dir)` so it:

```go
func Load(dir string) (*Snapshot, error) {
	// (existing dir validation)
	buckets := &rawBuckets{}
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		// (existing walk logic, but call decodeOne(path, docIdx, doc, buckets))
	})
	if err != nil {
		return nil, err
	}
	// Task C.5 wires projection here:
	// projected, err := projector.Project(buckets)
	// if err != nil { return nil, err }
	// Materialize Snapshot from buckets (and later from projected).
	return materializeSnapshot(buckets), nil
}

// materializeSnapshot copies the post-reconcile slices from buckets into the
// public Snapshot type. The projection step (added in Task C.5) populates the
// buckets' Internal* fields before this is called.
func materializeSnapshot(b *rawBuckets) *Snapshot {
	return &Snapshot{
		InternalHosts:          b.internalHosts,
		Themes:                 b.themes,
		Pages:                  b.pages,
		Apps:                   b.apps,
		Functions:              b.functions,
		InternalTranslations:   b.internalTranslations,
		InternalUtilityPages:   b.internalUtilityPages,
		ClusterPageArchetypes:  b.clusterPageArchetypes,
	}
}
```

- [ ] **Step 2: Update `decodeOne`'s switch to accept user-facing kinds without erroring**

Remove the `KDexHost, KDexTranslation, KDexUtilityPage, KDexPageArchetype` case that errors. Replace it with bucket appends:

```go
case "KDexHost":
	var obj kdexv1alpha1.KDexHost
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
	}
	b.userHosts = append(b.userHosts, obj)
case "KDexTranslation":
	var obj kdexv1alpha1.KDexTranslation
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
	}
	b.userTranslations = append(b.userTranslations, obj)
case "KDexUtilityPage":
	var obj kdexv1alpha1.KDexUtilityPage
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
	}
	b.userUtilityPages = append(b.userUtilityPages, obj)
case "KDexPageArchetype":
	var obj kdexv1alpha1.KDexPageArchetype
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
	}
	b.userPageArchetypes = append(b.userPageArchetypes, obj)
```

Keep the page-composition kinds error case for now — Task C.6 wires those.

Keep the silent-skip default for KDexRole/KDexRoleBinding/etc.

- [ ] **Step 3: Run existing tests — they should still pass**

```bash
go test ./internal/preview/loader/ -v
```

The 4 existing tests (`TestLoad_FlatDir_SingleFilePerCR`, `TestLoad_MultiDocYaml`, `TestLoad_RejectsInvalidYAML`, `TestLoad_RejectsUserFacingHostWithGuidance`) should still pass — but wait: `TestLoad_RejectsUserFacingHostWithGuidance` will now FAIL because KDexHost no longer errors.

- [ ] **Step 4: Update `TestLoad_RejectsUserFacingHostWithGuidance`**

Rename it to `TestLoad_AcceptsUserFacingHostIntoBuckets`. The assertion is no longer that the load errors — it's that the host gets into the user buckets. Since `rawBuckets` is unexported, the assertion has to be indirect. For now, assert `len(snap.InternalHosts) == 0` (because Task C.5's projection isn't wired yet — this becomes the spec-compliant assertion after C.5):

```go
func TestLoad_UserFacingHost_AwaitsProjection(t *testing.T) {
	dir := t.TempDir()
	hostYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  routing:
    domains: [example.local]
`)
	if err := os.WriteFile(filepath.Join(dir, "host.yaml"), hostYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Pre-projection: KDexHost is loaded into the user bucket but not yet
	// projected to InternalHost. Task C.5 wires the projection.
	if got, want := len(snap.InternalHosts), 0; got != want {
		t.Errorf("InternalHosts before projection wired: got %d want %d", got, want)
	}
}
```

(This test will get updated again in Task C.5 to assert non-zero InternalHosts.)

- [ ] **Step 5: Run all loader tests**

```bash
go test ./internal/preview/loader/ -v
go vet ./internal/preview/loader/
golangci-lint run ./internal/preview/loader/...
go build ./...
```

All clean.

- [ ] **Step 6: Commit**

```bash
git add internal/preview/loader/loader.go internal/preview/loader/loader_test.go
git commit -m "preview: loader restructure to buffer raw buckets (pre-projection)"
```

---

## Task C.2: Projector package — KDexHost → KDexInternalHost

Pure projection function matching `nexus-manager/internal/controller/kdexhost_controller.go:651-736`. No I/O, no controller-runtime.

**Files:**
- Create: `internal/preview/projector/projector.go`
- Create: `internal/preview/projector/projector_test.go`

- [ ] **Step 1: Write the failing test**

`internal/preview/projector/projector_test.go`:

```go
package projector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestProjectHost_CopiesSpecVerbatim(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "Test Brand",
			Organization: "Test Org",
			ModulePolicy: kdexv1alpha1.ModulePolicyAllowAll,
			Routing: kdexv1alpha1.RoutingSpec{
				Domains: []string{"test.local"},
			},
		},
	}

	got, err := ProjectHost(host, ProjectInput{})
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Name != "h1" || got.Namespace != "ns1" {
		t.Errorf("Name/Namespace: got %s/%s want h1/ns1", got.Name, got.Namespace)
	}
	if got.Spec.KDexHostSpec.BrandName != "Test Brand" {
		t.Errorf("BrandName not copied")
	}
}

func TestProjectHost_SynthesizesUtilityPageRefs(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.ModulePolicyAllowAll,
			Routing:      kdexv1alpha1.RoutingSpec{Domains: []string{"x"}},
			UtilityPages: &kdexv1alpha1.UtilityPagesSpec{
				LoginRef:        &kdexv1alpha1.KDexObjectReference{Name: "my-login"},
				ErrorRef:        &kdexv1alpha1.KDexObjectReference{Name: "my-error"},
				AnnouncementRef: &kdexv1alpha1.KDexObjectReference{Name: "my-announce"},
			},
		},
	}
	in := ProjectInput{
		UtilityPages: []kdexv1alpha1.KDexUtilityPage{
			{ObjectMeta: metav1.ObjectMeta{Name: "my-login", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.UtilityPageTypeLogin}},
			{ObjectMeta: metav1.ObjectMeta{Name: "my-error", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.UtilityPageTypeError}},
			{ObjectMeta: metav1.ObjectMeta{Name: "my-announce", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.UtilityPageTypeAnnouncement}},
		},
	}

	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Spec.LoginRef == nil || got.Spec.LoginRef.Name != "h1-login" {
		t.Errorf("LoginRef: got %+v want LocalObjectReference{Name: h1-login}", got.Spec.LoginRef)
	}
	if got.Spec.ErrorRef == nil || got.Spec.ErrorRef.Name != "h1-error" {
		t.Errorf("ErrorRef: got %+v", got.Spec.ErrorRef)
	}
	if got.Spec.AnnouncementRef == nil || got.Spec.AnnouncementRef.Name != "h1-announcement" {
		t.Errorf("AnnouncementRef: got %+v", got.Spec.AnnouncementRef)
	}
}

func TestProjectHost_SynthesizesTranslationRefs(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.ModulePolicyAllowAll,
			Routing:      kdexv1alpha1.RoutingSpec{Domains: []string{"x"}},
			TranslationRefs: []kdexv1alpha1.KDexObjectReference{
				{Name: "tr-en"},
				{Name: "tr-fr"},
			},
		},
	}
	in := ProjectInput{
		Translations: []kdexv1alpha1.KDexTranslation{
			{ObjectMeta: metav1.ObjectMeta{Name: "tr-en", Namespace: "ns1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "tr-fr", Namespace: "ns1"}},
		},
	}
	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	want := []corev1.LocalObjectReference{
		{Name: "h1-tr-en"},
		{Name: "h1-tr-fr"},
	}
	if len(got.Spec.InternalTranslationRefs) != len(want) {
		t.Fatalf("InternalTranslationRefs len: got %d want %d", len(got.Spec.InternalTranslationRefs), len(want))
	}
	for i, r := range got.Spec.InternalTranslationRefs {
		if r.Name != want[i].Name {
			t.Errorf("InternalTranslationRefs[%d]: got %q want %q", i, r.Name, want[i].Name)
		}
	}
}

func TestProjectHost_MissingUtilityPageRef_SkipsWithWarning(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.ModulePolicyAllowAll,
			Routing:      kdexv1alpha1.RoutingSpec{Domains: []string{"x"}},
			UtilityPages: &kdexv1alpha1.UtilityPagesSpec{
				LoginRef: &kdexv1alpha1.KDexObjectReference{Name: "missing-login"},
			},
		},
	}
	in := ProjectInput{} // no UtilityPages

	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Spec.LoginRef != nil {
		t.Errorf("LoginRef should be nil when source missing; got %+v", got.Spec.LoginRef)
	}
	if len(got.Warnings) == 0 || !contains(got.Warnings, "missing-login") {
		t.Errorf("expected warning naming missing-login; got: %v", got.Warnings)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s != "" && (s == needle || strings.Contains(s, needle)) {
			return true
		}
	}
	return false
}
```

Add `import "strings"` to the test file.

- [ ] **Step 2: Run test to verify it fails (compile errors)**

```bash
go test ./internal/preview/projector/ -v
```

Expected: FAIL — `ProjectHost`, `ProjectInput`, `ProjectedHost` undefined.

- [ ] **Step 3: Write `internal/preview/projector/projector.go`** (initial — just the host projection)

```go
// Package projector replicates nexus-manager's user-facing-CR → Internal*-CR
// projection in-process, so kdex preview can consume a real cluster's CR set
// directly. Three projections are implemented matching nexus-manager source:
//
//   KDexHost         → KDexInternalHost          (kdexhost_controller.go:651-736)
//   KDexTranslation  → KDexInternalTranslation   (kdexhost_controller_util.go:36-112)
//   KDexUtilityPage  → KDexInternalUtilityPage   (kdexhost_controller_util.go:114-181)
//
// Projections are pure functions over CR specs — no API server, no controller
// runtime, no OwnerReferences (preview has no apiserver to attach to).
//
// Out of scope (documented limitations):
//   - kdex-default-translation auto-injection (per-host, in nexus-manager)
//   - Default utility-page short-circuit names (require webhook constants)
//   - CreationTimestamp-ordered archetype defaulting (Phase 3 task)
package projector

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// ProjectInput collects all CRs the host projection needs to look up.
// Translations and UtilityPages are walked to validate the host's *Ref fields;
// missing refs produce warnings, not errors.
type ProjectInput struct {
	UtilityPages []kdexv1alpha1.KDexUtilityPage
	Translations []kdexv1alpha1.KDexTranslation
}

// ProjectedHost bundles the resulting KDexInternalHost with non-fatal warnings
// emitted during projection.
type ProjectedHost struct {
	Host     kdexv1alpha1.KDexInternalHost
	Warnings []string
}

// ProjectHost replicates nexus-manager's createOrUpdateInternalHostResource
// (kdexhost_controller.go:651-736). The resulting InternalHost has the same
// name + namespace as the source; spec is inlined verbatim; UtilityPages refs
// and TranslationRefs synthesize the Internal* ref fields.
func ProjectHost(host kdexv1alpha1.KDexHost, in ProjectInput) (ProjectedHost, error) {
	out := kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{
			Name:        host.Name,
			Namespace:   host.Namespace,
			Labels:      copyLabels(host.Labels, host.Name),
			Annotations: copyAnnotations(host.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: *host.Spec.DeepCopy(),
		},
	}

	pr := ProjectedHost{Host: out}

	// Synthesize utility-page refs.
	if host.Spec.UtilityPages != nil {
		if ref := host.Spec.UtilityPages.LoginRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: LoginRef %q not found in loaded CR set; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Host.Spec.LoginRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "login")}
			}
		}
		if ref := host.Spec.UtilityPages.ErrorRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: ErrorRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Host.Spec.ErrorRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "error")}
			}
		}
		if ref := host.Spec.UtilityPages.AnnouncementRef; ref != nil {
			if !lookupUtilityPage(in.UtilityPages, ref.Name, host.Namespace) {
				pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: AnnouncementRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			} else {
				pr.Host.Spec.AnnouncementRef = &corev1.LocalObjectReference{Name: utilityPageProjectedName(host.Name, "announcement")}
			}
		}
	}

	// Synthesize translation refs.
	for _, ref := range host.Spec.TranslationRefs {
		if !lookupTranslation(in.Translations, ref.Name, host.Namespace) {
			pr.Warnings = append(pr.Warnings, fmt.Sprintf("host %s/%s: TranslationRef %q not found; skipping", host.Namespace, host.Name, ref.Name))
			continue
		}
		pr.Host.Spec.InternalTranslationRefs = append(pr.Host.Spec.InternalTranslationRefs,
			corev1.LocalObjectReference{Name: translationProjectedName(host.Name, ref.Name)})
	}

	return pr, nil
}

// translationProjectedName returns the InternalTranslation name nexus-manager
// generates: "<host>-<source>". Matches kdexhost_controller_util.go:43.
func translationProjectedName(hostName, translationName string) string {
	return hostName + "-" + translationName
}

// utilityPageProjectedName returns the InternalUtilityPage name:
// "<host>-<lowercase-type>". Matches kdexhost_controller_util.go:121.
func utilityPageProjectedName(hostName, pageType string) string {
	return hostName + "-" + strings.ToLower(pageType)
}

func lookupUtilityPage(pages []kdexv1alpha1.KDexUtilityPage, name, namespace string) bool {
	for i := range pages {
		if pages[i].Name == name && pages[i].Namespace == namespace {
			return true
		}
	}
	return false
}

func lookupTranslation(translations []kdexv1alpha1.KDexTranslation, name, namespace string) bool {
	for i := range translations {
		if translations[i].Name == name && translations[i].Namespace == namespace {
			return true
		}
	}
	return false
}

// copyLabels copies the source labels and adds the nexus-manager standard
// labels (app.kubernetes.io/name, kdex.dev/instance). The `generation` label
// is not synthesized — preview has no real generation tracking.
func copyLabels(src map[string]string, hostName string) map[string]string {
	out := map[string]string{
		"app.kubernetes.io/name": "kdex-host",
		"kdex.dev/instance":      hostName,
	}
	for k, v := range src {
		out[k] = v
	}
	return out
}

func copyAnnotations(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
```

- [ ] **Step 4: Run tests, verify all 4 pass**

```bash
go test ./internal/preview/projector/ -v
```

- [ ] **Step 5: Verify vet + build + lint**

```bash
go vet ./internal/preview/projector/
golangci-lint run ./internal/preview/projector/...
go build ./...
```

- [ ] **Step 6: Commit**

```bash
git add internal/preview/projector/projector.go internal/preview/projector/projector_test.go
git commit -m "preview/projector: KDexHost → KDexInternalHost projection"
```

---

## Task C.3: Projector — KDexTranslation → KDexInternalTranslation

Replicates `nexus-manager/internal/controller/kdexhost_controller_util.go:36-112`.

**Files:**
- Modify: `internal/preview/projector/projector.go`
- Modify: `internal/preview/projector/projector_test.go`

- [ ] **Step 1: Add the failing test**

Append to `projector_test.go`:

```go
func TestProjectTranslation_NamesAndHostRef(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
	}
	tr := kdexv1alpha1.KDexTranslation{
		ObjectMeta: metav1.ObjectMeta{Name: "tr-en", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexTranslationSpec{
			Locale: "en",
			Values: map[string]string{"hello": "Hello"},
		},
	}
	got := ProjectTranslation(tr, host)
	if got.Name != "h1-tr-en" {
		t.Errorf("Name: got %q want %q", got.Name, "h1-tr-en")
	}
	if got.Namespace != "ns1" {
		t.Errorf("Namespace: got %q want %q", got.Namespace, "ns1")
	}
	if got.Spec.HostRef.Name != "h1" {
		t.Errorf("HostRef.Name: got %q want h1", got.Spec.HostRef.Name)
	}
	if got.Spec.Locale != "en" {
		t.Errorf("Spec.Locale not copied")
	}
	if got.Spec.Values["hello"] != "Hello" {
		t.Errorf("Spec.Values not copied")
	}
}
```

- [ ] **Step 2: Verify failure**

```bash
go test ./internal/preview/projector/ -v -run TestProjectTranslation
```

Expected: FAIL — `ProjectTranslation` undefined.

- [ ] **Step 3: Add `ProjectTranslation` to `projector.go`**

```go
// ProjectTranslation replicates nexus-manager's createOrUpdateInternalTranslation
// (kdexhost_controller_util.go:36-112). Name is "<host>-<source>", namespace is
// the host's namespace (even if the source was a cluster-scoped translation in
// nexus-manager — preview consolidates everything into the host's namespace).
func ProjectTranslation(tr kdexv1alpha1.KDexTranslation, host kdexv1alpha1.KDexHost) kdexv1alpha1.KDexInternalTranslation {
	return kdexv1alpha1.KDexInternalTranslation{
		ObjectMeta: metav1.ObjectMeta{
			Name:        translationProjectedName(host.Name, tr.Name),
			Namespace:   host.Namespace,
			Labels:      copyLabels(tr.Labels, host.Name),
			Annotations: copyAnnotations(tr.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalTranslationSpec{
			KDexTranslationSpec: *tr.Spec.DeepCopy(),
			HostRef:             corev1.LocalObjectReference{Name: host.Name},
		},
	}
}
```

- [ ] **Step 4: Verify all 5 tests pass**

```bash
go test ./internal/preview/projector/ -v
go vet ./internal/preview/projector/
golangci-lint run ./internal/preview/projector/...
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/preview/projector/
git commit -m "preview/projector: KDexTranslation → KDexInternalTranslation"
```

---

## Task C.4: Projector — KDexUtilityPage → KDexInternalUtilityPage

Replicates `nexus-manager/internal/controller/kdexhost_controller_util.go:114-181`.

**Files:**
- Modify: `internal/preview/projector/projector.go`
- Modify: `internal/preview/projector/projector_test.go`

- [ ] **Step 1: Add the failing test**

```go
func TestProjectUtilityPage_NamesAndHostRef(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
	}
	up := kdexv1alpha1.KDexUtilityPage{
		ObjectMeta: metav1.ObjectMeta{Name: "my-login", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexUtilityPageSpec{
			Type: kdexv1alpha1.UtilityPageTypeLogin,
		},
	}
	got := ProjectUtilityPage(up, host)
	if got.Name != "h1-login" {
		t.Errorf("Name: got %q want %q (host-lowercase-type, source name discarded)", got.Name, "h1-login")
	}
	if got.Namespace != "ns1" {
		t.Errorf("Namespace: got %q", got.Namespace)
	}
	if got.Spec.HostRef.Name != "h1" {
		t.Errorf("HostRef.Name: got %q", got.Spec.HostRef.Name)
	}
	if got.Spec.Type != kdexv1alpha1.UtilityPageTypeLogin {
		t.Errorf("Spec.Type not copied")
	}
}
```

- [ ] **Step 2: Verify failure**

```bash
go test ./internal/preview/projector/ -v -run TestProjectUtilityPage
```

- [ ] **Step 3: Add `ProjectUtilityPage`**

```go
// ProjectUtilityPage replicates nexus-manager's createOrUpdateInternalUtilityPage
// (kdexhost_controller_util.go:114-181). The output Name is "<host>-<lowercase-type>"
// — the source utility page's own name is discarded.
func ProjectUtilityPage(up kdexv1alpha1.KDexUtilityPage, host kdexv1alpha1.KDexHost) kdexv1alpha1.KDexInternalUtilityPage {
	return kdexv1alpha1.KDexInternalUtilityPage{
		ObjectMeta: metav1.ObjectMeta{
			Name:        utilityPageProjectedName(host.Name, string(up.Spec.Type)),
			Namespace:   host.Namespace,
			Labels:      copyLabels(up.Labels, host.Name),
			Annotations: copyAnnotations(up.Annotations),
		},
		Spec: kdexv1alpha1.KDexInternalUtilityPageSpec{
			KDexUtilityPageSpec: *up.Spec.DeepCopy(),
			HostRef:             corev1.LocalObjectReference{Name: host.Name},
		},
	}
}
```

- [ ] **Step 4: Verify all 6 tests pass + lint + build**

```bash
go test ./internal/preview/projector/ -v
go vet ./internal/preview/projector/
golangci-lint run ./internal/preview/projector/...
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/preview/projector/
git commit -m "preview/projector: KDexUtilityPage → KDexInternalUtilityPage"
```

---

## Task C.5: Loader integration — call projector on user-facing kinds

Wire the projector into the loader. After all docs are decoded into `rawBuckets`, walk every KDexHost, project it + its referenced UtilityPages + Translations.

**Files:**
- Modify: `internal/preview/loader/loader.go`
- Modify: `internal/preview/loader/loader_test.go`

- [ ] **Step 1: Add the projection call in `Load`**

In `Load`, after the WalkDir loop succeeds and before `materializeSnapshot`:

```go
if err := projectUserFacing(buckets); err != nil {
    return nil, fmt.Errorf("projection: %w", err)
}
```

Add the `projectUserFacing` helper:

```go
import (
	// existing imports
	"github.com/kdex-tech/host-manager/internal/preview/projector"
)

// projectUserFacing translates user-facing KDexHost/Translation/UtilityPage
// into the post-reconcile Internal* equivalents and appends them to the
// buckets. Warnings are logged to stderr.
func projectUserFacing(b *rawBuckets) error {
	for _, host := range b.userHosts {
		// Filter translations + utility pages by namespace (only those in the
		// host's namespace can be referenced by it).
		var hostNSTranslations []kdexv1alpha1.KDexTranslation
		for _, tr := range b.userTranslations {
			if tr.Namespace == host.Namespace {
				hostNSTranslations = append(hostNSTranslations, tr)
			}
		}
		var hostNSUtilityPages []kdexv1alpha1.KDexUtilityPage
		for _, up := range b.userUtilityPages {
			if up.Namespace == host.Namespace {
				hostNSUtilityPages = append(hostNSUtilityPages, up)
			}
		}

		ph, err := projector.ProjectHost(host, projector.ProjectInput{
			UtilityPages: hostNSUtilityPages,
			Translations: hostNSTranslations,
		})
		if err != nil {
			return fmt.Errorf("project host %s/%s: %w", host.Namespace, host.Name, err)
		}
		for _, w := range ph.Warnings {
			fmt.Fprintln(os.Stderr, "preview: projection warning:", w)
		}
		b.internalHosts = append(b.internalHosts, ph.Host)

		// Project each utility page referenced by this host.
		if host.Spec.UtilityPages != nil {
			projectUPRef(b, host, host.Spec.UtilityPages.LoginRef, hostNSUtilityPages)
			projectUPRef(b, host, host.Spec.UtilityPages.ErrorRef, hostNSUtilityPages)
			projectUPRef(b, host, host.Spec.UtilityPages.AnnouncementRef, hostNSUtilityPages)
		}

		// Project each translation referenced by this host.
		for _, ref := range host.Spec.TranslationRefs {
			for _, tr := range hostNSTranslations {
				if tr.Name == ref.Name {
					b.internalTranslations = append(b.internalTranslations, projector.ProjectTranslation(tr, host))
					break
				}
			}
		}
	}
	return nil
}

func projectUPRef(b *rawBuckets, host kdexv1alpha1.KDexHost, ref *kdexv1alpha1.KDexObjectReference, pages []kdexv1alpha1.KDexUtilityPage) {
	if ref == nil {
		return
	}
	for _, up := range pages {
		if up.Name == ref.Name {
			b.internalUtilityPages = append(b.internalUtilityPages, projector.ProjectUtilityPage(up, host))
			return
		}
	}
}
```

- [ ] **Step 2: Update the loader test to assert projection result**

Replace the `TestLoad_UserFacingHost_AwaitsProjection` test with:

```go
func TestLoad_UserFacingHost_ProjectsToInternal(t *testing.T) {
	dir := t.TempDir()
	hostYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  brandName: Test
  organization: Test
  modulePolicy: AllowAll
  routing:
    domains: [example.local]
`)
	if err := os.WriteFile(filepath.Join(dir, "host.yaml"), hostYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.InternalHosts), 1; got != want {
		t.Errorf("InternalHosts: got %d want %d", got, want)
	}
	if snap.InternalHosts[0].Name != "example" {
		t.Errorf("InternalHost name: got %q want example", snap.InternalHosts[0].Name)
	}
}

func TestLoad_UserFacingHostWithTranslation_ProjectsBoth(t *testing.T) {
	dir := t.TempDir()
	multiYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  brandName: Test
  organization: Test
  modulePolicy: AllowAll
  routing:
    domains: [example.local]
  translationRefs:
    - name: en
---
apiVersion: kdex.dev/v1alpha1
kind: KDexTranslation
metadata:
  name: en
  namespace: default
spec:
  locale: en
  values:
    hello: Hello
`)
	if err := os.WriteFile(filepath.Join(dir, "all.yaml"), multiYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.InternalHosts), 1; got != want {
		t.Errorf("InternalHosts: got %d want %d", got, want)
	}
	if got, want := len(snap.InternalTranslations), 1; got != want {
		t.Errorf("InternalTranslations: got %d want %d", got, want)
	}
	if snap.InternalTranslations[0].Name != "example-en" {
		t.Errorf("translation name: got %q want example-en", snap.InternalTranslations[0].Name)
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/preview/loader/ -v
go vet ./internal/preview/loader/
golangci-lint run ./internal/preview/loader/...
go build ./...
```

All clean.

- [ ] **Step 4: Commit**

```bash
git add internal/preview/loader/loader.go internal/preview/loader/loader_test.go
git commit -m "preview/loader: project user-facing KDex CRs at load time"
```

---

## Task C.6: Page-composition CRs in loader

Extend the loader to handle `KDexPageHeader`, `KDexPageFooter`, `KDexPageNavigation`, `KDexScriptLibrary`, and their cluster-scoped siblings. These have no projection — they're consumed directly by host-manager's page reconciler.

**Files:**
- Modify: `internal/preview/loader/loader.go` (add cases + extend Snapshot)
- Modify: `internal/preview/loader/loader_test.go`

- [ ] **Step 1: Extend `Snapshot` with new typed slices**

```go
type Snapshot struct {
	InternalHosts          []kdexv1alpha1.KDexInternalHost
	Themes                 []kdexv1alpha1.KDexTheme
	Pages                  []kdexv1alpha1.KDexPage
	Apps                   []kdexv1alpha1.KDexApp
	Functions              []kdexv1alpha1.KDexFunction
	InternalTranslations   []kdexv1alpha1.KDexInternalTranslation
	InternalUtilityPages   []kdexv1alpha1.KDexInternalUtilityPage
	ClusterPageArchetypes  []kdexv1alpha1.KDexClusterPageArchetype

	// NEW (Task C.6):
	PageArchetypes         []kdexv1alpha1.KDexPageArchetype   // independent kind, no projection
	PageHeaders            []kdexv1alpha1.KDexPageHeader
	PageFooters            []kdexv1alpha1.KDexPageFooter
	PageNavigations        []kdexv1alpha1.KDexPageNavigation
	ScriptLibraries        []kdexv1alpha1.KDexScriptLibrary
	ClusterPageHeaders     []kdexv1alpha1.KDexClusterPageHeader
	ClusterPageFooters     []kdexv1alpha1.KDexClusterPageFooter
	ClusterPageNavigations []kdexv1alpha1.KDexClusterPageNavigation
	ClusterScriptLibraries []kdexv1alpha1.KDexClusterScriptLibrary
}
```

Update `materializeSnapshot` and `rawBuckets` accordingly. (If the cluster-scoped variants don't exist in kdex-crds yet, comment out — verify with `grep -h "^type KDexCluster" /home/rotty/projects/kdex/workspace/kdex-crds/api/v1alpha1/*.go`.)

- [ ] **Step 2: Replace the error case in `decodeOne` for page-composition kinds with bucket appends**

```go
case "KDexPageHeader":
	var obj kdexv1alpha1.KDexPageHeader
	if err := yaml.Unmarshal(doc, &obj); err != nil {
		return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
	}
	b.pageHeaders = append(b.pageHeaders, obj)
case "KDexPageFooter":
	// ... mirror for Footer/Navigation/ScriptLibrary + cluster variants
```

Repeat for all 8 kinds (4 namespaced + 4 cluster-scoped).

- [ ] **Step 3: Add a behavioral test**

```go
func TestLoad_PageCompositionCRs_LoadIntoBuckets(t *testing.T) {
	dir := t.TempDir()
	yaml := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexPageHeader
metadata:
  name: header
  namespace: default
spec:
  content: "<header>X</header>"
---
apiVersion: kdex.dev/v1alpha1
kind: KDexPageFooter
metadata:
  name: footer
  namespace: default
spec:
  content: "<footer>Y</footer>"
`)
	if err := os.WriteFile(filepath.Join(dir, "comp.yaml"), yaml, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.PageHeaders), 1; got != want {
		t.Errorf("PageHeaders: got %d want %d", got, want)
	}
	if got, want := len(snap.PageFooters), 1; got != want {
		t.Errorf("PageFooters: got %d want %d", got, want)
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/preview/loader/ -v
golangci-lint run ./internal/preview/loader/...
go build ./...
```

All clean.

- [ ] **Step 5: Commit**

```bash
git add internal/preview/loader/loader.go internal/preview/loader/loader_test.go
git commit -m "preview/loader: support page-composition CRs (header/footer/navigation/scriptlibrary)"
```

---

## Task C.7: fakeclient — seed page-composition kinds into the fake client

The fakeclient currently seeds only the kinds Phase 2 supported. Extend it so host-manager's page reconciler can resolve the new kinds at reconcile time.

**Files:**
- Modify: `internal/preview/fakeclient/fakeclient.go`

- [ ] **Step 1: Extend `snapshotToObjects` to include the new kinds**

```go
for i := range snap.PageArchetypes {
    out = append(out, &snap.PageArchetypes[i])
}
for i := range snap.PageHeaders {
    out = append(out, &snap.PageHeaders[i])
}
for i := range snap.PageFooters {
    out = append(out, &snap.PageFooters[i])
}
for i := range snap.PageNavigations {
    out = append(out, &snap.PageNavigations[i])
}
for i := range snap.ScriptLibraries {
    out = append(out, &snap.ScriptLibraries[i])
}
for i := range snap.ClusterPageHeaders {
    out = append(out, &snap.ClusterPageHeaders[i])
}
for i := range snap.ClusterPageFooters {
    out = append(out, &snap.ClusterPageFooters[i])
}
for i := range snap.ClusterPageNavigations {
    out = append(out, &snap.ClusterPageNavigations[i])
}
for i := range snap.ClusterScriptLibraries {
    out = append(out, &snap.ClusterScriptLibraries[i])
}
```

- [ ] **Step 2: Extend `WithStatusSubresource` if needed**

Check each new kind's controller for `r.Status().Update()` calls. If present, add to the `WithStatusSubresource(...)` call. (Run `grep -l "r.Status().Update" /home/rotty/projects/kdex/workspace/kdex-host-manager/internal/controller/*.go` against the kind types to find which need it.)

- [ ] **Step 3: Verify existing tests still pass**

```bash
go test ./internal/preview/fakeclient/ -v
```

No new test required — Task C.9's e2e test exercises this code path against a real fixture.

- [ ] **Step 4: Verify build + lint**

```bash
go vet ./internal/preview/fakeclient/
golangci-lint run ./internal/preview/fakeclient/...
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add internal/preview/fakeclient/fakeclient.go
git commit -m "preview/fakeclient: seed page-composition kinds + status subresources"
```

---

## Task C.8: Stale doc + error-message cleanup

The current loader error message says "in-process projection is planned for Phase 3" — outdated after Task C.5 lands the projection. Update the message and the package doc.

**Files:**
- Modify: `internal/preview/loader/loader.go`

- [ ] **Step 1: Replace the obsolete error for the projection kinds**

The case `case "KDexHost", "KDexTranslation", "KDexUtilityPage", "KDexPageArchetype":` in `decodeOne` is now obsolete (Task C.1 removed it, Task C.5 made it work). Verify it's gone.

- [ ] **Step 2: Update package doc comment**

Update the loader's package comment to mention projection:

```go
// Package loader reads KDex CRs from a directory of YAML files and returns
// a typed Snapshot. Multi-doc YAML is supported. Subdirectories are walked
// recursively. Files not matching *.yaml or *.yml are ignored.
//
// User-facing CRs (KDexHost, KDexTranslation, KDexUtilityPage) are projected
// to their post-reconcile Internal* equivalents at load time via the
// internal/preview/projector package — preview consumes the same form as
// host-manager's in-cluster reconcilers. KDexPageArchetype and KDexClusterPageArchetype
// are independent kinds (no projection); both are seeded into the fake client.
//
// Kinds orthogonal to rendering (KDexRole, KDexRoleBinding) are silently ignored.
//
// Kustomize support is deferred to Phase 4.
```

- [ ] **Step 3: Lint + build**

```bash
go vet ./internal/preview/loader/
golangci-lint run ./internal/preview/loader/...
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add internal/preview/loader/loader.go
git commit -m "preview/loader: doc-comment update post-projection"
```

---

## Task C.9: End-to-end test against real cluster CR set

Add an e2e test that loads a realistic CR fixture set (modeled on the user's `knowdrive-site/k8s/dev/` shape) and verifies the page renders. This is the "is the real thing working?" smoke gate.

**Files:**
- Create: `internal/preview/server/testdata/knowdrive-mini/` (subdir with ~8 fixture files)
- Modify: `internal/preview/server/server_test.go` (add one new test)

- [ ] **Step 1: Create the fixture set**

Copy a representative subset of `/home/rotty/projects/RSI/knowdrive-site/k8s/dev/` files into `testdata/knowdrive-mini/`. Minimum:
- `host.yaml` (a KDexHost with brandName, organization, modulePolicy, routing.domains, plus a translationRef + utilityPages.loginRef)
- `theme.yaml` (a KDexTheme with at least one asset)
- `page_archetype.yaml` (a KDexPageArchetype OR KDexClusterPageArchetype)
- `page.yaml` (a KDexPage referencing the host + archetype)
- `translation.yaml` (a KDexTranslation matching the host's translationRef)
- `utility_page_login.yaml` (a KDexUtilityPage of type Login matching the host's loginRef)
- `page_header.yaml` (a KDexPageHeader referenced by the archetype)
- `page_footer.yaml` (a KDexPageFooter referenced by the archetype)

Each file should be the smallest valid form of the CR (the user-facing form, not post-reconcile). Use `kubectl get -o yaml` style minimal specs — drop status, drop annotations, drop labels except the ones nexus-manager requires.

If the user's k8s/dev fixtures have complex content not needed for the smoke test, simplify (e.g., a single-key translation, an empty page contentEntries array if the page reconciler allows).

- [ ] **Step 2: Write the test**

In `server_test.go`:

```go
func TestPreview_LoadsRealClusterCRShape(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real server")
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{CRsDir: "testdata/knowdrive-mini", Addr: addr})
	}()
	waitForServer(t, "http://"+addr+"/")

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) {
		t.Errorf("expected HTML; got: %s", body)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
```

- [ ] **Step 3: Run the test**

```bash
go test ./internal/preview/server/ -run TestPreview_LoadsRealClusterCRShape -v -timeout 60s
```

If it fails, common failure modes:
1. **Compile error in fixtures** — fix YAML structure against actual kdex-crds types.
2. **`projection: ...` error from Load** — translation/utility-page ref doesn't match: fix the names.
3. **Page reconciler runs but renders empty** — archetype not found or header/footer ref doesn't match: confirm Task C.7's fakeclient seeding wires the new kinds.
4. **400/404 on `/`** — page's `basePath` doesn't match `/`. Adjust the fixture.

Iterate until the test PASSES.

- [ ] **Step 4: Manual smoke against the user's REAL dev dir**

```bash
make build-kdex
./bin/kdex preview --crs /home/rotty/projects/RSI/knowdrive-site/k8s/dev --addr :18080 &
PID=$!
sleep 5
curl -s -o /dev/null -w "/=%{http_code}\n" http://localhost:18080/
kill $PID 2>/dev/null
wait $PID 2>/dev/null
```

If it returns 200, Phase 2.5 succeeded. If not, capture the error and triage (likely some unsupported CR kind, missing default-translation, or a real-CR field shape we haven't tested for).

- [ ] **Step 5: Commit**

```bash
git add internal/preview/server/testdata/knowdrive-mini/ internal/preview/server/server_test.go
git commit -m "preview: e2e test against real-shape cluster CR fixture set"
```

---

## Task C.10: Verification + documentation of limitations

Final gate: lint clean, full test suite green, manual smoke against the user's real dir, document the known limitations in the package comment.

- [ ] **Step 1: Full verification**

```bash
make lint
make test
```

Both PASS.

- [ ] **Step 2: Document limitations in the projector package**

Add to `internal/preview/projector/projector.go`'s package doc:

```go
// # Known limitations (vs. nexus-manager)
//
//   - kdex-default-translation auto-injection: nexus-manager silently appends a
//     hard-coded default translation to every host's TranslationRefs list
//     (kdexhost_controller_util.go:217-246). Preview does not. If your host
//     relies on default fallback values, copy the kdex-default-translation CR
//     into your --crs directory.
//
//   - Default utility-page short-circuit: nexus-manager recognizes magic names
//     like KDexDefaultUtilityPageLogin (from internal/webhook/) and lets hosts
//     reference them even when the CR doesn't exist. Preview requires the
//     referenced KDexUtilityPage to exist or emits a "not found; skipping"
//     warning and drops the ref.
//
//   - CreationTimestamp-ordered defaulting: ResolveOrDefaultPageArchetype in
//     host-manager prefers the oldest archetype labeled kdex.dev/default=true.
//     Preview can't reproduce timestamps; the fakeclient's default-archetype
//     injection uses a static fixture instead.
//
//   - Cluster-scoped ref resolution rules: nexus-manager's ResolveKDexObjectReference
//     (resolver_common.go:218-288) has subtle rules around cluster-vs-namespace
//     referrers. Preview implements only the common case (same-namespace + same-scope).
//     Edge cases (cluster referrer pointing at namespaced target) are not handled.
```

- [ ] **Step 3: Commit**

```bash
git add internal/preview/projector/projector.go
git commit -m "preview/projector: document limitations vs nexus-manager"
```

- [ ] **Step 4: Final manual smoke (no commit needed — just confirm)**

```bash
make build-kdex
./bin/kdex preview --crs /home/rotty/projects/RSI/knowdrive-site/k8s/dev --addr :18080 &
sleep 5
curl -s http://localhost:18080/ | head -20
kill %1 2>/dev/null
wait 2>/dev/null
```

Expected: composed HTML page from the user's actual cluster CRs.

---

## Conclusion

After Task C.10:

- `kdex preview --crs <real-cluster-CR-dir>` boots and renders against the user-facing CR form.
- nexus-manager's three projections (Host, Translation, UtilityPage) are replicated in-process.
- Page-composition CRs (Header/Footer/Navigation/ScriptLibrary) are seeded into the fake client; host-manager's existing page reconciler resolves them.
- Known limitations are documented in the projector package.

Next plan: Phase 3 (hot reload) — fsnotify watcher covering CRs + theme/app/fn paths, WS hub, JS shim, error overlay.

## Out-of-band notes

- **Verify kdex-crds type names before writing the rawBuckets struct.** Some kinds (esp. cluster-scoped variants like `KDexClusterPageHeader`) may not exist in the current kdex-crds version. The plan assumes they do; if any are missing, comment out the corresponding `decodeOne` case and Snapshot field and document the gap.
- **Synthetic default labels.** Task C.2's `copyLabels` always adds `app.kubernetes.io/name=kdex-host` and `kdex.dev/instance=<host>`. nexus-manager also adds `kdex.dev/generation=<gen>`; preview skips that since it has no real generation tracking. If host-manager's reconcilers gate on the generation label, projection won't satisfy them — flag as BLOCKED in Task C.5 if surfaced.
- **`go run`-style sub-modules.** The plan adds CRs to `testdata/` directories. Go's `testdata` convention causes `go build ./...` to skip them — no special handling needed, just keep fixtures under `testdata/`.
- **Lint cleanups during plan execution.** Per the Phase 2 pattern, expect 1-2 small `errcheck`/`gofmt` violations to surface during execution. Bundle them into a follow-up commit per the existing precedent.

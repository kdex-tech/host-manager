# Default Landing Paths Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `KDexHost` declare an ordered, entitlement-checked list of pages a caller is redirected to when the page gate denies the page they requested (chiefly: after login when a gated `/` isn't accessible to them), instead of landing on the arbitrary `firstAuthorizedPage`.

**Architecture:** One new optional CRD field, `KDexHost.spec.auth.defaultLandingPaths []string`, read directly from `hh.host.Auth` by host-manager. A new `discoverLandingPage` helper walks the list in order, returns the first entry the caller may render (checked with the same `VerifyResourceParsedEntitlements` the gate uses), and falls back to `firstAuthorizedPage` when the list is empty/unset or nothing matches. The existing discovery-redirect branch in `page.go` calls the helper instead of `firstAuthorizedPage`; nothing else changes (login flow, denial contract, language prefixing, `?denied=` one-hop guard all untouched).

**Tech Stack:** Go 1.26, kubebuilder/controller-gen (CRD markers + deepcopy), `github.com/kdex-tech/entitlements/go`, envtest-free httptest unit tests using the existing `internal/host` page fixtures.

**Spec:** `docs/superpowers/specs/2026-09-10-default-landing-paths-design.md` (host-manager)

## Global Constraints

- Go version is pinned to **1.26.0** across kdex-crds / kdex-host-manager / kdex-nexus-manager — do not change it.
- Resolution order is fixed: **`return` (if accessible) → `defaultLandingPaths[]` (first accessible) → `firstAuthorizedPage()` → 403.** `return` handling is NOT modified (an accessible `return` already renders on arrival); the list only participates in the deny path.
- Scope is **pages only** — the function/proxy identity gate is untouched.
- `defaultLandingPaths` unset or empty ⇒ behavior byte-identical to today.
- CRD validation stays **per-item** (bounded by item `MaxLength`). Never add a rule-level `XValidation` iterating the whole list — it makes the CRD fail to install via the apiserver cost estimator.
- A new CRD field is a serialization change ⇒ release **both** host-manager AND nexus-manager, and run each actor's `make test` (not just `go build`) before tagging.
- Never hand-edit the `replace kdex.dev/crds => …` directive to a local path. Cross-repo propagation goes through `./updateCrdUsage.sh`.
- host-manager code work lands on branch `feature/default-landing-paths` (already created off `main`).

---

### Task 1: kdex-crds — add `DefaultLandingPaths` field + validation + round-trip test

**Files:**
- Modify: `kdex-crds/api/v1alpha1/types.go` (the `Auth` struct, ~line 176)
- Create: `kdex-crds/api/v1alpha1/defaultlandingpaths_test.go`
- Regenerated (do not hand-edit): `kdex-crds/api/v1alpha1/zz_generated.deepcopy.go`, `kdex-crds/config/crd/bases/*.yaml`, `kdex-crds/CRD_REFERENCE.md`

**Interfaces:**
- Produces: `Auth.DefaultLandingPaths []string` (JSON `defaultLandingPaths`, omitempty). Read by Task 3 as `hh.host.Auth.DefaultLandingPaths`.

- [ ] **Step 1: Write the failing round-trip test**

Create `kdex-crds/api/v1alpha1/defaultlandingpaths_test.go`:

```go
package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuth_DefaultLandingPaths_OmittedWhenUnset(t *testing.T) {
	b, err := json.Marshal(Auth{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "defaultLandingPaths") {
		t.Fatalf("unset defaultLandingPaths must be omitted, got %s", b)
	}
}

func TestAuth_DefaultLandingPaths_RoundTrips(t *testing.T) {
	in := Auth{DefaultLandingPaths: []string{"/home", "/dashboard"}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Auth
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.DefaultLandingPaths) != 2 ||
		out.DefaultLandingPaths[0] != "/home" ||
		out.DefaultLandingPaths[1] != "/dashboard" {
		t.Fatalf("round-trip mismatch: %+v", out.DefaultLandingPaths)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run TestAuth_DefaultLandingPaths -v`
Expected: FAIL to compile — `Auth` has no field `DefaultLandingPaths`.

- [ ] **Step 3: Add the field to the `Auth` struct**

In `kdex-crds/api/v1alpha1/types.go`, inside `type Auth struct { … }`, add:

```go
	// defaultLandingPaths is an ordered list of page basePaths a caller is
	// redirected to after the page gate denies the page they requested — for
	// example a gated `/` after login when the caller lacks access to it. The
	// first entry the caller is entitled to render wins, checked exactly like
	// the page gate; entries the caller cannot reach, or that name no page, are
	// skipped. When the list is empty/unset or nothing matches, the host falls
	// back to the first authorized page in navigation order. Entries are
	// canonical basePaths ("/dashboard"); the language prefix is applied
	// automatically at redirect time.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=512
	// +kubebuilder:validation:items:Pattern=`^/.*`
	// +kubebuilder:validation:items:XValidation:rule="!self.startsWith('/-/')",message="defaultLandingPaths entries must not be under the reserved /-/ prefix"
	DefaultLandingPaths []string `json:"defaultLandingPaths,omitempty" protobuf:"bytes,11,rep,name=defaultLandingPaths"`
```

Note: protobuf field number 11 is the next unused-ish tag on `Auth` (existing tags in this struct are already duplicated and unused; 11 avoids collision with the real ones). If controller-gen (Step 5) rejects `items:XValidation` (older version), DROP that one marker only — the runtime skip in Task 3 covers a stray `/-/` entry; keep `MaxItems`, item `MaxLength`, and item `Pattern`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run TestAuth_DefaultLandingPaths -v`
Expected: PASS.

- [ ] **Step 5: Regenerate deepcopy, manifests, docs**

Run: `cd kdex-crds && make generate manifests docs`
Expected: `zz_generated.deepcopy.go` now copies `DefaultLandingPaths` in `Auth.DeepCopyInto`; `config/crd/bases/*kdexhost*.yaml` and `*kdexclusterhost*`/internal variants (any CRD embedding `Auth`) gain the `defaultLandingPaths` array schema with `maxItems: 16` and item `maxLength: 512` / `pattern: ^/.*`; `CRD_REFERENCE.md` documents the field.

- [ ] **Step 6: Full crds test + lint**

Run: `cd kdex-crds && make test lint`
Expected: PASS (envtest validates the regenerated CRD installs — this is where an accidental rule-level CEL or a bad pattern would fail; per-item validation must pass the cost estimator).

- [ ] **Step 7: Commit (on kdex-crds `main`)**

```bash
cd kdex-crds
git add api/v1alpha1/types.go api/v1alpha1/defaultlandingpaths_test.go \
        api/v1alpha1/zz_generated.deepcopy.go config/crd/bases CRD_REFERENCE.md
git commit -m "feat: KDexHost.spec.auth.defaultLandingPaths (ordered post-deny landing list)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Propagate the CRD tag and repin host-manager

**Files:**
- Modify (via script, then commit on feature branch): `kdex-host-manager/go.mod`, `kdex-host-manager/go.sum`
- Also touched by the script (left uncommitted): `kdex-nexus-manager/go.mod`, `kdex-nexus-manager/go.sum` — handled in Task 4.

**Interfaces:**
- Produces: host-manager's `kdex.dev/crds` pin advanced to the new tag, so Task 3 can compile against `Auth.DefaultLandingPaths`.

- [ ] **Step 1: Tag kdex-crds and repin consumers, without auto-committing consumers**

⚠️ This pushes kdex-crds `main` + a new tag to the remote — an outward action. Confirm before running in a real session.

Run: `cd <workspace-root> && ./updateCrdUsage.sh -t -n`
Expected: kdex-crds patch tag incremented and pushed; `make test lint docs` run in kdex-crds; `go.mod`/`go.sum` in host-manager AND nexus-manager updated to the new tag and **left in the working tree** (`--no-commit`). Note the new tag it prints (e.g. `v0.14.NNN`).

- [ ] **Step 2: Verify host-manager compiles against the new field**

Run: `cd kdex-host-manager && go build ./...`
Expected: builds. (Confirms the repin pulled the field.)

- [ ] **Step 3: Commit the repin on the feature branch**

```bash
cd kdex-host-manager
git checkout feature/default-landing-paths   # ensure we're on it
git add go.mod go.sum
git commit -m "build: repin kdex-crds for defaultLandingPaths field

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

Leave the nexus-manager `go.mod`/`go.sum` changes in that repo's working tree for Task 4.

---

### Task 3: host-manager — `discoverLandingPage` helper + wire into the page gate

**Files:**
- Modify: `kdex-host-manager/internal/host/navigation.go` (add helper next to `firstAuthorizedPage`)
- Modify: `kdex-host-manager/internal/host/page.go` (the discovery-redirect branch, ~line 148)
- Create: `kdex-host-manager/internal/host/landing_test.go`

**Interfaces:**
- Consumes: `Auth.DefaultLandingPaths []string` (Task 1); existing `hh.host *kdexv1alpha1.KDexHostSpec`, `hh.Pages.List() []page.PageHandler`, `page.PageHandler.BasePath() string`, `page.PageHandler.ParsedRequirements *entitlements.ParsedRequirements`, `hh.authChecker.VerifyResourceParsedEntitlements(kind, name string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, extra ...string) (bool, error)`, `hh.firstAuthorizedPage(ctx, *language.Tag, bool) string`, `hh.IsAuthEnabled() bool`.
- Produces: `(*HostHandler).discoverLandingPage(ctx context.Context, l *language.Tag, isDefaultLanguage bool, userEntitlements *entitlements.ParsedEntitlements) string` — returns a bare basePath (no language prefix).

- [ ] **Step 1: Write the failing tests**

Create `kdex-host-manager/internal/host/landing_test.go`:

```go
package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// denyPaths denies every listed basePath and allows the rest — a superset of
// denyPath (which denies exactly one). Used to model a caller who can reach
// some landing candidates but not others.
func denyPaths(basePaths ...string) *pageMockAuthChecker {
	denied := map[string]bool{}
	for _, p := range basePaths {
		denied[p] = true
	}
	return &pageMockAuthChecker{
		verifyFn: func(_ string, name string, _ entitlements.ParsedEntitlements, _ entitlements.ParsedRequirements, _ ...string) (bool, error) {
			return !denied[name], nil
		},
	}
}

// List order wins over navigation/alpha order: /home is listed first and is
// accessible, so it wins even though /dashboard sorts first alphabetically
// (which is what firstAuthorizedPage would have picked).
func TestDiscoverLanding_ListOrderBeatsNavOrder(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated,
		newPage("home", "Home", "/home"),
		newPage("dash", "Dash", "/dashboard"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home", "/dashboard"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/home?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /home (list order beats alpha-first /dashboard)", got)
	}
}

// The first list entry the caller cannot reach is skipped; the next accessible
// entry wins.
func TestDiscoverLanding_SkipsInaccessibleEntry(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated,
		newPage("home", "Home", "/home"),
		newPage("dash", "Dash", "/dashboard"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home", "/dashboard"}}
	hh.authChecker = denyPaths("/developer-keys", "/home")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/dashboard?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /dashboard (first accessible after skipping /home)", got)
	}
}

// An entry naming no existing page is skipped; with nothing left in the list
// the host falls back to firstAuthorizedPage.
func TestDiscoverLanding_UnknownEntryFallsBackToFirstAuthorized(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/nope"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want firstAuthorizedPage fallback /pricing", got)
	}
}

// Unset list ⇒ behavior identical to today (firstAuthorizedPage).
func TestDiscoverLanding_UnsetListUsesFirstAuthorized(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	// hh.host.Auth is nil (gatedHostFixture leaves it unset).
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want unchanged /pricing", got)
	}
}

// Scope boundary: in Forbid mode the list is never consulted; the caller gets
// a 403, same as today.
func TestDiscoverLanding_ForbidModeIgnoresList(t *testing.T) {
	gated := newPage("dk", "DK", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("home", "Home", "/home"))
	hh.host.Auth = &kdexv1alpha1.Auth{DefaultLandingPaths: []string{"/home"}}
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialForbid)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations, language.Make(hh.defaultLanguage))(
		w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (forbid mode never consults the list)", w.Code)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestDiscoverLanding -v`
Expected: FAIL — `discoverLandingPage` not defined (the tests exercise the gate, which will still call `firstAuthorizedPage` until Step 4). If the run errors on missing envtest assets rather than a compile/assert failure, run instead as `make test` (which sets `KUBEBUILDER_ASSETS`), or prefix with `KUBEBUILDER_ASSETS=$(bin/setup-envtest use -p path)`.

- [ ] **Step 3: Add the `discoverLandingPage` helper**

In `kdex-host-manager/internal/host/navigation.go`, add after `firstAuthorizedPage`:

```go
// discoverLandingPage picks where to send a caller the page gate denied. It
// honors the host's ordered spec.auth.defaultLandingPaths first — returning the
// first entry the caller is entitled to render, checked with the same
// VerifyResourceParsedEntitlements the gate uses — and falls back to
// firstAuthorizedPage when the list is empty/unset or nothing in it is
// reachable. The returned value is a bare basePath (no language prefix); the
// caller applies the /<lang> prefix, exactly as it does for firstAuthorizedPage.
// See docs/superpowers/specs/2026-09-10-default-landing-paths-design.md.
func (hh *HostHandler) discoverLandingPage(
	ctx context.Context,
	l *language.Tag,
	isDefaultLanguage bool,
	userEntitlements *entitlements.ParsedEntitlements,
) string {
	if hh.host != nil && hh.host.Auth != nil {
		for _, candidate := range hh.host.Auth.DefaultLandingPaths {
			for _, handler := range hh.Pages.List() {
				if handler.BasePath() != candidate {
					continue
				}
				// A page with requirements is a candidate only when the caller
				// satisfies them — the same check the gate runs. A checker
				// fault or a denial drops this candidate (try the next path); a
				// page with no requirements is reachable by everyone.
				if hh.IsAuthEnabled() && hh.authChecker != nil &&
					userEntitlements != nil && handler.ParsedRequirements != nil {
					access, err := hh.authChecker.VerifyResourceParsedEntitlements(
						"pages", candidate, *userEntitlements, *handler.ParsedRequirements)
					if err != nil || !access {
						break
					}
				}
				return candidate
			}
		}
	}
	return hh.firstAuthorizedPage(ctx, l, isDefaultLanguage)
}
```

(`context`, `entitlements`, and `language` are already imported in `navigation.go`.)

- [ ] **Step 4: Wire it into the discovery-redirect branch**

In `kdex-host-manager/internal/host/page.go`, in the `if outcome != denial.Unauthenticated && …` block, replace:

```go
					first := hh.firstAuthorizedPage(r.Context(), &l, l.String() == hh.defaultLanguage)
```

with:

```go
					first := hh.discoverLandingPage(r.Context(), &l, l.String() == hh.defaultLanguage, &parsedUserEntitlements)
```

Everything downstream (`if first != ""`, the `/<lang>` prefix, `?denied=`, `Cache-Control: no-store`, the `303`) stays exactly as is. `parsedUserEntitlements` is already in scope (derived at the top of the `if !authorized` block).

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestDiscoverLanding -v` (or `make test` if envtest assets are needed)
Expected: all five PASS.

- [ ] **Step 6: Run the full host package to confirm no regression**

Run: `cd kdex-host-manager && make test`
Expected: PASS — in particular the existing `TestPageGateDiscoverModeRedirectsHTMLWithDeniedMarker`, `TestPageGateAuthenticatedUnderEntitledGets403`, and the `#184` login-preference tests are unchanged.

- [ ] **Step 7: Lint**

Run: `cd kdex-host-manager && make lint`
Expected: 0 issues.

- [ ] **Step 8: Commit (feature branch)**

```bash
cd kdex-host-manager
git add internal/host/navigation.go internal/host/page.go internal/host/landing_test.go
git commit -m "feat: honor KDexHost defaultLandingPaths on page-gate denial

Walk spec.auth.defaultLandingPaths in order, redirect to the first entry the
caller may render (checked like the page gate), else fall back to
firstAuthorizedPage. Single call-site swap in page.go's discovery branch;
login flow, denial contract, and language prefixing unchanged.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: nexus-manager repin + release all three actors

**Files:**
- Modify (already changed by Task 2's script, now commit): `kdex-nexus-manager/go.mod`, `kdex-nexus-manager/go.sum`

**Interfaces:**
- Consumes: the new kdex-crds tag (Task 2) and the host-manager code (Task 3).
- Produces: released tags on host-manager and nexus-manager carrying the feature + the CRD schema.

- [ ] **Step 1: Verify nexus-manager still builds/tests against the new CRD**

Run: `cd kdex-nexus-manager && make test`
Expected: PASS. A validation-message or schema change can break tests that pin messages — this is why we run `make test`, not just `go build`. If nexus tests fail on the schema, fix before tagging.

- [ ] **Step 2: Commit the nexus repin**

```bash
cd kdex-nexus-manager
git add go.mod go.sum
git commit -m "build: repin kdex-crds for defaultLandingPaths field

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 3: Merge the host-manager feature branch to main (rebase + fast-forward)**

```bash
cd kdex-host-manager
git checkout main && git pull --ff-only
git checkout feature/default-landing-paths && git rebase main
git checkout main && git merge --ff-only feature/default-landing-paths
git log --merges main..feature/default-landing-paths   # must print nothing
```

- [ ] **Step 4: Release host-manager and nexus-manager**

⚠️ Outward actions (push main + tags to both remotes; CI publishes images). Confirm the exact version numbers and that this is wanted before pushing.

```bash
# host-manager — pick the next patch/minor per its tag convention (git tag | tail)
cd kdex-host-manager
git push origin main
git tag v<next> && git push origin v<next>

# nexus-manager
cd kdex-nexus-manager
git push origin main
git tag v<next> && git push origin v<next>
```

Expected: both CI runs green. Confirm with `gh run list --limit 3` in each repo.

- [ ] **Step 5: Verify the published CRD carries the field**

After the nexus/crds release is applied to a cluster (or by inspecting the generated manifest), confirm the `KDexHost` CRD schema exposes `spec.auth.defaultLandingPaths`. This closes the loop that the field is authorable.

---

## Self-Review

**1. Spec coverage:**
- Resolution order (`return` → list → firstAuthorizedPage → 403): Task 3 Step 4 keeps `return`/login untouched; helper returns list-then-fallback → covered.
- Single insertion point in `page.go`, login.go unchanged: Task 3 Step 4 → covered.
- Entitlement check identical to the gate: Task 3 Step 3 uses `VerifyResourceParsedEntitlements("pages", …)` → covered.
- CRD field + per-item validation, no whole-list CEL: Task 1 Step 3 → covered; item CEL has a documented drop-path.
- Scope: pages only, empty/unset unchanged, discover-mode only: tested in Task 3 (T4 unset, T5 forbid) → covered.
- Release both actors + `make test`: Tasks 2/4 → covered.
- Backward compatibility: T4 (unset ⇒ firstAuthorizedPage) → covered.

**2. Placeholder scan:** No TBD/TODO. `v<next>` in Task 4 is an intentional operator choice (release version), not a code placeholder; the tag convention command is given. `<workspace-root>` / `<ctx>` are path stand-ins with explicit instructions.

**3. Type consistency:** Helper name `discoverLandingPage` and signature match between Task 3 Step 3 (definition) and Step 4 (call site). `Auth.DefaultLandingPaths` matches between Task 1 (definition), Task 3 tests, and the helper. `VerifyResourceParsedEntitlements` signature matches the mock in `page_test.go` and the helper. `PageDenialDiscover`/`PageDenialForbid`/`SetPageDenialMode`, `authedReq`, `newPage`, `gatedHostFixture`, `denyPath` all exist in the current test package; `denyPaths` is newly defined in `landing_test.go`.

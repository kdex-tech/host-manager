# Text-serving KDexPages + enumerated l10n route prefixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a `KDexPage` serve a canonical root-level text file (robots.txt, llms.txt, sitemap.xml) at `200` with the right Content-Type, and replace the `/{l10n}` root-namespace wildcard with enumerated per-language prefixes so unknown roots return a clean `404` instead of `400`.

**Architecture:** Add three fields to `KDexPageSpec` (`localized`, `mimeType`, `body`). In host-manager, (B) register one literal language prefix per supported language instead of the `/{l10n}` wildcard, with the handler learning its language from the registration closure; (A) branch the page handler on `mimeType` to render `body` through the existing template+translation engine (no HTML chrome) and serve it with a mapped Content-Type at an exact path; (C) map a bad explicit `{l10n}` parameter to `400` not `500`.

**Tech Stack:** Go 1.26, kubebuilder/controller-runtime, Go 1.22 `http.ServeMux` pattern routing, `golang.org/x/text/language`, envtest.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-09-02-text-pages-and-enumerated-l10n-routing-design.md`

## Global Constraints

- Go pinned to **1.26.0** across kdex-crds / host-manager / nexus-manager (keep `go.mod`, Dockerfiles, CI aligned).
- **CRD schema change → release all actors:** after the `kdex-crds` change, run `./updateCrdUsage.sh -t` from the workspace root and release **both** host-manager and nexus-manager, even though nexus does not read the new fields.
- YAML indentation 2 spaces; one Kubernetes resource per file.
- Use `rg`, not `grep`. Commit inside the sub-repo where the change lives.
- `body` MUST stay bounded (`MaxLength=65536`) and any CEL rule MUST keep the CRD within the apiserver cost estimator — **only envtest catches an over-budget rule**, not decode tests.
- TDD throughout: failing test first, watch it fail, minimal implementation, watch it pass, commit.

---

## Phase 1 — `kdex-crds` schema

### Task 1.1: Add `localized`, `mimeType`, `body` to `KDexPageSpec` with validation

**Files:**
- Modify: `kdex-crds/api/v1alpha1/kdexpage_types.go` (the `KDexPageSpec` struct + its `contentEntries` field markers)
- Test: `kdex-crds/api/v1alpha1/kdexpage_types_test.go` (decode/validation unit test) and the envtest suite under `kdex-crds/internal/` if present; otherwise the controller envtest that installs the CRD

**Interfaces:**
- Produces: `KDexPageSpec.Localized *bool`, `KDexPageSpec.MimeType string`, `KDexPageSpec.Body string`. host-manager reads these as `pr.ph.Page.Localized`, `pr.ph.Page.MimeType`, `pr.ph.Page.Body`.

- [ ] **Step 1: Add the fields.** In `KDexPageSpec`, add:

```go
// localized controls whether language-prefixed routes (/<lang>/…) are
// registered for this page. Default true. Set false for a page that must live
// at exactly one path (robots.txt, llms.txt, sitemap.xml).
// +kubebuilder:default=true
// +kubebuilder:validation:Optional
Localized *bool `json:"localized,omitempty" protobuf:"varint,13,opt,name=localized"`

// mimeType, when set, serves the page as a raw text document of this type
// instead of composing HTML from an archetype.
// +kubebuilder:validation:Enum=txt;json;yaml;markdown;xml
// +kubebuilder:validation:Optional
MimeType string `json:"mimeType,omitempty" protobuf:"bytes,14,opt,name=mimeType"`

// body is the content served when mimeType is set. It runs through the same
// [[ ]] template + translation pipeline as a rawHTML content entry.
// +kubebuilder:validation:MaxLength=65536
// +kubebuilder:validation:Optional
Body string `json:"body,omitempty" protobuf:"bytes,15,opt,name=body"`
```

(Use the next free protobuf field numbers; `contentEntries`=1 … `scriptLibraryRef`=12, so 13/14/15.)

- [ ] **Step 2: Relax `contentEntries` and add cross-field CEL.** Change the `ContentEntries` field markers: drop `+kubebuilder:validation:Required` and `+kubebuilder:validation:MinItems=1`, keep it `+kubebuilder:validation:Optional` with `+kubebuilder:validation:MaxItems=32`. Move the "main slot" guarantee to spec-level CEL. On the `KDexPageSpec` type doc, add:

```go
// +kubebuilder:validation:XValidation:rule="has(self.mimeType) == has(self.body)",message="mimeType and body must be set together"
// +kubebuilder:validation:XValidation:rule="has(self.mimeType) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))",message="an HTML page (no mimeType) must declare contentEntries with a 'main' slot"
```

- [ ] **Step 3: Write the decode/validation unit test.** In `kdexpage_types_test.go`, add table cases asserting: (a) a text page `{mimeType: txt, body: "..."}` with no contentEntries is valid; (b) `mimeType` without `body` is rejected; (c) an HTML page with contentEntries lacking `main` is rejected; (d) `localized` defaults to a non-nil true after defaulting. (Follow the existing test style in that file; if it uses envtest apply for validation, put a/b/c there.)

- [ ] **Step 4: Run it to verify it fails.**

Run: `cd kdex-crds && go test ./api/v1alpha1/ -run TestKDexPage -v`
Expected: FAIL (fields/markers not yet regenerated into validation, or CEL not present).

- [ ] **Step 5: Regenerate.**

Run: `cd kdex-crds && make generate manifests`
This updates `zz_generated.deepcopy.go` (the `*bool` needs a deepcopy) and `config/crd/bases/kdex.dev_kdexpages.yaml`.

- [ ] **Step 6: Run tests + envtest to verify pass AND the CRD installs.**

Run: `cd kdex-crds && make test`
Expected: PASS, including the envtest that applies the CRD (proves the CEL rules are within the cost budget — a decode test alone would not).

- [ ] **Step 7: Commit.**

```bash
cd kdex-crds
git add api/v1alpha1/kdexpage_types.go api/v1alpha1/kdexpage_types_test.go api/v1alpha1/zz_generated.deepcopy.go config/crd/bases/kdex.dev_kdexpages.yaml
git commit -m "feat(api): KDexPage localized flag + text-serving (mimeType, body)"
```

### Task 1.2: Propagate the CRD tag to host-manager and nexus-manager

**Files:**
- Modify (via script): `kdex-nexus-manager/go.mod`, `kdex-nexus-manager/go.sum`, `kdex-host-manager/go.mod`, `kdex-host-manager/go.sum`

- [ ] **Step 1: Bump + propagate.**

Run from the workspace root: `./updateCrdUsage.sh -t`
This increments the kdex-crds patch tag, runs `make test lint install docs` in kdex-crds, commits & pushes the bump + tag, then updates `go.mod`/`go.sum` in host-manager and nexus-manager and pushes those to `main`.

- [ ] **Step 2: Verify host-manager sees the new fields.**

Run: `cd kdex-host-manager && go build ./... && rg -n "MimeType|Localized|Body" $(go list -m -f '{{.Dir}}' kdex.dev/crds)/api/v1alpha1/kdexpage_types.go`
Expected: build clean; the fields present in the resolved module.

> After Task 1.2, work in host-manager on the branch `feat/text-pages-enumerated-l10n` (already created; the spec commit is there). The go.mod bump lands on host-manager `main`; rebase the feature branch onto `main` before Phase 2: `git fetch origin && git rebase origin/main`.

---

## Phase 2 — host-manager: enumerated language prefixes (Track B)

### Task 2.1: Register one literal language prefix per supported language (replacing `/{l10n}`)

**Files:**
- Modify: `kdex-host-manager/internal/host/handlers.go` (`addHandlerAndRegister`, ~lines 48-165)
- Modify: `kdex-host-manager/internal/host/page.go` (`pageHandlerFunc`, line 20 — accept a language)
- Modify: `kdex-host-manager/internal/host/host.go` (the not-ready registration at ~line 369)
- Test: `kdex-host-manager/internal/host/handlers_test.go` (or a new `enumerated_l10n_test.go`)

**Interfaces:**
- Consumes: `hh.Translations.Languages() []language.Tag` (internal/host/types.go:230), `hh.defaultLanguage string`.
- Produces: `pageHandlerFunc(ph page.PageHandler, translations *Translations, lang language.Tag) http.HandlerFunc` — the handler now takes its language explicitly instead of calling `GetLang` on `{l10n}`.

- [ ] **Step 1: Write the failing test.** Assert the mux registers per-language literal prefixes and no `/{l10n}` wildcard. Using an in-test HostHandler with two supported languages (`en` default, `fr`) and a page `pricing`:

```go
func TestEnumeratedPrefixes_RegisterPerLanguage(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"}) // helper: sets Translations + defaultLanguage
	hh.registerPageForTest(t, "pricing", "/pricing")        // helper: runs addHandlerAndRegister
	mux := hh.currentMux(t)

	assertMatches(t, mux, "GET", "/pricing/", "GET /pricing/{$}")        // bare = default
	assertMatches(t, mux, "GET", "/fr/pricing/", "GET /fr/pricing/{$}")  // non-default prefix
	assertNoPattern(t, mux, "GET /{l10n}/pricing/{$}")                   // wildcard gone
	// unknown root falls through — no page/wildcard swallows it
	assertNotMatched(t, mux, "GET", "/robots.txt")
}
```

(If test helpers don't exist, add minimal ones next to the test: `assertMatches` uses `mux.Handler(httptest.NewRequest(...))` and compares the returned pattern; `assertNotMatched` asserts the returned pattern is empty / the not-found handler.)

- [ ] **Step 2: Run it to verify it fails.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestEnumeratedPrefixes -v`
Expected: FAIL — today `/{l10n}/pricing/{$}` is registered and `/fr/pricing/{$}` is not.

- [ ] **Step 3: Implement enumerated registration.** In `addHandlerAndRegister`, replace the two `/{l10n}`-prefixed `registerIfNew(...)` blocks (finalPath and patternPath) with a loop over `hh.Translations.Languages()`. For each `lang` that is **not** the default, register `GET /<lang.String()>` + finalPath (and patternPath) with a handler bound to that language; register the bare finalPath/patternPath with a handler bound to the default language. Build the handler per language: `handler := hh.pageHandlerFunc(pr.ph, translations, lang)`. Keep `regFunc` for OpenAPI registration, passing the concrete `lang.String()`. Do the same at the not-ready site in `host.go:369`.

- [ ] **Step 4: Update `pageHandlerFunc`.** Change its signature to accept `lang language.Tag` and use it directly instead of `l, err := GetLang(...)`. Remove the page-route `GetLang` call and its `400` branch (that class is now gone structurally — the language is known from the prefix). Keep the rest (gate, cache, render) intact.

- [ ] **Step 5: Run tests to verify pass.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestEnumeratedPrefixes -v`
Expected: PASS.

- [ ] **Step 6: Run the full host suite** to catch fallout in existing page/routing tests (many assert `/{l10n}` behavior and will need updating to the enumerated form).

Run: `cd kdex-host-manager && go test ./internal/host/...`
Expected: PASS after updating any test that asserted the old wildcard to assert the enumerated prefixes. Update those tests as part of this task (they are pinning the behavior we deliberately changed).

- [ ] **Step 7: Commit.**

```bash
git add internal/host/handlers.go internal/host/page.go internal/host/host.go internal/host/*_test.go
git commit -m "feat(host): enumerated per-language route prefixes, replacing the /{l10n} wildcard"
```

### Task 2.2: 301 the default-language prefix to the bare path

**Files:**
- Modify: `kdex-host-manager/internal/host/handlers.go` (registration) + a small redirect handler
- Test: `kdex-host-manager/internal/host/enumerated_l10n_test.go`

**Interfaces:**
- Consumes: `hh.defaultLanguage`.

- [ ] **Step 1: Write the failing test.**

```go
func TestDefaultLanguagePrefixRedirectsToBare(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")
	rr := doRequest(t, hh.currentMux(t), "GET", "/en/pricing/") // en == default
	require.Equal(t, http.StatusMovedPermanently, rr.Code)
	require.Equal(t, "/pricing/", rr.Header().Get("Location"))
}
```

- [ ] **Step 2: Run it to verify it fails.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestDefaultLanguagePrefixRedirectsToBare -v`
Expected: FAIL — the default prefix is currently not registered at all (Task 2.1 skipped it), so this 404s.

- [ ] **Step 3: Implement.** In the registration loop, for the **default** language register `GET /<default>` + finalPath (and patternPath) with a handler that `http.Redirect(w, r, <bare path>, http.StatusMovedPermanently)` — strip the `/<default>` prefix from `r.URL.Path` to build the target. Add a small `defaultLangRedirectHandler(barePath string) http.HandlerFunc`.

- [ ] **Step 4: Run to verify pass.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestDefaultLanguagePrefixRedirectsToBare -v`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/host/handlers.go internal/host/enumerated_l10n_test.go
git commit -m "feat(host): 301 the default-language prefix to the canonical bare path"
```

### Task 2.3: `localized:false` registers only the bare path

**Files:**
- Modify: `kdex-host-manager/internal/host/handlers.go`
- Test: `kdex-host-manager/internal/host/enumerated_l10n_test.go`

**Interfaces:**
- Consumes: `pr.ph.Page.Localized *bool` (nil OR *true ⇒ localized; *false ⇒ not).

- [ ] **Step 1: Write the failing test.**

```go
func TestLocalizedFalse_BareOnly(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withLocalizedFalse()) // helper sets Localized=&false
	mux := hh.currentMux(t)
	assertMatches(t, mux, "GET", "/robots.txt", "GET /robots.txt")   // exact (Task 3.3 gives this its no-slash form; here assert bare presence)
	assertNoPattern(t, mux, "GET /fr/robots.txt")                    // no localized twin
	assertNoPattern(t, mux, "GET /en/robots.txt")                    // no default prefix either
}
```

- [ ] **Step 2: Run to verify it fails.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestLocalizedFalse_BareOnly -v`
Expected: FAIL — the loop currently registers `/fr/...` regardless of `localized`.

- [ ] **Step 3: Implement.** Gate the per-language registrations (both non-default prefixes AND the default-language redirect) behind `isLocalized(pr.ph.Page.Localized)` where `func isLocalized(b *bool) bool { return b == nil || *b }`. When not localized, register only the bare path.

- [ ] **Step 4: Run to verify pass.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestLocalizedFalse_BareOnly -v`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/host/handlers.go internal/host/enumerated_l10n_test.go
git commit -m "feat(host): localized=false registers only the bare (unprefixed) route"
```

### Task 2.4: Unknown root returns a clean 404 (end-to-end guard)

**Files:**
- Test: `kdex-host-manager/internal/host/enumerated_l10n_test.go`

- [ ] **Step 1: Write the guard test** (this is the #137/#177 acceptance guard for unserved roots):

```go
func TestUnknownRootIs404NeverBadRequest(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	hh.registerPageForTest(t, "pricing", "/pricing")
	// no page for /robots.txt
	for _, p := range []string{"/robots.txt", "/sitemap.xml", "/xx/pricing"} {
		rr := doRequest(t, hh.fullHandler(t), "GET", p) // fullHandler = mux + not-found fallthrough
		require.NotEqual(t, http.StatusBadRequest, rr.Code, "%s must never be 400", p)
		require.Equal(t, http.StatusNotFound, rr.Code, "%s should be 404", p)
	}
}
```

- [ ] **Step 2: Run to verify.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestUnknownRootIs404 -v`
Expected: PASS (with Task 2.1 the wildcard is gone, so these fall through to the not-found handler). If any returns 400, trace the residual `/{l10n}` registration and remove it.

- [ ] **Step 3: Commit.**

```bash
git add internal/host/enumerated_l10n_test.go
git commit -m "test(host): unknown root paths return 404, never 400"
```

---

## Phase 3 — host-manager: text-serving KDexPage (Track A)

### Task 3.1: Text render + Content-Type serving

**Files:**
- Modify: `kdex-host-manager/internal/host/page.go` (`pageHandlerFunc` branch; `serveRendered` → parameterize, or add `serveText`)
- Modify: `kdex-host-manager/internal/host/host.go` (add `L10nRenderText` beside `L10nRender` at ~216, or a render mode)
- Create: `kdex-host-manager/internal/host/textpage.go` (Content-Type map + text render helper)
- Test: `kdex-host-manager/internal/host/textpage_test.go`

**Interfaces:**
- Consumes: `pr.ph.Page.MimeType`, `pr.ph.Page.Body`, the `[[ ]]` template + translation engine used by `L10nRender`.
- Produces: `func contentTypeFor(mime string) string`; `func (hh *HostHandler) L10nRenderText(ph page.PageHandler, lang language.Tag, translations *Translations) (string, error)`.

- [ ] **Step 1: Write the failing test — Content-Type map.**

```go
func TestContentTypeFor(t *testing.T) {
	cases := map[string]string{
		"txt":      "text/plain; charset=utf-8",
		"json":     "application/json",
		"yaml":     "application/yaml",
		"markdown": "text/markdown; charset=utf-8",
		"xml":      "application/xml",
	}
	for mime, want := range cases {
		require.Equal(t, want, contentTypeFor(mime), mime)
	}
}
```

- [ ] **Step 2: Run to verify fail.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestContentTypeFor -v`
Expected: FAIL — `contentTypeFor` undefined.

- [ ] **Step 3: Implement `contentTypeFor`** in `textpage.go` (a `switch` returning the table above; default `text/plain; charset=utf-8`).

- [ ] **Step 4: Run to verify pass.** Run the same command; Expected: PASS.

- [ ] **Step 5: Write the failing test — text render through translation, no chrome.**

```go
func TestL10nRenderText_TranslatesAndOmitsChrome(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en", "fr"})
	ph := textPageForTest(t, "llms", "/llms.txt", "txt",
		`KnowDrive — [[ t "tagline" ]]`) // body uses the l10n function
	// translations: en tagline="the knowledge engine"
	out, err := hh.L10nRenderText(ph, language.Make("en"), hh.Translations)
	require.NoError(t, err)
	require.Equal(t, "KnowDrive — the knowledge engine", out)
	require.NotContains(t, out, "<html", "text render must not wrap in archetype HTML")
}
```

(Match the actual template delimiter/function names the rawHTML path uses — inspect `L10nRender` / the template funcmap first; the `t`/translate function name may differ.)

- [ ] **Step 6: Run to verify fail.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestL10nRenderText -v`
Expected: FAIL — `L10nRenderText` undefined.

- [ ] **Step 7: Implement `L10nRenderText`.** Reuse the same template parsing + translation funcmap `L10nRender` builds, but execute only `ph.Page.Body` and return the raw string — no archetype/header/footer/nav. Factor the shared funcmap/translation setup out of `L10nRender` so both paths use it (DRY).

- [ ] **Step 8: Run to verify pass.** Expected: PASS.

- [ ] **Step 9: Branch `pageHandlerFunc` on `mimeType` and serve.** In the handler, after the gate + cache lookup, if `ph.Page.MimeType != ""` call `L10nRenderText` (cache the result under the same `(name, lang)` key) and serve via a `serveText(w, log, l, name, rendered, contentTypeFor(ph.Page.MimeType))` that sets `Content-Language` + the mapped `Content-Type`. Otherwise keep the existing HTML path. Add a handler-level test:

```go
func TestTextPage_ServesBodyWithContentType(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "User-agent: *\nAllow: /\n"), withLocalizedFalse())
	rr := doRequest(t, hh.fullHandler(t), "GET", "/robots.txt")
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "text/plain; charset=utf-8", rr.Header().Get("Content-Type"))
	require.Equal(t, "User-agent: *\nAllow: /\n", rr.Body.String())
}
```

- [ ] **Step 10: Run to verify** (this will still fail on the exact-path `307` until Task 3.2; it may 404/307 here). If it 307s, proceed to Task 3.2 which makes the exact path resolve, then this test passes. Note the dependency in the commit.

- [ ] **Step 11: Commit.**

```bash
git add internal/host/textpage.go internal/host/textpage_test.go internal/host/page.go internal/host/host.go
git commit -m "feat(host): render a text-mime KDexPage body via the l10n engine and serve with its Content-Type"
```

### Task 3.2: Exact-path registration for text pages (no trailing-slash 307)

**Files:**
- Modify: `kdex-host-manager/internal/host/handlers.go` (`addHandlerAndRegister` — choose exact vs `toFinalPath` by mimeType)
- Test: `kdex-host-manager/internal/host/textpage_test.go`

**Interfaces:**
- Consumes: `pr.ph.Page.MimeType`.

- [ ] **Step 1: Write the failing test.**

```go
func TestTextPage_ExactPathNoRedirect(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.registerPageForTest(t, "robots", "/robots.txt", withText("txt", "ok"), withLocalizedFalse())
	rr := doRequest(t, hh.fullHandler(t), "GET", "/robots.txt")
	require.Equal(t, http.StatusOK, rr.Code)        // NOT 307
	require.Empty(t, rr.Header().Get("Location"))
}
```

- [ ] **Step 2: Run to verify fail.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestTextPage_ExactPathNoRedirect -v`
Expected: FAIL with `307` → `/robots.txt/` (the `toFinalPath` `{$}` anchor).

- [ ] **Step 3: Implement.** In `addHandlerAndRegister`, compute the registration path per page kind: for a text page (`ph.Page.MimeType != ""`) register the **exact** basePath (`"GET " + basePath`, no `toFinalPath`); for an HTML page keep `toFinalPath(basePath)`. Apply the same to the per-language prefixed forms (`"GET /<lang>" + basePath` exact for text; `"/<lang>" + finalPath` for HTML).

- [ ] **Step 4: Run to verify pass** (Task 3.1's `TestTextPage_ServesBodyWithContentType` now also passes).

Run: `cd kdex-host-manager && go test ./internal/host/ -run 'TestTextPage' -v`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/host/handlers.go internal/host/textpage_test.go
git commit -m "feat(host): register text-mime pages at their exact path (no trailing-slash 307)"
```

---

## Phase 4 — host-manager: status vocabulary (Track C)

### Task 4.1: Navigation-fragment bad `{l10n}` → 400, not 500

**Files:**
- Modify: `kdex-host-manager/internal/host/navigation.go` (~lines 166-170)
- Test: `kdex-host-manager/internal/host/navigation_test.go`

- [ ] **Step 1: Write the failing test.**

```go
func TestNavigationBadLanguageIs400NotServerError(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	rr := doRequest(t, hh.fullHandler(t), "GET", "/-/navigation/main/not-a-lang/pricing")
	require.Equal(t, http.StatusBadRequest, rr.Code) // was 500
}
```

- [ ] **Step 2: Run to verify fail.**

Run: `cd kdex-host-manager && go test ./internal/host/ -run TestNavigationBadLanguage -v`
Expected: FAIL — currently `http.StatusInternalServerError`.

- [ ] **Step 3: Implement.** In `navigation.go`, change the `GetLang` error branch from `http.StatusInternalServerError` to `http.StatusBadRequest` (a caller-supplied `{l10n}` API parameter is a client error, never a server fault). Leave `/-/translation/{l10n}`'s existing `400` as-is.

- [ ] **Step 4: Run to verify pass.** Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add internal/host/navigation.go internal/host/navigation_test.go
git commit -m "fix(host): a bad {l10n} navigation parameter is a 400, not a 500"
```

---

## Phase 5 — release

### Task 5.1: Lint, full test, merge, release host-manager + nexus-manager

- [ ] **Step 1: Full lint + test from workspace root.**

Run: `cd /home/rotty/projects/kdex/workspace && make lint && make test`
Expected: 0 lint issues; all module tests pass.

- [ ] **Step 2: Merge the feature branch (rebase + ff-only).**

```bash
cd kdex-host-manager
git fetch origin && git rebase origin/main
git checkout main && git merge --ff-only feat/text-pages-enumerated-l10n
git log --merges origin/main..main --oneline   # must print nothing
git push origin main
```

- [ ] **Step 3: Tag host-manager and nexus-manager releases.** Cut a minor host-manager release (new feature + a behavior change: unknown roots 404, default prefix 301). Release nexus-manager too (schema-change rule — even though it does not read the new fields). Verify each artifact exists (`docker manifest inspect`, `helm show chart`), not inferred from green CI.

- [ ] **Step 4: Update the issues.** Comment on host-manager#197 and #177 with the shipped versions and the acceptance-criteria verification; note on GitLab knowdrive-site#137 (or its successor) that the platform capability shipped so the site can add its robots.txt/llms.txt pages.

---

## Self-review notes

- **Spec coverage:** Track A → Phase 1 (schema) + Phase 3 (serving); Track B → Phase 2; Track C → Phase 4; release/migration → Phase 5. Content-Type table → Task 3.1. Default-language 301 → Task 2.2. `localized` gate → Task 2.3. 404-not-400 acceptance → Task 2.4. CEL cost budget → Task 1.1 Step 6 (envtest).
- **Known executor caveats:** the exact template delimiter/translation-function name in Task 3.1 Step 5 must be read from `L10nRender`'s funcmap before writing the test (the `[[ t … ]]` form is illustrative). Test helpers (`newTestHostHandler`, `registerPageForTest`, `assertMatches`, `doRequest`, `withText`, `withLocalizedFalse`) are introduced in Task 2.1 and reused; if the existing suite already has equivalents, use those instead of adding duplicates.
- **Ordering:** Phase 1 must fully land (incl. Task 1.2 `updateCrdUsage.sh -t`) before Phase 2-4 can reference the new fields; rebase the feature branch onto host-manager `main` after Task 1.2.

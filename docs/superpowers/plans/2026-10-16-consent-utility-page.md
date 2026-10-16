# Themeable Consent Utility Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a host brand its DCR consent page with a `Consent` KDexUtilityPage, while host-manager keeps owning the disclosure, the form and the hold-back script, and no other script can run on the page.

**Architecture:** kdex-crds adds the `Consent` type, `consentRef`, a structural CEL rule and the shared consent message keys. nexus-manager resolves `consentRef` (defaulted on every host) into a `<host>-consent` internal page and bundles a default page and translations. host-manager renders a fixed consent block, embeds it in the Consent utility page through a scriptless render, verifies it appears exactly once via a per-render marker, sends a hash-locked CSP, and falls back to the built-in page on any failure.

**Tech Stack:** Go 1.26.0, controller-runtime/kubebuilder, envtest + Ginkgo (nexus, host-manager controllers), `html/template`, `golang.org/x/text/message`.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-10-16-consent-utility-page-design.md`

## Global Constraints

- Go 1.26.0 in every module; run `make lint` from the workspace root after each code task.
- Commit inside the sub-repo the change lives in, never at the workspace root.
- Never hand-edit the `replace kdex.dev/crds => …` directives; repin only with `./updateCrdUsage.sh`.
- Branded consent CSP, exactly: `default-src 'none'; script-src 'sha256-<hold-back script>'; style-src 'self' https: 'unsafe-inline'; font-src 'self' https: data:; img-src 'self' https: data:; base-uri 'none'`.
- The built-in page keeps the stage-1 policy: `default-src 'none'; script-src 'sha256-<hold-back script>'; style-src 'unsafe-inline'; frame-ancestors 'none'`.
- Flow headers (`no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `frame-ancestors 'none'`) stay as set in `oauth2_consent.go`; no `form-action`.
- Template data name: `.Extra.consent.Block`. The template never receives `ConsentView` or the sealed request.
- The block must appear in the rendered page exactly once (by marker); otherwise serve the built-in page and log an error naming the utility page.
- CEL rule (message verbatim): `self.type != 'Consent' || (!has(self.scriptLibraryRef) && self.contentEntries.all(e, !has(e.appRef)))` / "a Consent page cannot reference scripts: no scriptLibraryRef and no appRef content".
- Default page name: `kdex-default-utility-page-consent`; internal page name `<host>-consent`.
- The 14 `consent.*` keys and their English text are exactly the spec's table.
- YAML: 2-space indent, one resource per file.
- **No push, tag or release without the user's explicit go-ahead at that step** (Tasks 2 and 7).

**Deviation from the spec, decided here:** the spec puts the English fallbacks in host-manager and checks nexus's translation "against a key list". nexus cannot import host-manager, so the key list and English text live once in kdex-crds (`render.ConsentMessages`), which both actors already import. host-manager's fallback and nexus's translation test both read it. The spec's "envtest in kdex-crds" becomes envtest in nexus-manager's controller suite: kdex-crds has no envtest, and nexus's suite installs the kdex-crds CRDs from the pinned module.

## Review Focus

1. **A language with partial or no `consent.*` keys** (a host translation for `ja`, or an operator's `fr` override missing `consent.warning`): each missing key shows its English text, never the raw key. Test in Task 5.
2. **A client name or account containing `%s`, `%!`, `<b>` or `&`**: rendered literally and escaped; no format verb in an argument is ever interpreted. Test in Task 5.
3. **An operator translation containing HTML** (`consent.warning: "<b>Careful</b>"`): shown as literal text, not markup. Test in Task 5.
4. **The consent page requested while the host is reconciling** (Consent utility page not yet indexed, or removed): the built-in page, never a 404 or blank page; and rendering under a concurrent `SetHost` is race-free. Test in Task 6 (run with `-race`).
5. **A template that prints the block inside an HTML comment or attribute** (`<!-- [[ .Extra.consent.Block ]] -->`): the marker is present once, so it passes the check, but the user sees no form; acceptable (a broken-looking page, not a bypass), and documented in the test so nobody "fixes" it into a false sense of safety. Test in Task 6.

---

### Task 1: kdex-crds: Consent type, consentRef, CEL rule, shared consent messages

**Files:**
- Modify: `kdex-crds/api/v1alpha1/kdexutilitypage_types.go` (enum at :24 and :78; add the XValidation on `KDexUtilityPageSpec`)
- Modify: `kdex-crds/api/v1alpha1/kdexhost_types.go:391-407` (`UtilityPages.ConsentRef`)
- Modify: `kdex-crds/api/v1alpha1/kdexinternalhost_types.go:30-38` (`ConsentRef *corev1.LocalObjectReference`)
- Create: `kdex-crds/render/consent_messages.go`
- Test: `kdex-crds/api/v1alpha1/kdexutilitypage_types_test.go` (new), `kdex-crds/render/consent_messages_test.go` (new)
- Regenerated: `config/crd/bases/*.yaml`, `zz_generated.deepcopy.go`, `CRD_REFERENCE.md`

**Interfaces:**
- Produces: `v1alpha1.ConsentUtilityPageType KDexUtilityPageType = "Consent"`; `UtilityPages.ConsentRef *KDexObjectReference` (json `consentRef`, same kind rule as `LoginRef`); `KDexInternalHostSpec.ConsentRef *corev1.LocalObjectReference` (json `consentRef`); `render.ConsentMessages map[string]string` (the 14 keys → English text from the spec table); `render.ConsentMessageKeys() []string` (sorted keys).

- [ ] **Step 1: Write the failing tests**

`TestKDexUtilityPageGeneratedSchema_Consent` (use the existing `translationCRDSpecSchema` helper on `kdex.dev_kdexutilitypages.yaml`, `kdex.dev_kdexclusterutilitypages.yaml`, `kdex.dev_kdexinternalutilitypages.yaml`): the `type` enum contains `Consent`; the spec-level `x-kubernetes-validations` contain a rule whose `message` is exactly "a Consent page cannot reference scripts: no scriptLibraryRef and no appRef content". `TestKDexHostGeneratedSchema_ConsentRef`: `utilityPages.properties.consentRef` exists with one validation whose rule mentions `KDexUtilityPage` and `KDexClusterUtilityPage`. `TestKDexInternalHostGeneratedSchema_ConsentRef`: `consentRef` exists on the internal host spec. `TestConsentMessages`: exactly 14 keys, every key has prefix `consent.`, `ConsentMessages["consent.allow"] == "Allow"`, `ConsentMessages["consent.signed-in-as"] == "Signed in as %s."`, and `ConsentMessageKeys()` is sorted and has length 14.

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-crds && go test ./api/v1alpha1/ ./render/ -run 'Consent' -v`
Expected: FAIL (undefined `ConsentMessages`; enum lacks `Consent`).

- [ ] **Step 3: Implement**

Add the constant and `Consent` to both enum markers; add the CEL marker with the exact rule and message; add `ConsentRef` to `UtilityPages` (copy `LoginRef`'s markers, swap the description to "consent page") and to `KDexInternalHostSpec`; write `render/consent_messages.go` with the spec's table as a map literal. Then `make manifests generate docs`.

- [ ] **Step 4: Run to verify they pass**

Run: `cd kdex-crds && make test lint`
Expected: PASS, lint clean.

- [ ] **Step 5: Commit (local only)**

```bash
cd kdex-crds && git add -A && git commit -m "feat: Consent utility page type, consentRef and consent messages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Tag kdex-crds and repin the actors (USER GATE)

**Files:** `kdex-nexus-manager/go.mod`, `go.sum`; `kdex-host-manager/go.mod`, `go.sum` (by the script).

**Interfaces:** Produces the new kdex-crds tag `v0.14.251` pinned (uncommitted) in both actors.

- [ ] **Step 1: Ask the user** for the go-ahead to push kdex-crds `main` and the new tag (public repo). Stop until they say yes.
- [ ] **Step 2: Run** from the workspace root: `./updateCrdUsage.sh -t -n`. If it refuses because Task 1 is already committed, push kdex-crds `main` by hand first, then rerun.
- [ ] **Step 3: Verify** `git -C kdex-crds describe --tags --abbrev=0` prints `v0.14.251`, and both actors' `go.mod` `replace` lines name it; `go build ./...` succeeds in both actors. The go.mod/go.sum changes are committed with each actor's first task (Tasks 3 and 5).

### Task 3: nexus-manager: resolve consentRef, default it, watch it; CEL behaviour

**Files:**
- Modify: `kdex-nexus-manager/internal/controller/kdexhost_controller_util.go:276-340`
- Modify: `kdex-nexus-manager/internal/controller/kdexhost_controller.go:326` (caller), `:700-704` (watches), `:797-799` (internal host refs)
- Modify: `kdex-nexus-manager/internal/webhook/kdexhost_defaulter.go:62-93`, `internal/webhook/types.go:21-23`
- Test: `kdex-nexus-manager/internal/controller/kdexhost_controller_test.go`, `internal/controller/kdexutilitypage_cel_test.go` (new, envtest), `internal/webhook/kdexhost_defaulter_test.go` (new or existing)

**Interfaces:**
- Consumes: Task 1's `ConsentUtilityPageType`, `UtilityPages.ConsentRef`, `KDexInternalHostSpec.ConsentRef`.
- Produces: `webhook.KDexDefaultUtilityPageConsent = "kdex-default-utility-page-consent"`; `resolveUtilityPages(ctx, host) (map[kdexv1alpha1.KDexUtilityPageType]*corev1.LocalObjectReference, bool, ctrl.Result, error)` (replaces the three positional returns; one `utilityPageTypes` slice and one `utilityPageRef(host, type)` switch are the only places listing the four types).

- [ ] **Step 1: Write the failing tests**

Envtest (`Describe("Consent utility page CEL")`): creating a `KDexClusterUtilityPage` with `type: Consent` and one `rawHTML` `main` entry succeeds; with `scriptLibraryRef` set, `Create` fails and the error contains "a Consent page cannot reference scripts"; with an `appRef` entry (plus `customElementName`), the same; a `Login` page with `scriptLibraryRef` still succeeds. Controller test: a host whose `consentRef` names a `KDexUtilityPage` of type `Consent` gets a `KDexInternalUtilityPage` named `<host>-consent` and `KDexInternalHost.Spec.ConsentRef.Name == "<host>-consent"`; a `consentRef` pointing at a `Login`-typed page degrades the host with "does not match requested type Consent". Defaulter test: an empty host gets `ConsentRef{Kind: "KDexClusterUtilityPage", Name: "kdex-default-utility-page-consent"}`; a host with a `consentRef` set keeps it.

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-nexus-manager && make test`
Expected: FAIL on the new specs (no consent resolution, no default).

- [ ] **Step 3: Implement**

Refactor `resolveUtilityPages` to the map return, add Consent to the type list and the ref switch, extend `isDefaultUtilityPage`, the two `Watches` reference paths (`{.Spec.UtilityPages.ConsentRef}`), the caller and `internalHost.Spec.ConsentRef`; add the defaulter block and constant mirroring Login.

- [ ] **Step 4: Run to verify they pass**

Run: `cd kdex-nexus-manager && make test` then `cd .. && make lint`
Expected: PASS, lint clean.

- [ ] **Step 5: Commit**

```bash
cd kdex-nexus-manager && git add -A && git commit -m "feat: resolve and default the Consent utility page

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: nexus-manager: bundled default consent page and translations

**Files:**
- Create: `kdex-nexus-manager/config/bundled/kdex-default-utility-page-consent.yaml`
- Modify: `kdex-nexus-manager/config/bundled/kdex-default-translation.yaml` (all 8 languages)
- Test: `kdex-nexus-manager/internal/webhook/bundled_consent_test.go` (new; follow `bundled_footer_test.go`)

**Interfaces:**
- Consumes: `render.ConsentMessageKeys()`, `render.ValidateContent`, Task 3's default name.

- [ ] **Step 1: Write the failing tests**

`TestBundledConsentPage`: the file unmarshals into `KDexClusterUtilityPage` named `kdex-default-utility-page-consent`, `Spec.Type == ConsentUtilityPageType`, `PageArchetypeRef.Name == "kdex-default-page-archetype-utility"`, no `ScriptLibraryRef`, every entry is `rawHTML`, the `main` entry contains `.Extra.consent.Block` exactly once and no `<script`, and `render.ValidateContent` accepts it. `TestBundledTranslationHasConsentKeys`: for each of `en de es fr it pt ru zh`, every key in `render.ConsentMessageKeys()` is present and non-empty; for `en` each value equals `render.ConsentMessages[key]`; each translated value has the same count of `%s` as the English one.

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-nexus-manager && go test ./internal/webhook/ -run 'Bundled(Consent|Translation)' -v`
Expected: FAIL (file missing, keys missing).

- [ ] **Step 3: Implement**

The page: `main` slot wraps `[[ .Extra.consent.Block ]]` in `<div class="login-container">` with the brand heading (`[[ l10n .BrandName ]]`) and the `footer-organization` block copied from the login page; no script. Translations: the 14 keys in each language, preserving `%s` placeholders.

- [ ] **Step 4: Run to verify they pass**

Run: `cd kdex-nexus-manager && make test` then `cd .. && make lint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd kdex-nexus-manager && git add config/bundled internal/webhook && git commit -m "feat: bundle the default consent page and its translations

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: host-manager: the fixed consent block

**Files:**
- Modify: `kdex-host-manager/internal/auth/consent_page.go`
- Test: `kdex-host-manager/internal/auth/consent_page_test.go`

**Interfaces:**
- Consumes: `render.ConsentMessages`.
- Produces: `type Translator func(key string, args ...any) (string, bool)` (false = key missing); `RenderConsentCore(v ConsentView, marker string, t Translator) template.HTML`; `ConsentMarkerAttr = "data-kdex-consent"`; `ConsentScriptHash() string` (the `'sha256-…'` source, computed from the script constant); `RenderBuiltinConsent` unchanged in signature, now wrapping `RenderConsentCore` with an English-only translator and a fresh marker.

- [ ] **Step 1: Write the failing tests**

`TestRenderConsentCore_EnglishFallback`: with a translator that returns `false` for everything, the output contains `Allow access to your account?`, `Signed in as <strong>a@b.c</strong>.`, `Only allow this if you started connecting this application yourself.`, and `data-kdex-consent="m1"` exactly once. `TestRenderConsentCore_PartialTranslation` (Review Focus 1): a translator that knows only `consent.title` → its value plus English for the rest; no output contains the substring `consent.`. `TestRenderConsentCore_ArgsAreLiteral` (Review Focus 2): `ClientName: "%s<b>&x%!"` and `Account: "%d@x"` appear escaped (`%s&lt;b&gt;&amp;x%!`, `%d@x`) inside `<strong>`, with no `%!(` anywhere in the output. `TestRenderConsentCore_TranslationHTMLEscaped` (Review Focus 3): `consent.warning` translated to `<b>Careful</b>` renders `&lt;b&gt;Careful&lt;/b&gt;`. `TestRenderConsentCore_Conditions`: device redirect shows the application line and no website line; web redirect with a registrable domain shows `Website: <strong>example.com</strong>`; empty `ClientName` omits the client-name line; empty `Scopes` uses `consent.permissions`. `TestConsentScriptHoldsEveryAllow`: the script source uses `querySelectorAll` over `button[value=allow]` (assert the constant contains `querySelectorAll('button[value=allow]')`). `TestBuiltinConsentCSPMatchesScript`: the sha256 of the `<script>` body in `RenderBuiltinConsent` output equals the hash in its CSP header. Existing stage-1 tests keep passing.

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-host-manager && go test ./internal/auth/ -run 'Consent' -v`
Expected: FAIL (undefined `RenderConsentCore`).

- [ ] **Step 3: Implement**

Move the stage-1 body markup into a block template rooted at `<div data-kdex-consent="{{marker}}">` containing the disclosure, the form and the script. Each string: call `t(key, sentinels...)` where sentinel *i* is `"" + strconv.Itoa(i) + ""`; when it returns false use `fmt.Sprintf(render.ConsentMessages[key], sentinels...)`; `html.EscapeString` the result; then replace each sentinel with the escaped argument (wrapped in `<strong>` where stage 1 bolds it). Arguments never pass through a format string. Rewrite the hold-back script to attach the hold to every `button[value=allow]` (one `armed` state for the page; the submit guard checks `e.submitter.matches('button[value=allow]')`). `builtinConsentCSP` uses `ConsentScriptHash()`.

- [ ] **Step 4: Run to verify they pass**

Run: `cd kdex-host-manager && go test ./internal/auth/ -v` then `cd .. && make lint`
Expected: PASS.

- [ ] **Step 5: Commit** (with the Task 2 go.mod/go.sum repin)

```bash
cd kdex-host-manager && git add -A && git commit -m "feat(auth): render the consent block from translatable messages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: host-manager: branded consent rendering

**Files:**
- Modify: `kdex-host-manager/internal/host/host.go:271-293` (`L10nRender` scriptless option), `:1201-1262` (`renderUtilityPage`)
- Create: `kdex-host-manager/internal/host/consent.go`
- Modify: `kdex-host-manager/internal/host/handlers.go:396-407` (`newOAuth2` sets `RenderConsent`)
- Modify: `kdex-host-manager/internal/controller/kdexinternalhost_controller.go:235-239` (warm-up list), `:895` (watch `{.Spec.ConsentRef}`)
- Test: `kdex-host-manager/internal/host/consent_test.go` (new), `internal/controller/kdexinternalhost_controller_test.go`

**Interfaces:**
- Consumes: `auth.RenderConsentCore`, `auth.ConsentMarkerAttr`, `auth.ConsentScriptHash`, `auth.RenderBuiltinConsent`, `auth.Translator`, `kdexv1alpha1.ConsentUtilityPageType`.
- Produces: `type renderOptions struct{ Scriptless bool }`; `renderUtilityPage(type, l, extra, translations, opts renderOptions) string` (existing callers pass `renderOptions{}`); `(hh *HostHandler) renderConsentPage(w http.ResponseWriter, r *http.Request, v auth.ConsentView)`; `brandedConsentCSP() string` returning the Global Constraints policy.

- [ ] **Step 1: Write the failing tests**

Using the existing host test helpers to install a theme with a `style` asset, a Consent utility page whose archetype prints `[[ .Meta ]] [[ .Theme ]] [[ .HeadScript ]] [[ .Header ]] [[ .Navigation.main ]] [[ .Content.main ]] [[ .Footer ]] [[ .FootScript ]]`, a host script library and a navigation:
`TestConsentPage_Branded`: response contains the theme's style, the header text, the block's `data-kdex-consent` exactly once, no `type="importmap"`, no `type="module"`, no `/-/navigation/` fetch; `Content-Security-Policy` values include the exact branded policy; `Content-Type` is `text/html; charset=utf-8`; `Content-Language` is set. `TestConsentPage_FallbackNoUtilityPage` (Review Focus 4): no Consent page indexed → built-in page (its `<title>Allow access?</title>` and its stricter CSP). `TestConsentPage_FallbackMarkerMissing`: template omits `.Extra.consent.Block` → built-in page, and the log contains the utility page name. `TestConsentPage_FallbackMarkerTwice`: template prints the block twice → built-in page. `TestConsentPage_FallbackRenderError`: a template that fails at execution → built-in page. `TestConsentPage_BlockInCommentPassesCheck` (Review Focus 5): template wraps the block in `<!-- -->` → branded page served (marker once); the test comment records that this is a broken-looking page, not a bypass. `TestConsentPage_ConcurrentSetHost` (Review Focus 4): 50 goroutines render the consent page while another calls `SetHost` repeatedly; run under `-race`, no race, every response is 200. `TestNewOAuth2SetsRenderConsent`: `hh.newOAuth2().RenderConsent != nil`. Controller test: a `KDexInternalUtilityPage` of type Consent referenced by `KDexInternalHost.Spec.ConsentRef` is indexed (`GetUtilityPageHandler(ConsentUtilityPageType).Name` is set).

- [ ] **Step 2: Run to verify they fail**

Run: `cd kdex-host-manager && go test -race ./internal/host/ -run 'Consent|NewOAuth2' -v`
Expected: FAIL (undefined `renderConsentPage`).

- [ ] **Step 3: Implement**

`renderConsentPage` takes `hh.mu.RLock()` (the OAuth2 path holds no host lock), negotiates the language as `LoginGet` does, builds the `Translator` from `hh.messagePrinter` (missing ⇔ `p.Sprintf(key) == key`), generates the marker from 16 bytes of `crypto/rand` hex, renders the block, calls `renderUtilityPage(ConsentUtilityPageType, l, {"consent": {"Block": block}}, &hh.Translations, renderOptions{Scriptless: true})`, and checks `strings.Count(rendered, ConsentMarkerAttr+`="`+marker+`"`) == 1`. On an empty result or a failed check it logs (error, with the utility page name) and calls `auth.RenderBuiltinConsent`. It adds the branded CSP, `Content-Type` and `Content-Language` only after the check passes, so the fallback never carries two page policies. Scriptless makes `L10nRender` leave `HeadScript`, `FootScript` and `Navigations` empty. Add Consent to the warm-up list and the watch.

- [ ] **Step 4: Run to verify they pass**

Run: `cd kdex-host-manager && make test` then `cd .. && make lint`
Expected: PASS, including `-race` for the host package.

- [ ] **Step 5: Commit**

```bash
cd kdex-host-manager && git add -A && git commit -m "feat: brand the consent page with a Consent utility page

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: Release and live verification (USER GATE)

- [ ] **Step 1:** Run the quad over each actor's unreleased range (`origin/main..main` in kdex-nexus-manager and kdex-host-manager); fix findings test-first before release.
- [ ] **Step 2: Ask the user** for the go-ahead to push and tag kdex-nexus-manager (next minor after `v0.6.2`) and kdex-host-manager `v0.24.0` together. Stop until they say yes.
- [ ] **Step 3:** Push `main` and the annotated tags; verify both CI runs green, both images (amd64 + arm64) and both charts exist.
- [ ] **Step 4:** Ask infra for a spike2-only deploy (host-only override) of both, as for 0.23.0; wait for Ready.
- [ ] **Step 5: Live check** (browser, fresh DCR client, as in the 0.23.0 run-through): the consent page carries the spike2 theme; a CSP violation probe shows `script-src` is the single hash and `style-src` includes `https:`; the double-click on the held-back Allow posts nothing; blur re-holds; Allow returns a code; `prompt=none` without consent → `consent_required`.
- [ ] **Step 6:** On the user's go-ahead, request the fleet pin of both from infra and update the `dcr-consent-stage1` memory.

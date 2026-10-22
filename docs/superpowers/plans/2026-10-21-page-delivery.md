# Page Delivery (#246, #247, #248) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendered pages import only what their CRs declare, travel compressed, and carry browser security headers, with a host-level HSTS knob.

**Architecture:**
- **kdex-crds:** gains `Routing.HSTS`.
- **host-manager #246:** separates the host-scope package refs (theme and host script libraries) from the host-wide aggregate, which still feeds the importmap and the packages image.
- **host-manager #247:** `DesignMiddleware` compresses with gzhttp. It wraps the writer *outside* `errorResponseWriter`, so error capture stays uncompressed, and only for handlers marked `compressible`.
- **host-manager #248:** one helper sets the security headers on every page and utility-page write path.

**Tech Stack:**
- Go 1.26.0, kubebuilder, controller-gen CEL, envtest (Ginkgo in nexus-manager);
- `github.com/klauspost/compress/gzhttp` v1.20.1, already a dependency.

**Spec:** `kdex-host-manager/docs/superpowers/specs/2026-10-21-page-delivery-design.md`

## Global Constraints

- Go 1.26.0 in every module.
- **Never edit `replace kdex.dev/crds` in a go.mod by hand, and never use `go.work` (user
  ruling).** After the CRD change, run `./updateCrdUsage.sh -t -n` from the workspace root. It
  tags and pushes kdex-crds and leaves the go.mod/go.sum bumps in nexus and host for us to
  commit. This means kdex-crds is tagged before the quad; a quad fix to kdex-crds ships as the
  next patch tag.
- YAML uses 2-space indentation, one resource per file.
- Run `make lint` from the workspace root after code changes.
- **No security headers on proxied function or backend responses, `/-/modules`, `/-/theme`
  or `/-/transfer`.** The one exception is the HTML error page host-manager renders over a ≥400.
- **Never compress SSE.** Never wrap a rewrite alias in the compressor.
- **Keep the consent pages' stricter values:** `X-Frame-Options: DENY`,
  `frame-ancestors 'none'`, `Referrer-Policy: same-origin`.
- **HSTS:**
  - unset `maxAge` sends `max-age=31536000`;
  - `0` sends `max-age=0`;
  - the ceiling is `63072000`;
  - neither `includeSubDomains` nor `preload` is on by default;
  - it's sent only when the routing scheme is `https`.
- **Exact default header values:**
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Content-Security-Policy: frame-ancestors 'self'`
  - `X-Frame-Options: SAMEORIGIN`
- **Run the quad (Task 7) before any tag.**
- Commits go inside each sub-repo, and every commit message ends with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A browser denied a gated page under `Accept-Encoding: gzip`** must still get the login
   redirect or challenge, and `Cache-Control: no-store`, intact, with a readable (decompressible)
   body. Test in Task 4.
2. **A function's 500 seen by a browser:** the error page's `ErrorMessage` must be the function's
   plain text, never compressed bytes, and the response must still say
   `Vary: Accept-Encoding` when compressed. Test in Task 4.
3. **The same page requested with gzip, then identity, then gzip plus the gzip ETag** must give
   two different ETags and a 304 only for the matching coding. Test in Task 4.
4. **An SSE function reached through a page-path alias** must stream unbuffered with no
   `Content-Encoding`. Test in Task 4.
5. **A host whose `routing.scheme` is `http`** must never send HSTS, even with `routing.hsts`
   set. Test in Task 5.

---

### Task 1: kdex-crds — `Routing.HSTS`

**Files:**
- Modify: `kdex-crds/api/v1alpha1/types.go` (the `Routing` struct, about line 1310; add the
  `HSTS` type beside it)
- Test: `kdex-crds/api/v1alpha1/routing_hsts_test.go` (new)
- Regenerated: `config/crd/bases/*.yaml`, `zz_generated.deepcopy.go`, docs

**Interfaces — produces:**

```go
// in Routing, after Scheme:
// hsts tunes the Strict-Transport-Security header host-manager sends on rendered pages when
// scheme is https. Unset sends max-age=31536000 with neither includeSubDomains nor preload.
// +kubebuilder:validation:Optional
HSTS *HSTS `json:"hsts,omitempty" protobuf:"bytes,6,opt,name=hsts"`

// +kubebuilder:validation:XValidation:rule="!has(self.preload) || !self.preload || (has(self.includeSubDomains) && self.includeSubDomains && (!has(self.maxAge) || self.maxAge >= 31536000))",message="preload requires includeSubDomains and a maxAge of at least 31536000"
type HSTS struct {
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63072000
	MaxAge *int32 `json:"maxAge,omitempty" protobuf:"varint,1,opt,name=maxAge"`
	// +kubebuilder:validation:Optional
	IncludeSubDomains bool `json:"includeSubDomains,omitempty" protobuf:"varint,2,opt,name=includeSubDomains"`
	// +kubebuilder:validation:Optional
	Preload bool `json:"preload,omitempty" protobuf:"varint,3,opt,name=preload"`
}
```

Field doc comments are the spec's (design doc §#248), verbatim.

- [ ] **Step 1: Write the failing tests** in `routing_hsts_test.go`, following
  `apitoken_maxttl_test.go`, which reads the generated schema with `translationCRDSpecSchema`:
  - `TestRouting_HSTS_OmittedWhenUnset`: marshal `Routing{Domains: []string{"a.example"}}`; the
    JSON has no `"hsts"`.
  - `TestRouting_HSTS_RoundTrips`: `MaxAge=new(int32(0))`, `IncludeSubDomains=true`. Unmarshal
    gives `*MaxAge == 0`, so an explicit 0 survives.
  - `TestRoutingGeneratedSchema_HSTS`, for both `kdex.dev_kdexhosts.yaml` and
    `kdex.dev_kdexinternalhosts.yaml`: `routing.properties.hsts` exists; `maxAge` has
    `minimum` 0 and `maximum` 63072000; there's exactly one `x-kubernetes-validations` rule,
    equal to the rule string above.
- [ ] **Step 2:** Run `cd kdex-crds && go test ./api/... -run 'HSTS' -v`. Expected: FAIL to
  compile (`HSTS` undefined).
- [ ] **Step 3:** Add the type and field, then run `make manifests generate docs`.
- [ ] **Step 4:** Run `make test`. Expected: PASS.
- [ ] **Step 5:** Commit in `kdex-crds`:
  `feat: KDexHost routing.hsts tunes the Strict-Transport-Security header (host-manager#248)`.
- [ ] **Step 6:** From the workspace root, run `./updateCrdUsage.sh -t -n`. It runs
  `make test lint docs`, pushes kdex-crds main, and tags and pushes **v0.14.253**. It then
  rewrites the `replace` line and runs `go mod tidy` in nexus-manager and host-manager, leaving
  both uncommitted.
- [ ] **Step 7:** In each of kdex-nexus-manager and kdex-host-manager, run `go build ./...`
  (expect success), then commit only `go.mod` and `go.sum`:
  `Update kdex-crds version to v0.14.253`. Do not push yet.

### Task 2: nexus-manager — envtest proves the HSTS CEL rule

**Files:**
- Test: `kdex-nexus-manager/internal/controller/kdexhost_routing_hsts_test.go` (new), modelled on
  `kdexhost_apitoken_maxttl_test.go`.

**Interfaces — consumes:** `kdexv1alpha1.HSTS` and `Routing.HSTS` from Task 1, through the
v0.14.253 pin.

- [ ] **Step 1:** Write the spec. `hostWith(h *kdexv1alpha1.HSTS)` builds the same host as the
  maxTTL test with `Routing.HSTS = h`. Use `client.DryRunAll` throughout.
  - It accepts: nil; `{}`; `{MaxAge: 0}`; `{MaxAge: 63072000}`;
    `{IncludeSubDomains: true, Preload: true}` (unset maxAge counts as 31536000);
    `{MaxAge: 31536000, IncludeSubDomains: true, Preload: true}`.
  - It refuses, and the error contains `preload requires includeSubDomains`:
    `{Preload: true}`; `{MaxAge: 86400, IncludeSubDomains: true, Preload: true}`.
  - It refuses, and the error contains `maxAge`: `{MaxAge: -1}`; `{MaxAge: 63072001}`.
- [ ] **Step 2:** Run `cd kdex-nexus-manager && make test`. Expected: the new specs pass
  against the v0.14.253 CRDs.
- [ ] **Step 3:** Commit in `kdex-nexus-manager`, without pushing:
  `test: envtest covers KDexHost routing.hsts validation (host-manager#248)`.

### Task 3: host-manager #246 — import only what the page declares

**Files:**
- Modify: `internal/controller/kdexinternalhost_controller.go`. Collect a `hostScopeRefs` slice
  next to `packageRefs` at the two script-library sites (theme, about line 196; host, about
  line 223), and pass `UniquePackageRefs(hostScopeRefs)` to `SetHost` in place of
  `uniquePackageRefs` (about line 671). `handleInternalPackageReferences` keeps
  `uniquePackageRefs`.
- Modify: `internal/host/host.go`. In `HeadScriptToHTML` (line 175), replace the map with
  `UniquePackageRefs`-style ordering. Also rename `SetHost`'s parameter to
  `hostScopePackageReferences` and update its doc comment.
- Test: `internal/host/head_script_test.go` (new); and in
  `internal/controller/kdexinternalhost_controller_test.go`, the existing envtest suite.

**Interfaces:**
- Produces: `SetHost`'s 4th parameter now means "host-scope package references". Its type is
  unchanged, so no other callers change.
- `HeadScriptToHTML` emits statements sorted by `Name`, then `Version`.

**Sorting.** `UniquePackageRefs` lives in package `controller`. Don't import controller from
host. Use `slices.SortFunc` with the same comparison, after deduping by `Name` (page wins over
host scope, as today).

- [ ] **Step 1: Write the failing tests** in `head_script_test.go`:
  - `TestHeadScriptToHTML_ImportsOnlyHostScopeAndPageRefs`: `SetHost` with host-scope refs
    `[@x/theme-lib]` and an importmap string `{"imports":{"@x/a":"/a.js","@x/b":"/b.js","@x/theme-lib":"/t.js"}}`.
    A `page.PageHandler{PackageReferences: [@x/a]}` gives output containing
    `import "@x/a"` and `import "@x/theme-lib"`, and **not** `import "@x/b"`. The output also
    contains the full importmap string verbatim.
  - `TestHeadScriptToHTML_DeterministicOrder`: with page refs `[@x/z, @x/a, @x/m]`, 50 calls
    give byte-identical output, and `@x/a` appears before `@x/m`, which appears before `@x/z`.
  - Use the exact import statement `PackageReference.ToImportStatement()` returns. Read it from
    kdex-crds rather than guessing the quoting.
- [ ] **Step 2:** Run `go test ./internal/host/ -run HeadScript -v`. Expected: the order test
  FAILs (map iteration order). The narrowing test may already pass at host level. Step 3's
  controller test is what proves the narrowing.
- [ ] **Step 3:** Add an envtest case to the internal-host controller suite: a host with two
  pages, each declaring a different app. Assert that page A's rendered head (fetched through
  `HostHandler` the way existing controller tests render pages) imports A's package and not
  B's, and that the KIPR spec still lists both packages.
- [ ] **Step 4:** Implement it.
- [ ] **Step 5:** Run `make test` in `kdex-host-manager`. Expected: PASS.
- [ ] **Step 6:** Commit:
  `fix(host): a page imports only the packages its own CRs declare (#246)`.

### Task 4: host-manager #247 — compress host-manager's own responses

**Files:**
- Create: `internal/host/compress.go`
- Modify:
  - `internal/host/feedback.go` (`DesignMiddleware`, `unwrap`);
  - `internal/host/funcs.go` (`applyCachingHeadersWithSeed`);
  - `internal/host/openapi.go` (drop the now-redundant explicit seed);
  - `internal/host/handlers.go`: the page registration loop (about line 323), `NavigationGet`
    (line 945), `TranslationGet` (line 1549), `openapiHandler` (line 1130, which loses its own
    gzhttp wrap), the announcement and not-ready routes, and the login page route.
- Test:
  - `internal/host/compress_test.go` (new);
  - update `internal/host/openapi_gzip_test.go` to go through
    `hh.DesignMiddleware(hh.Mux)` instead of `th.Mux`.

**Interfaces — produces:**
- `type compressibleHandler struct{ http.Handler }`, plus
  `func compressible(h http.Handler) http.Handler`, which returns `compressibleHandler{h}`.
- `var gzipWrap = gzhttp.GzipHandler`. If construction needs options, build the wrapper once at
  package init with `gzhttp.NewWrapper()` and default options.
- `DesignMiddleware`: after `h, p := mux.Handler(r)`, if `_, ok := h.(compressibleHandler)` or
  `p == ""` (unmatched, i.e. a 404 error page), run the rest of the middleware body inside
  `gzipWrap(...)`, so the `w` it sees is the gzhttp writer. `errorResponseWriter` then wraps that
  writer. Function and backend matches run exactly as today.
- `unwrap`: after the header wipe, if the pre-wipe header had `Vary` containing
  `Accept-Encoding`, re-add `Vary: Accept-Encoding`. gzhttp adds it before the handler runs, and
  the wipe deletes it.
- `applyCachingHeadersWithSeed` folds `acceptEncodingSeed(r)` into the ETag input for every
  caller. `OpenAPIGet` then passes `""` as its seed.

**What gets wrapped with `compressible(...)`:**
- the page handler from `pageHandlerFunc`;
- `NavigationGet`, `TranslationGet` and `OpenAPIGet`;
- the login page;
- the announcement and not-ready handlers on their mux routes.

**What stays unwrapped:** `rewriteHandlerFunc`, the 301 legacy redirects, function and backend
proxies, `/-/modules`, `/-/theme` and `/-/transfer`.

- [ ] **Step 1: Write the failing tests** in `compress_test.go`. Drive everything through
  `hh.DesignMiddleware(hh.Mux)`, with a host whose page renders over 1024 bytes (gzhttp's
  minimum).
  - `TestCompress_PageNegotiatesGzip`: `Accept-Encoding: gzip` gives `Content-Encoding: gzip`,
    and `Vary` contains `Accept-Encoding`. The gunzipped body equals the identity response body.
  - `TestCompress_IdentityWithoutAcceptEncoding`: no `Content-Encoding` header.
  - `TestCompress_ETagPerCoding`: the gzip and identity ETags differ. Re-requesting with the
    gzip ETag and gzip encoding gives 304; with the gzip ETag and no Accept-Encoding gives 200.
  - `TestCompress_TranslationAndNavigation`: both get `Content-Encoding: gzip` under gzip. Use
    enough translation keys to pass 1024 bytes.
  - `TestCompress_FunctionRouteUntouched`: a function proxied to an `httptest.Server` that
    returns 4 KB of `text/html` gives no `Content-Encoding` from host-manager.
  - `TestCompress_FunctionErrorMessagePlainText`: the upstream returns 500 with body `boom`; the
    request uses `Accept: text/html` and `Accept-Encoding: gzip`. The rendered error page's
    `ErrorMessage` is `boom`. Use an error utility page template that prints
    `{{ .Extra.ErrorMessage }}`; match the actual template field the error page exposes.
  - `TestCompress_UnmatchedErrorPageCompressedWithVary`: a 404 for an HTML-accepting gzip client
    is gzip-encoded, keeps `Vary: Accept-Encoding`, and decompresses to the error page.
  - `TestCompress_DeniedPageKeepsPreservedHeaders`: a gated page with an anonymous browser and
    gzip gets the same status, `Location` or `WWW-Authenticate`, and `Cache-Control: no-store`
    as without gzip. Its body is readable after decoding `Content-Encoding`, if present.
  - `TestCompress_AliasToSSEFunctionNotBuffered`: a rewrite alias targeting a function whose
    upstream writes `text/event-stream` in two flushed chunks. The first chunk reaches the client
    before the upstream writes the second (synchronise with a channel), and there's no
    `Content-Encoding`.
- [ ] **Step 2:** Run `go test ./internal/host/ -run 'TestCompress|TestOpenAPI' -v`. Expected:
  the new tests FAIL. The openapi tests still pass after you switch them to the middleware.
- [ ] **Step 3:** Implement `compress.go`, the middleware and `unwrap` changes, the ETag seed
  fold, and the registrations.
- [ ] **Step 4:** Run `make test`. Expected: PASS, with no regressions in `feedback_*`,
  `rewrite_*` or `consent_*`.
- [ ] **Step 5:** Commit:
  `feat(host): gzip/zstd-negotiate pages, utility pages, translation and navigation (#247)`.

### Task 5: host-manager #248 — page security headers + HSTS

**Files:**
- Create: `internal/host/security_headers.go`
- Modify:
  - `internal/host/types.go`: add the `hstsValue string` field;
  - `internal/host/host.go`: `SetHost` computes `hstsValue` from `scheme` and `host.Routing.HSTS`;
  - call sites `serveRendered` and `serveText` in `page.go` (`serveText` drops its own nosniff
    line);
  - `serveError` in `host.go`;
  - the login page in `login.go`;
  - the announcement and not-ready pages in `handlers.go`;
  - `renderConsentPage` in `consent.go`.
- Test: `internal/host/security_headers_test.go` (new)

**Interfaces — produces:**
- `func hstsHeaderValue(scheme string, h *kdexv1alpha1.HSTS) string`:
  - returns `""` unless `strings.EqualFold(scheme, "https")`;
  - otherwise returns `max-age=<n>`, then `; includeSubDomains`, then `; preload`, in that
    order, with `n` = `*h.MaxAge`, or 31536000 when `h` or `h.MaxAge` is nil.
- `func (hh *HostHandler) setPageSecurityHeadersLocked(w http.ResponseWriter)` (the caller holds
  `hh.mu.RLock`):
  - `Set`s the four default headers;
  - `Set`s `Strict-Transport-Security` when `hh.hstsValue != ""`;
  - uses `Set` throughout, so a later stricter `Set` wins.
- `func (hh *HostHandler) setTransportSecurityHeadersLocked(w http.ResponseWriter)`: nosniff
  plus HSTS only. This is for consent, whose flow already set the framing and referrer
  headers. If `renderConsentPage` doesn't hold the lock, take `hh.mu.RLock` around the call.
- **Ordering:**
  - in `serveError` and `unwrap`, call the helper on the writer after `unwrap`'s header wipe,
    i.e. inside `serveError`;
  - in page handlers, call it before `WriteHeader`/`Write`;
  - the 304 path doesn't need it.

- [ ] **Step 1: Write the failing tests** in `security_headers_test.go`:
  - `TestHSTSHeaderValue`, table-driven:
    - `("https", nil)` gives `max-age=31536000`;
    - `("https", {MaxAge:0})` gives `max-age=0`;
    - `("https", {MaxAge:63072000, IncludeSubDomains:true, Preload:true})` gives
      `max-age=63072000; includeSubDomains; preload`;
    - `("https", {IncludeSubDomains:true})` gives `max-age=31536000; includeSubDomains`;
    - `("http", {MaxAge:100})` gives `""`;
    - `("HTTPS", nil)` gives `max-age=31536000`.
  - `TestSecurityHeaders_RenderedPage`, `_TextPage` and `_ErrorPage`: each default is present
    with its exact value, plus HSTS under an https host.
  - `TestSecurityHeaders_HTTPHostSendsNoHSTS`: a `routing.scheme: http` host with
    `routing.hsts` set sends no `Strict-Transport-Security` on a page.
  - `TestSecurityHeaders_ConsentKeepsStricterValues`: the branded consent page gets
    `X-Frame-Options: DENY`, a CSP header containing `frame-ancestors 'none'`,
    `Referrer-Policy: same-origin`, nosniff and HSTS. Reuse `newConsentPageHost`.
  - `TestSecurityHeaders_FunctionResponseHasNone`: a proxied 200 function response has none of
    the five headers.
  - `TestSecurityHeaders_FunctionErrorPageHasThem`: the HTML error page over a function 404 has
    them.
- [ ] **Step 2:** Run `go test ./internal/host/ -run 'HSTS|SecurityHeaders' -v`. Expected: FAIL.
- [ ] **Step 3:** Implement it.
- [ ] **Step 4:** Run `make test`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat(host): browser security headers on rendered pages (#248)`.

### Task 6: Whole-workspace verification

- [ ] **Step 1:** From the workspace root, run `make lint`. Expected: clean in every module.
  Commit any formatting fixes in the module that owns them.
- [ ] **Step 2:** Run `make test` in kdex-crds, kdex-nexus-manager and kdex-host-manager.
  Expected: PASS in all three.

### Task 7: The quad (before any tag)

Per the workspace CLAUDE.md "Marking Quad Reviews in Git".

- [ ] **Step 1: Ranges.**
  - kdex-crds: `870195d..HEAD`, where 870195d ends the last marker, f8b2576.
  - kdex-nexus-manager: `e18c344..HEAD`, where e18c344 ends the last marker, 4b13f56.
  - kdex-host-manager: `7e9f52c..HEAD`, where 7e9f52c ends the last marker, 1522978.
  Write one combined diff to the scratchpad as the review package.
- [ ] **Step 2:** Dispatch the four reviewers in parallel: data integrity, performance, security,
  and DRY/tech-debt. Give them independent prompts, the diff path, and the spec path.
- [ ] **Step 3:** Synthesize a single deduplicated list, ranked by severity. Fix HIGH and MEDIUM
  findings in each repo as `fix(quad): fixes from the <from>..<to> quad (#246 #247 #248)`.
  File LOW findings that are deferred as issues.
- [ ] **Step 4:** Re-review the fix commits with one fresh reviewer, then repeat Task 6.
- [ ] **Step 5:** In each of the three repos, add an empty **signed** marker commit,
  `chore(quad): mark the <from>..<to> quad (#246 #247 #248)`. Its body has one line per lens
  (the finding, and the fix commit or issue), and its last trailer is `Quad-Range: <from>..<to>`.

### Task 8: Release

- [ ] **Step 1:** If the quad changed kdex-crds, commit the fix there, re-run
  `./updateCrdUsage.sh -t -n` (it cuts v0.14.254), and commit the go.mod/go.sum bumps in nexus
  and host. Then run `make test` in both. Expected: PASS.
- [ ] **Step 2:** Push `main` in kdex-nexus-manager and kdex-host-manager.
- [ ] **Step 3:** Tag with annotated tags, matching v0.26.0's style:
  - host-manager **v0.27.0**, message
    `v0.27.0: pages import only their own packages (#246); compressed pages, translation and navigation (#247); page security headers + routing.hsts (#248)`;
  - nexus-manager **v0.7.3**, message `v0.7.3: kdex-crds v0.14.253 (routing.hsts)`, or the
    v0.14.254 the quad cut.
  Push the tags, and confirm CI is green for both.
- [ ] **Step 4:** Update the kdex-kcnas skill with:
  - the #246 contract: a page imports only what its CRs declare, and an indirect dependency
    must be imported by the code that renders it or declared by a CR;
  - #247 compression;
  - `routing.hsts`.
  Diff the source, installed and knowdrive-site copies before syncing, since they have diverged
  before.
- [ ] **Step 5:** Tell `site` (SendMessage) that v0.27.0 and nexus v0.7.3 are tagged. Ask it to
  confirm its top-bar fix is live on each host to be pinned.
- [ ] **Step 6:** Only once the site confirms, ask `infra` to pin host-manager v0.27.0, nexus
  v0.7.3 and kdex-crds v0.14.253. Then smoke test dev:
  - `/for/agent-teams` HTML carries one app import plus the host-scope imports;
  - `curl -H 'Accept-Encoding: gzip' -D -` on that page and on `/-/translation/en` shows
    `content-encoding: gzip`;
  - the five security headers are present;
  - a signed-in user still gets `<knowdrive-usermenu>`.

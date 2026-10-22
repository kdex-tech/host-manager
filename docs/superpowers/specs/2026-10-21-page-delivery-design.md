# Page delivery: narrow imports, compression, security headers (#246, #247, #248)

Date: 2026-10-21
Issues: kdex-tech/host-manager#246, #247, #248 (filed by the knowdrive-site session from its
review of the ad-driven `/for/*` landing pages)

## Intent

A public landing page on a KDex host should cost what that page uses, travel compressed, and
be safe to show in a browser. Today a one-element page imports every app on the host
(2.35 MB gzipped on `dev.knowdrive.ai/for/agent-teams`), its HTML and translation JSON go out
uncompressed, and it carries no anti-framing, HSTS, referrer or nosniff headers. The three
fixes are independent and ship together as one host-manager minor release, with the HSTS knob
landing in kdex-crds.

## Goals

1. **#246:** a rendered page's inline `<script type="module">` imports only the packages the
   page's own CRs declare. The emitted order is deterministic.
2. **#247:** page HTML, utility pages, `/-/translation/{l10n}` and `/-/navigation/...` are
   content-encoding negotiated (gzip, zstd), with `Vary: Accept-Encoding` and per-coding ETags.
3. **#248:** page and utility-page responses carry safe browser security headers by default,
   and the host can tune HSTS.

## Non-goals

- Resolving indirect dependencies. **User ruling:** it is not host-manager's job to work out
  that a page needs an element it never declared. That is the site CRs' responsibility: a CR
  declares the dependency, or the code that renders the element imports it, so the
  transitivity is expressed through the importmap. No "host-global app" flag and no chrome
  carve-out.
- Trimming the importmap. It stays host-wide. Apps leave shared packages (react, `@kdex-tech/ui`,
  topbar, l10n, language-switcher) out of their bundles and resolve them through the importmap,
  so trimming it would break every page.
- Lazy-defining elements on first appearance in the DOM (the issue's alternative).
- A full script/style CSP with nonces or hashes. Follow-up material, not this work.
- A per-page security-header override. **Site verdict (2026-10-21): not needed.** Nothing
  frames a site page cross-origin, no page needs to opt out, and the user accepted skipping the
  KDexPage CRD change.
- Brotli. gzhttp negotiates gzip and zstd. Adding `andybalholm/brotli` is a new dependency for a
  few percent. **Builder's call recorded here: no br.**

## Anti-goals

- Security headers on proxied function or backend responses (`/api/...`, backends, `/-/modules`,
  `/-/theme`). They must not change. The inspector's file preview frames a same-origin function
  route and must keep working.
- Compressing or buffering SSE (`text/event-stream`) function responses.
- Weakening the consent pages' stricter headers (`X-Frame-Options: DENY`,
  `frame-ancestors 'none'`, `Referrer-Policy: same-origin`).
- HSTS `includeSubDomains` or `preload` by default. On prod `knowdrive.ai` they would pin every
  subdomain, including tenant subdomains.

## #246: narrow the page's import list

**Current state.** `HostHandler.HeadScriptToHTML` (`internal/host/host.go`) unions
`hh.packageReferences` with `handler.PackageReferences`. `hh.packageReferences` comes from
`SetHost(..., uniquePackageRefs, ...)` in `internal/controller/kdexinternalhost_controller.go`,
which is the host-wide aggregate:
- the theme's `scriptLibraryRef`;
- the host's `scriptLibraryRef`;
- every utility page's refs;
- every page's refs.

The page's own `PackageReferences` are already exactly what its CRs declare
(`kdexpage_controller.go`):
- the archetype library;
- `appRef` content entries;
- the header, footer and navigation libraries;
- the page library.

Utility pages are built the same way (`kdexinternalutilitypage_controller.go`).

**Change.**
- The internal-host reconciler keeps the aggregate for what needs it:
  `handleInternalPackageReferences` (the packages image) and the importmap.
- It passes a separate **host-scope** set to `SetHost`, containing only the theme's and the
  host's `scriptLibraryRef` package references (deduped with `UniquePackageRefs`).
  `hh.hostScopePackageReferences` holds that set.
- `headScriptToHTMLLocked` unions the host-scope set with the page's own refs, keyed by package
  name (the page wins on a shared name). It emits one import statement per name, sorted by
  name, instead of ranging over a map.
- The importmap emitted in the head stays the full host importmap, unchanged.
- **Decided (Task 3 ruling): the importmap is emitted whenever the host has one**, including on a
  page that ends up with zero imports. The old `len(packageReferences) > 0` gate is gone: a
  page's inline module scripts may use bare specifiers, and those resolve only through the
  importmap.
- **Decided (quad): rendered output is versioned in the render caches.** The page and utility
  render caches are keyed by CR-status checksums only, so a new binary would serve the previous
  binary's renders (without #246) as current, and a rollback would serve the new ones.
  `renderFormatVersion` is part of those caches' class names (`page.v2`, `utility.v2`), so two
  binaries never read each other's renders. Bump it whenever rendered HTML or head output
  changes. The `nav` cache is unversioned: navigation fragments carry no head output.

**Known site impact, already arranged.** knowdrive-site's top bar renders `<knowdrive-usermenu>`
(defined by `@recourse-software/knowdrive-shell`) without importing the shell, relying on the
eager import (`packages/topbar/src/Topbar.jsx:257-267`). That affects 20 pages. The site
session has the user's okay to fix it site-side and ships that fix **before** this release
goes out. Its planned fix is for the top bar to dynamically import the shell, through the
importmap, when it shows a signed-in user. host-manager carries no shim for it.

**Release gate (my call).** Tagging host-manager doesn't deploy anything, so the tag needn't
wait. The **infra pin** is the deploy, and it waits until the site session confirms its
top-bar fix is live on the hosts being pinned. The site session is reachable as `site`
(SendMessage) and has promised to report when the fix is live on dev. Mention #246 in the
heads-up.

**Tests.** `HeadScriptToHTML` on a host with an aggregate of several apps and a page declaring
one must:
- import only the page's package plus the host-scope ones;
- produce byte-identical output across repeated calls (order);
- still carry the full importmap.

Also cover a utility page, and a reconciler-level check that the packages image and importmap
inputs still carry the full aggregate.

## #247: compress host-manager's own responses

**Precedent.** `/-/openapi` (`internal/host/handlers.go`, `openapiHandler`) was already wrapped in
`gzhttp.GzipHandler` from `github.com/klauspost/compress` v1.20.1, which is already a dependency.
Its ETag was seeded with `acceptEncodingSeed(r)` so each coding has its own ETag
(RFC 9110 8.8.3). It now goes through the same mechanism as every other compressed route
(below).

**Change.**
- **Decided: compression is decided once, in `DesignMiddleware`, not wrapped route by route.**
  A route opts in by being registered as `compressible(handler)` (outermost wrapper). The
  compressible routes are:
  - the page routes registered in `handlers.go` (the `pageHandlerFunc` registration loop,
    including the `patternPath` and per-language twins);
  - `NavigationGet`;
  - `TranslationGet`;
  - the login and announcement utility pages, and `/-/openapi`.

  An unmatched request (whose response is the 404 error page) is compressed too.
  `DesignMiddleware` matches against the mux it is actually dispatching to (the snapshot
  `ServeHTTP` passes as `next`), never a re-read of `hh.Mux`, so a rebuild during the
  authentication pass cannot send a function response through gzhttp.
- Do not wrap at the mux root. Function proxies, backend proxies, SSE and `/-/transfer` must
  stay untouched.
- **Decided: rewrite aliases are never compressed, whatever their target.**
  `rewrite.targetRef.kind` may be a `KDexFunction`, and `rewriteResponseWriter` keeps
  Flush/Hijack so SSE streams through it. gzhttp v1.20.1 has no `text/event-stream` exclusion,
  so it would buffer the stream. The alias calls its target's handler directly, beneath
  `DesignMiddleware`'s decision, so **an alias to a page is served identity** too. A possible
  future fix is to mark compressible the aliases whose `targetRef.kind` is a page.
- **The re-rendered error page.** `DesignMiddleware` (`internal/host/feedback.go`) wraps the
  whole mux in `errorResponseWriter`. For any status ≥400 sent to a client that accepts HTML,
  `hh.unwrap` replaces the body with the error utility page through `serveError`. This covers
  mux 404s and function/backend 4xx/5xx responses. That replacement is host-manager's own HTML,
  so it **does** carry the #248 headers.
- **Where compression sits (decided while planning).** `DesignMiddleware` wraps the writer in
  gzhttp *outside* `errorResponseWriter`. It does so only when the matched handler is marked
  compressible (pages, utility pages, translation, navigation, openapi) or nothing matched (the
  404 error page). This gives:
  - **The error message stays plain.** The error capture sees uncompressed bytes, so
    `ew.statusMsg` is never compressed.
  - **Preserved headers survive.** The handler writes straight to the error writer, so
    `auth.PreserveHeader`'s type assertion still finds it, and the denial headers survive
    `unwrap`'s wipe without any change to `PreserveHeader`.
  - **The compressor never touches a function.** A function or backend URL is not compressed,
    and neither is the error page host-manager renders over it. Error pages are small, so that
    costs little.
  - **`Vary` must be put back.** `unwrap`'s wipe deletes the `Vary: Accept-Encoding` gzhttp
    added up front, so `unwrap` restores it.
- **Decided: the Accept-Encoding ETag seed applies only where gzhttp is in play.**
  `applyCachingHeadersWithSeed` folds `acceptEncodingSeed(r)` into the ETag only when the
  response's `Vary` already lists `Accept-Encoding`, which gzhttp adds before the handler runs.
  A route gzhttp never wraps (the favicon, a schema) keeps one ETag for every coding, and a HEAD
  (which gzhttp never compresses) gets the identity ETag. The language and per-page seeds stay.
  A 304 must never be answered for a coding the client didn't get. gzhttp's `SuffixETag` is not
  used: it does not strip the suffix from `If-None-Match`, so the 304 check would never match.
- **When `If-None-Match` is present, `If-Modified-Since` is ignored** (RFC 9110 13.1.3).
  Otherwise a matching date would answer 304 for a coding, language or page the client's ETag
  says it does not hold.
- Redirect responses (301 legacy redirects, login redirects) are fine wrapped or not; the
  builder chooses.
- gzhttp's default minimum size and content-type filter are acceptable.

**Tests.** For a page, a utility (error) page, translation and navigation:
- `Accept-Encoding: gzip` gets `Content-Encoding: gzip` and `Vary: Accept-Encoding`, and the
  body decompresses to the uncompressed render;
- no `Accept-Encoding` gets an identity body;
- ETags differ between the two, and a conditional request with the gzip ETag plus gzip encoding
  gets a 304;
- the gzip ETag plus a validating `If-Modified-Since`, with no `Accept-Encoding`, gets a 200
  identity body;
- `Accept-Encoding: zstd, gzip` gets `Content-Encoding: zstd`.

A function proxy route is still not compressed by host-manager.

## #248: security headers on page and utility-page responses

**Defaults, always on for rendered pages, text-mime pages and utility pages:**

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` (text pages already send it) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | `frame-ancestors 'self'` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Strict-Transport-Security` | `max-age=<maxAge>[; includeSubDomains][; preload]`, **only when `routing.scheme` is `https`** |

These are set before the handler writes, so a handler that needs stricter values overrides them.
Consent uses `Set` for X-Frame-Options and Referrer-Policy. Its `frame-ancestors 'none'` is
`Add`ed, and browsers enforce every CSP header they receive, so the stricter policy wins either
way. Verify that the consent pages still send `DENY` / `'none'` / `same-origin`.

A page whose CRs or archetype author their own `<meta http-equiv>` is unaffected; headers are
the transport layer.

**HSTS knob, kdex-crds.** A new optional field on `Routing` (`api/v1alpha1/types.go`), placed
next to `scheme` because HSTS only applies under https. Builder's call: `routing.hsts`.

```go
// hsts tunes the Strict-Transport-Security header host-manager sends on
// rendered pages when scheme is https. Unset sends max-age=31536000 with
// neither includeSubDomains nor preload.
// +kubebuilder:validation:Optional
HSTS *HSTS `json:"hsts,omitempty"`

type HSTS struct {
	// maxAge in seconds. 0 sends max-age=0, which tells browsers to forget
	// the policy (the way to back one out). Unset means 31536000.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=63072000
	MaxAge *int32 `json:"maxAge,omitempty"`
	// includeSubDomains extends the policy to every subdomain. Opt-in:
	// it pins tenant subdomains of the same apex.
	IncludeSubDomains bool `json:"includeSubDomains,omitempty"`
	// preload adds the preload token. The HSTS preload list requires
	// includeSubDomains and a max-age of at least 31536000.
	Preload bool `json:"preload,omitempty"`
}
```

- **Validation (CEL on `HSTS`):** `preload` requires `includeSubDomains` and an effective
  `maxAge >= 31536000` (unset counts as 31536000). It's a bounded scalar rule, so the CEL cost
  budget is fine.
- **Builder's calls:**
  - the one-year default;
  - `0` as the explicit back-out;
  - the two-year ceiling, matching common preload guidance.
- **Release:** kdex-crds bump via `./updateCrdUsage.sh -t`, then release **both host-manager and
  nexus-manager**. A new field is a CRD serialization change, and every actor gets released.
  Run each actor's `make test`, not just `go build`.
- **Wiring:** host-manager reads `internalHost.Spec.Routing` (already passed to `SetHost` as
  the scheme) and precomputes the header value once per `SetHost`, not per request.

**Where the headers are applied.** One small helper (e.g. `hh.setPageSecurityHeaders(w)`)
called from:
- `serveRendered`, which the login and announcement pages also serve through;
- `serveText`, folding in its existing nosniff line;
- the error and consent serve paths (consent then tightens);
- `NavigationGet`, whose fragments are per-user HTML (added by the quad).

Calling it on the 304 short-circuit is the builder's call: browsers keep the stored response's
headers, so it isn't required. It must not be reachable from the proxy, function, backend or
module paths. **The one exception** is the error page `unwrap` renders over a ≥400 response
(see #247). That body is host-manager's HTML, so it gets the headers even at a function URL.
SAMEORIGIN still allows the inspector's same-origin preview frame. A **rewrite alias to a
`KDexFunction`** is a function response and gets no headers; the helper lives in the page and
utility serve paths, not in the alias wrapper. **Decided by me (Claude)** after the builder check.

**Tests.**
- Each default is present on a rendered page, a text page and the error page.
- HSTS is present under https, absent under http, and honours `maxAge`, `0`,
  `includeSubDomains` and `preload`.
- The consent pages keep their stricter values.
- A successful proxied function response, and a function reached through a rewrite alias,
  carries none of them.
- The HTML error page that replaces a function's 404 for a browser does carry them.
- kdex-crds envtest covers the CEL rule (accepted and rejected cases).

## Constraints

- Go 1.26.0 across kdex-crds / host-manager / nexus-manager.
- Never hand-edit the `replace kdex.dev/crds` directive; use `./updateCrdUsage.sh`.
- Run `make lint` from the workspace root after changes.
- **Run the quad before tagging (user ruling).** Cover every repo with new commits: in
  host-manager everything after 7e9f52c (the last marker, 1522978), and in kdex-crds everything
  after its last `Quad-Range:` marker. Commit the fixes as `fix(quad): …`, then add the signed
  empty marker commit with its `Quad-Range:` trailer, and only then tag.

## Left to the builder

- The exact helper names and file placement.
- Whether to wrap the 301 compatibility redirects in gzhttp.
- ~~Whether the importmap is emitted on a page that ends up with zero imports.~~ Decided: it
  is (see #246).
- Whether to call the security-header helper on the 304 path.
- How the work is ordered across commits. Suggested: kdex-crds HSTS field first, then the
  #246, #247 and #248 commits in host-manager.

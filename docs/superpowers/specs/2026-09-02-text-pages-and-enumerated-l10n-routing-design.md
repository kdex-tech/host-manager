# Text-serving KDexPages + enumerated l10n route prefixes — design

- **Date:** 2026-09-02
- **Status:** approved (brainstorm), pending spec review
- **Issues:** kdex-tech/host-manager#197 (feature), kdex-tech/host-manager#177 (400→404), GitLab recoursellm-group/knowdrive-site#137 (origin, closed/moved)
- **Repos touched:** `kdex-crds` (schema), `kdex-host-manager` (routing + serving), release also `kdex-nexus-manager` (schema-change rule)

## Problem

A `KDexHost` cannot serve any root-level file. Two independent defects and one
missing capability combine:

1. **Design flaw — the `/{l10n}` wildcard is a root-namespace catch-all.** Every
   `KDexPage` registers a base route and an `/{l10n}`-prefixed twin; the home
   page's twin is `/{l10n}/{$}`, a single-segment root wildcard matching
   `/<anything>/`. So `GET /robots.txt` → (stdlib ServeMux subtree redirect)
   `307` → `/robots.txt/` → matches `/{l10n}/{$}` with `l10n="robots.txt"` →
   `GetLang` fails to parse it as a BCP-47 tag → `400 invalid language tag:
   robots.txt`. The wildcard asserts *every root segment is a language*, which is
   false, and it intercepts `llms.txt`, `robots.txt`, `sitemap.xml`, `ads.txt`,
   and every typo.
2. **Correctness bug (#177) — `400` where it should be `404`.** `GetLang` returns
   one error for both "invalid tag" and "unsupported language", and the page
   handler maps it to `400`. A path with no resource behind it is a `404`; the
   `400` hands crawlers a hard client-error they are told not to retry, and the
   same error becomes a **`500`** in the navigation-fragment handler.
3. **Missing capability.** No user CR can register a root path or serve a
   non-HTML text body. Only `x-kdex-type: SYSTEM` routes (built into
   host-manager: `/favicon.ico`, `/.well-known/jwks.json`, …) reach the root.

The fix is three tracks, all shipping together:

- **A — text-serving `KDexPage`:** serve `robots.txt`/`llms.txt`/`sitemap.xml`
  at their canonical root path with `200` and the right Content-Type.
- **B — enumerated language prefixes:** replace the `/{l10n}` wildcard with one
  literal prefix per supported language, so unknown roots get a clean `404` and
  the namespace capture is gone.
- **C — status vocabulary fix:** a resource miss is `404`, a bad explicit
  language parameter is `400`, never `500`.

## Acceptance criteria (from GitLab #137)

- `GET https://knowdrive.ai/llms.txt` → `200 text/plain` with the file.
- `GET https://knowdrive.ai/robots.txt` → `200` with crawl rules, **or** `404` —
  never `400`.
- Same on `dev.knowdrive.ai`.

## Track A — text-serving KDexPage

### Schema (`kdex-crds`, `KDexPageSpec`)

Three new fields:

```go
// localized controls whether language-prefixed routes (/<lang>/…) are
// registered for this page. Default true. Set false for a page that must live
// at exactly one path (robots.txt, llms.txt, sitemap.xml).
// +kubebuilder:default=true
// +kubebuilder:validation:Optional
Localized *bool

// mimeType, when set, serves the page as a raw text document of this type
// instead of composing HTML from an archetype. Fixed enum.
// +kubebuilder:validation:Enum=txt;json;yaml;markdown;xml
// +kubebuilder:validation:Optional
MimeType string

// body is the content served when mimeType is set. It runs through the same
// [[ ]] Go-template + translation pipeline as a rawHTML content entry, so it
// has the l10n/translation function in scope and a localized text page (e.g.
// /en/llms.txt vs /fr/llms.txt) is valid. Paired with mimeType.
// +kubebuilder:validation:MaxLength=65536
// +kubebuilder:validation:Optional
Body string
```

**Validation (CEL `XValidation` on the spec):**

- `mimeType` and `body` come together: `has(self.mimeType) == has(self.body)`.
- `contentEntries` drops from unconditionally-required (`MinItems=1`, the
  `slot=='main'` rule) to **required only when `mimeType` is absent**. A text
  page has a `body`, not slots/archetype. Concretely: relax the field-level
  `Required`/`MinItems` and add
  `has(self.mimeType) || (has(self.contentEntries) && self.contentEntries.exists(x, x.slot == 'main'))`.
- Existing `contentEntries` rules (slot map, `main` present) become conditional
  on the HTML branch.

**Cost budget.** `body` MUST carry a `MaxLength`, and any new CEL rule must keep
the CRD within the apiserver cost estimator (see the value-struct / CEL-cost
lessons: an unbounded string or an unbounded-collection rule can make the whole
CRD fail to install; only envtest catches it). Pick a `MaxLength` generous
enough for a real `llms.txt` (the drafted one is 181 lines / ~8 KB) with margin
— proposed `65536`.

### Serving (`host-manager`)

**Registration.** A text page (`mimeType` set) registers at its **exact**
basePath — `GET /robots.txt` (Go 1.22 exact-match semantics), *not* through
`toFinalPath` — so there is no forced trailing slash, no `{$}` subtree anchor,
and no `307`. When `localized` is true it additionally registers
`GET /<lang>/robots.txt` per non-default supported language (Track B). A
`localized:false` text page registers only the bare exact path.

**Render.** `pageHandlerFunc` branches on `mimeType`:

- The authorization gate and the per-`(name, lang)` render cache are unchanged —
  a text page can still be security-gated, and a public one (no `security`)
  serves anonymously.
- Instead of composing archetype + header + footer + navigation, it renders
  **only `body`** through the existing `[[ ]]` template + translation engine
  (the same engine `rawHTML` uses; the l10n function is in scope), then writes
  the result with the mapped Content-Type. No HTML wrapper.

**mimeType → Content-Type:**

| `mimeType` | Content-Type |
|---|---|
| `txt` | `text/plain; charset=utf-8` |
| `json` | `application/json` |
| `yaml` | `application/yaml` (RFC 9512) |
| `markdown` | `text/markdown; charset=utf-8` |
| `xml` | `application/xml` |

## Track B — enumerated language prefixes

Replace the `/{l10n}` wildcard registrations in `addHandlerAndRegister` (and the
not-ready twin at `host.go:369`) with **one literal prefix per supported
language**, taken from `hh.Translations.Languages()` at registration time (the
mux is rebuilt wholesale each reconcile, so a changed language set is picked up
next cycle):

- For `pricing`: `GET /pricing/{$}` (bare = default language) plus
  `GET /<lang>/pricing/{$}` for each **non-default** supported language.
- The page handler learns its language from the **per-registration closure**
  (the matched prefix carries the language), so page routes no longer call
  `GetLang` on an arbitrary first segment. `pageHandlerFunc` gains a language
  parameter (or is wrapped per-language) rather than reading
  `r.PathValue("l10n")`.
- **Default-language canonicalization.** The default language has one canonical
  URL: the bare path. The default-language prefix `/<default>/pricing/` is
  **301-redirected to `/pricing/`** rather than serving a duplicate `200`.
- `localized:false` skips every `/<lang>/…` prefix, registering only the bare
  path.

Consequence: an unknown root (`/robots.txt` with no page, `/xx/…` for an
unsupported `xx`) matches nothing and falls to the not-found handler — a clean
`404`, no redirect, no `400`. Registered pages are unaffected: Go ServeMux gives
a literal segment precedence over any remaining wildcard, and a page whose
basePath *is* a language code still wins (verified in the investigation).

## Track C — status vocabulary

With enumerated prefixes, a page route's language is known from the prefix, so
the page handler **never surfaces a raw `400` for a language miss** — that class
is eliminated structurally. Remaining cleanups:

- The navigation-fragment handler (`navigation.go`) returns `500` for a bad
  `{l10n}`; change to `400`. A caller-supplied language in
  `/-/navigation/{navKey}/{l10n}/…` is at worst a client error, never a server
  fault, and per the denial-contract conventions a `500` wrongly signals an
  outage.
- `/-/translation/{l10n}` keeps its `400` (also an explicit API parameter).
- Net: one vocabulary — `404` for a resource miss, `400` for a malformed
  explicit parameter, never `500`.

## Cross-cutting

- **Back-compat.** `localized` defaults `true`, so every existing page keeps its
  localized routes — now `/en/…`, `/fr/…` instead of the `/{l10n}` wildcard. The
  only intended behavior changes for existing sites: unknown roots return `404`
  not `400`, and the default-language prefix `301`s to the bare path. No existing
  manifest needs editing.
- **`/-/openapi` growth.** Per-language rows replace the single wildcard row, so
  the document grows by roughly `(languages − 1) × pages`. Acceptable — the
  investigation measured the route table at hundreds of entries against a trie.
- **Unsupported-language prefixes now 404.** `/{l10n}` previously matched any
  first segment; `/xx/pricing` for an unsupported `xx` now `404`s instead of
  rendering the default-language page. This is the intended tightening.
- **Out of scope / accepted:** the universal trailing-slash `307` on HTML page
  routes (`toFinalPath`'s `{$}` canonicalization) stays — it is expected
  canonicalization for HTML pages, and text pages opt out via exact-path
  registration. The default-language duplicate-content issue is resolved by the
  `301` above.

## Release plan (schema-change rule)

1. Land the `kdex-crds` schema change; `make manifests generate test lint`.
2. From the workspace root: `./updateCrdUsage.sh -t` — bumps the `kdex-crds`
   patch tag and updates `go.mod`/`go.sum` in host-manager and nexus-manager.
3. Implement Tracks A/B/C in host-manager.
4. Release **both** host-manager and nexus-manager (a serialization change
   releases all actors, even though nexus does not read the new fields).

## Testing (TDD)

- **Schema (envtest):** `mimeType`/`body` pairing; `contentEntries` required
  only without `mimeType`; the CRD installs within the CEL cost budget (only
  envtest catches an over-budget rule).
- **Routing:** enumerated prefixes register per language; unknown root → `404`
  (no `307`, no `400`); default-language prefix → `301` to bare;
  `localized:false` → bare path only; a page whose basePath is a language code
  still resolves.
- **Serving:** a text page serves `body` at its exact path with `200` and the
  mapped Content-Type, no `307`; the `[[ ]]` template + translation is applied
  (a localized text page differs by language); no HTML chrome; a gated text page
  still denies per the contract.
- **Status:** navigation bad-`{l10n}` → `400` not `500`.
- **Acceptance:** `GET /robots.txt` and `GET /llms.txt` against a host with the
  corresponding text pages return `200` + correct Content-Type; the same paths
  with no page return `404`, never `400`.

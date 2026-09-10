# Default landing paths — post-login/forbidden landing policy

**Date:** 2026-09-10
**Status:** Approved (design)
**Repos touched:** kdex-crds (new field), kdex-host-manager (consume it), kdex-nexus-manager (bundled CRD schema + release)

## Problem

When the root page `/` is gated, an anonymous visitor is redirected to
`/-/login?return=%2F`. After a successful login the user is redirected back to
`return` (`/`). But a user who authenticated may *still* lack `pages:/:read` —
so the page gate denies `/` again, now classified `Forbidden` (a credential is
present), and takes the discovery-redirect branch, which sends the user to
`firstAuthorizedPage()`.

`firstAuthorizedPage()` returns the accessible top-level page with the lowest
`navigationHints.weight`, ties broken by `basePath` (deterministic since #184).
Because every page defaults to `weight: 0`, in practice this collapses to
"alphabetically-first accessible top-level page" — an arbitrary destination from
the user's point of view. There is no way to express an *intended* landing page
that differs by what the user is entitled to, short of abusing `weight` (which
also reorders the navigation menu — the two concerns are coupled today).

## Current flow (unchanged parts)

1. Anonymous → gated page: `page.go` classifies `Unauthenticated`, no
   credential, login page exists, HTML → `303 /-/login?return=<RequestURI>`.
2. Login success: `login.go:LoginPost` → `303` to `SafeReturnPath(return)`
   (empty/unsafe collapses to `/`).
3. Gate re-runs, now authenticated. If still denied → `Forbidden`, and (when
   `pageDenialMode != PageDenialForbid`, HTML, and no `?denied=` marker yet) a
   discovery redirect to `firstAuthorizedPage()` with `?denied=<path>`.

The change touches **only** step 3's discovery-redirect branch
([internal/host/page.go](../../../internal/host/page.go), ~L143-163). `login.go`
is **not** changed: an accessible `return` already renders on arrival, so the
list only needs to participate where the gate denies.

## Resolution order (the decision)

When the page gate denies and would otherwise discover a fallback:

1. **`return`, if accessible** — already honored by the existing flow (the user
   is sent to `return`; its gate passes; it renders). Real deep-links win.
2. **`defaultLandingPaths[]`, first accessible** — NEW. Walk the list in order;
   the first entry the user is entitled to render is the redirect target.
3. **`firstAuthorizedPage()`** — existing safety net, consulted only when no
   list entry matched (or the list is empty/unset).
4. **403 denial page** — when nothing is accessible / discover mode is off.

Unset or empty `defaultLandingPaths` ⇒ behavior is byte-identical to today.

## Design

### CRD field

`KDexHost.spec.auth.defaultLandingPaths []string` (kdex-crds
`api/v1alpha1/kdexhost_types.go`, on the auth config type alongside the existing
auth fields).

- Authors write **canonical basePaths** (`/dashboard`, `/home`) — NOT
  language-prefixed. host-manager applies the `/<lang>` prefix at redirect time,
  exactly as `firstAuthorizedPage` does for a non-default language.
- Validation is kept **per-item and cheap** — no rule-level CEL iterating the
  list (an XValidation over an unbounded `[]string` makes the whole CRD fail to
  install via the apiserver cost estimator; see the crd-cel-cost-budget note):
  - `+kubebuilder:validation:MaxItems=16`
  - item `+kubebuilder:validation:MaxLength=512`
  - item `+kubebuilder:validation:Pattern=^/.*` — must start with `/`. CRD
    patterns compile with **RE2**, which has no lookahead, so the "not under
    `/-/`" constraint is NOT expressed in the pattern.
  - "not under `/-/`" is a **per-item** CEL rule on the items schema
    (`+kubebuilder:validation:XValidation:rule="!self.startsWith('/-/')"`),
    bounded by the item `MaxLength` — cheap, and NOT a rule over the whole list
    (which is what trips the apiserver cost estimator). An entry that slips
    through anyway (e.g. an odd `/-/…` value on an older cluster) simply resolves
    to no page and is skipped at runtime — validation is defense, not the only
    guard.
- `omitempty`; a decode/omitempty test asserts the field round-trips and is
  absent when unset (kdex-crds `omitempty_test.go` / `accessors_test.go` style).

### host-manager consumption

In `page.go`, the discovery-redirect branch computes the target via a new helper
rather than calling `firstAuthorizedPage()` directly:

```
target := hh.discoverLandingPage(ctx, &l, isDefaultLanguage, parsedUserEntitlements)
```

`discoverLandingPage`:

1. For each `p` in `hh.authConfig` / host `defaultLandingPaths`:
   - resolve `p` to its `PageHandler` (by `BasePath`, same lookup the nav walk
     uses); skip if none.
   - if the handler has `ParsedRequirements`, run the SAME
     `authChecker.VerifyResourceParsedEntitlements("pages", p, userEnts, reqs)`
     used by the gate and by `firstAuthorizedPage`. Skip on deny or on a checker
     fault (a fault is not an authorization — treat as "not a candidate", do not
     500 the discovery step).
   - a handler with no requirements is accessible to everyone → it matches.
   - first match wins; return `p`.
2. If no entry matched, return `firstAuthorizedPage(...)`.

The caller keeps the existing language-prefixing (`/<lang>` when not default),
the `?denied=<r.URL.Path>` one-hop marker, and `Cache-Control: no-store`. The
`!r.URL.Query().Has("denied")` guard still bounds the whole thing to one hop —
the same TOCTOU note the existing code documents applies (walk-check and
render-check are separate; the marker is the bound), and it now covers list
entries identically.

### Scope boundaries

- **Pages only.** Mirrors `firstAuthorizedPage`; the function/proxy identity gate
  is untouched.
- **No implicit `/` prepend.** Empty ⇒ `firstAuthorizedPage`.
- **Discover mode only.** Inside the existing
  `pageDenialMode != PageDenialForbid && acceptsHTML && !denied` branch;
  `PageDenialForbid` hosts still 403.
- **Non-HTML callers** fall through to the denial contract (401/403) exactly as
  today — the list is a browser-navigation convenience, not part of the contract.

## Testing

kdex-host-manager `internal/host/page_test.go` (envtest):

1. Forbidden `return`, user is entitled to list entry #2 (not #1) → redirect to
   entry #2's basePath.
2. User entitled to no list entry → `firstAuthorizedPage` fallback fires.
3. A list entry names a page the user is NOT entitled to → skipped (next entry,
   then fallback).
4. A list entry names a non-existent basePath → skipped.
5. Empty/unset `defaultLandingPaths` → behavior identical to pre-change (assert
   `firstAuthorizedPage` path).
6. Non-default language → target carries the `/<lang>` prefix.
7. `PageDenialForbid` mode → 403, list never consulted.

kdex-crds: decode/omitempty test for the new field; `make test lint`.

Run `make test` on **both** host-manager and nexus-manager, not just
`go build` — a schema/validation change can break downstream tests that pin
messages (the CRD-serialization-change rule).

## Release path

1. kdex-crds: add field + markers, `make manifests generate test lint docs`.
2. From workspace root: `./updateCrdUsage.sh -t` (bumps kdex-crds patch tag,
   regenerates, updates go.mod/go.sum in host-manager + nexus-manager).
3. host-manager: implement + tests, tag a release.
4. nexus-manager: pick up the CRD bump (bundled schema), tag a release.

A new CRD field is a serialization change ⇒ release **both** host-manager and
nexus-manager even though neither's runtime behavior for existing CRs changes.

## Backward compatibility

- Field is optional and `omitempty`; existing `KDexHost` CRs decode unchanged.
- With the field unset/empty, host-manager behaves exactly as before
  (`firstAuthorizedPage` fallback).
- No change to the denial contract, the login flow, or non-HTML responses.

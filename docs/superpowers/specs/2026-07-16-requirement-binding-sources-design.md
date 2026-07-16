# Design: Requirement binding sources — declare the source, and only where the AS is the authority

**Date:** 2026-07-16
**Scope:** kdex-host-manager (the binder), knowdrive-site CRs, knowdb (#360), kdex-kcnas rule 8
**Status:** design — resolves the blocker left open by the v0.4.0 release
**Depends on:** `kdex-entitlements` v0.4.0 (`BindRequirements`, `{param}`)
**Predecessor:** `kdex-entitlements/docs/superpowers/specs/2026-07-15-requirement-placeholders-design.md`

## Problem

`kdex-entitlements` v0.4.0 gives a requirement the `{param}` form and binds it at
check time. host-manager (the AS) must now supply those bindings at the gate
(`internal/host/proxy.go:501-513`). Path params are unambiguous. Headers are not:
knowdb hardcodes `X-Vector-Store-Id`, but host-manager is generic across every
`KDexFunction`, so *something* must tell it which header feeds
`{vector_store_id}`.

The question as originally posed — **"naming convention or explicit per-op
declaration?"** — turns out to be the less important half. Both answers are
wrong on their own, because they share a false premise: that reading a value
from the request is the same as knowing the value the backend will act on.

## Finding 1: the mapping is already declared

`KDexFunction.spec.api` is an OpenAPI document, and every op that targets a
store **already declares its source as an ordinary OpenAPI parameter**:

```yaml
# knowdrive-site/k8s/dev/function_knowdb_ingest.yaml:207-209
parameters:
  - name: X-Vector-Store-Id
    in: header

# knowdrive-site/k8s/dev/function_knowdb_vector_stores.yaml:951-956
parameters:
  - name: vector_store_id
    in: path
```

Real `in: header` declarations across the knowdb CRs today: `files` 3, `search`
2, `ingest` 1, `uploads` 1. The author already wrote the mapping. Nothing reads
it.

So no naming convention is needed to *name* a source, and no CRD schema change
is needed to *carry* one. The plumbing is verified end to end:

- `kdex-crds/api/v1alpha1/kdexfunction_types.go:143-144` — `spec.api` carries
  `+kubebuilder:pruning:PreserveUnknownFields`, so the apiserver keeps `x-*`.
- `kdex-crds/api/v1alpha1/types.go:920` — `PathItem.GetOp()` unmarshals the
  `RawExtension` into kin-openapi's `openapi.Operation`, whose `UnmarshalJSON`
  dumps every unknown `x-*` key into `Operation.Extensions`
  (kin-openapi v0.133.0, `openapi3/operation.go:16,119`).
- `kdex-host-manager/internal/host/proxy.go:329` — the mux-build loop already
  holds `op` at the exact site that caches
  `parsedRequirements[method+" "+p]`. A per-route binding spec parses once per
  route, same lifecycle. No new plumbing.

A dedicated CRD field would also buy nothing in validation: `spec.api`'s
operation bodies are `RawExtension` and therefore opaque to CEL. Getting
apply-time validation would mean hoisting the binding *outside* `spec.api`,
divorcing it from the op it describes and dropping it to per-function
granularity — reintroducing exactly the drift this contract exists to prevent.

## Finding 2: readability is not authority

`kdex-kcnas` rule 8 tests whether the AS can *resolve the identity from the
request*. By that test `/ingest` passes: `X-Vector-Store-Id` is right there in
the headers. The test is wrong.

knowdb's `effective_vs` (`multi-modal-store/src/api.rs:872-883`) resolves an
unscoped handler's target as **body → header → `system`**. The multipart body
wins, and neither host-manager nor knowdb's own middleware can read it — the
entitlements middleware runs before the body is parsed.

knowdb knows. `ingest_handler` (`src/api.rs:2264` ff.) carries a re-check whose
comment names the attack directly:

> *Issue #60: the route-level middleware resolves the VS contextually (URL /
> `?vector_store_id=` / `X-Vector-Store-Id` header → `system` only when
> scopeless) but is blind to a multipart-body `vector_store_id`, so it may have
> authorized a different scope than the effective target. Without this re-check
> a token scoped to any one store could ingest into another.*

So binding `{X-Vector-Store-Id}` on `/ingest` gates **a store that is not the
target**. Header `vs_alice` + body `vs_bob` passes the gate on `vs_alice`;
knowdb's #60 re-check is what actually stops the write. The gate is not
dangerous — the backend holds the line — it is *useless*, and it is not free:
under `unbound ⇒ error` a legitimate body-only caller is denied at the gate for
omitting a header that would not have decided anything.

**The correct test is not "can the AS read a source?" but "can the AS derive the
value the backend will act on?"** A readable-but-outranked source is still
underivable, because deriving the fallback is not deriving the target.

This makes rule 8's category **"row-derived"** too narrow. The real category is
**AS-underivable**, comprising:

- **row-derived** — `GET /v1/files/{file_id}` checked against the file's
  `vector_store_id`; needs a table lookup.
- **body-derived** — `/ingest`'s multipart `vector_store_id`; needs body
  parsing the gate does not do.
- **readable-but-outranked** — any source the AS *can* read that is outranked
  by one it cannot.

## Evidence: measured, not reasoned

knowdb's spec test pins the exact set of routes that honor the header
(`tests/suite/url_ingest_test.rs:666-673`):

`POST /v1/ingest` · `POST /v1/files` · `GET /v1/files` · `GET /v1/search` ·
`POST /v1/search` · `POST /v1/uploads`

Those six are **precisely the six `effective_vs` call sites**
(`src/api.rs:1528, 2264, 2797, 3187, 4062, 7117` →
`upload_create_handler`, `ingest_handler`, `search_handler`,
`search_multipart_handler`, `openai_upload_file_handler`,
`openai_list_files_handler`). Every one of them puts a body or query value
ahead of the header.

> **Zero of the nine unscoped routes has an authoritative header today.**

Not one is bindable as-is. That is not a wrinkle in the plan; it is the plan's
premise being false.

### Correction to the predecessor design doc

`2026-07-15-requirement-placeholders-design.md:68` states, in the evidence table
that motivates the entire feature:

| requirement | actual meaning | can the enforcing layer bind it? |
| --- | --- | --- |
| `vector_stores:*:write` on `/ingest` | the store in `X-Vector-Store-Id` | **yes** — a header |

The store is in the **body**; the header is a fallback. That row is the same
class of error as the `file_id` trap caught late in the v0.4.0 session — sitting
in the document that argued for the fix, and it is the canonical header example
a naming convention would have been derived from. **v0.4.0 itself is unaffected**
(the library is correct; only the doc's evidence is wrong).

### Is the body override used?

Checked rather than assumed:

- **No knowdrive-site client targets via the body.** The dashboard
  (`packages/dashboard/src/api.js`) only calls `/vector_stores` and
  `/vector_stores/{id}/stats` — it never calls `/ingest`. Its only
  `vector_store_id` use is client-side event filtering.
- **The kd-handoff plugin uses the header**, and its reference doc records that
  a body-only `vector_store_id` already 403s for scoped callers (the middleware
  falls back to `system`).
- **MCP is a separate surface.** `/mcp` is exempt from the entitlements
  middleware; MCP tools target via JSON-RPC args with `default_vs`, not an HTTP
  body. (That is #360's "6 MCP tools" half.)
- **OpenAI compat is not at risk.** `vector_store_id` is not an OpenAI Files API
  field — it is a knowdb extension to that body, so removing it costs no
  compatibility.

The **query** override is a different story: `?vector_store_id=` on
`GET /v1/search` and `GET /v1/files` is real and tested
(`tests/suite/vector_store_search_get_test.rs`). Query is AS-readable, so it
does not need removing — it needs ordering.

## Resolution

### The grammar

**The placeholder key is a logical identity, not a source.** It stays
`{vector_store_id}` on every op, so it reads consistently, keeps parity with
`x-required-entitlement`, and keeps `WildcardRequirements`' migration inventory
coherent across ops.

**Path — identity match, no declaration.** `{vector_store_id}` in `security`
matching `{vector_store_id}` in the path pattern is not a convention; it is an
identity match against a pattern present in the CR. Covers the ~15 scoped ops
with zero annotation.

**Non-path — declare the ordered source chain**, via an operation-level
extension beside `security` and `x-required-entitlement`:

```yaml
security:
  - bearer: ["functions:/api/v1/ingest:read", "functions:/api/v1/ingest:create",
             "vector_stores:{vector_store_id}:write"]
x-entitlement-binding:
  vector_store_id:
    - { in: header, name: X-Vector-Store-Id }
```

A chain of length 1 is the common case; the two query-overridable GETs need two
links, in the backend's own precedence order:

```yaml
x-entitlement-binding:
  vector_store_id:
    - { in: query,  name: vector_store_id }
    - { in: header, name: X-Vector-Store-Id }
```

### The legality rule

> **An op may declare a `{param}` in `security` only if the AS can read *every*
> link in the backend's precedence chain for that identity.**

If any higher-precedence source is AS-unreadable — a body, a table — the op is
**not bindable**. Do not declare the placeholder. Keep `security` at the coarse
gate the AS can enforce (`functions:<basePath>:<verb>`) and publish the real
requirement through `x-required-entitlement` as prose, where nothing parses it.
This is rule 8's row-derived treatment, generalized.

No header fallback by convention. An undeclared non-path source is an error, not
a guess: host-manager is generic across every function and must never infer the
header spelling of a backend it does not control.

### Why no over-restriction guard is needed

knowdb ignores the header on `NameDefault::Wildcard` routes deliberately
(`src/auth/entitlements.rs:16-19`) — *"to prevent the header from making a check
more restrictive than the caller's actual grants."* That guard is an artifact of
knowdb's always-resolve design: its table produces a name for **every** route,
so it needs a rule to stop a caller-supplied header leaking into routes that do
not use it.

host-manager's binder is the opposite shape: it binds **only** placeholders the
CR declares. A row-derived op declares none, so nothing binds and the gate stays
coarse. The failure mode cannot arise, and the guard does not transfer.

## Classification: the nine unscoped routes

`NameDefault::System` in knowdb's `ROUTE_AUTH` (`src/auth/entitlements.rs:503`
ff.) is, in effect, the AS-resolvable/row-derived classification — a
machine-checkable cross-reference for the 42-op inventory in knowdrive-site#33
rather than a hand re-derivation. It splits three ways, not two:

| routes | today | after #360 | disposition |
| --- | --- | --- | --- |
| `POST /v1/ingest`, `POST /v1/uploads`, `POST /v1/files`, `POST /v1/search` (multipart) | body outranks header → **not bindable** | header authoritative | drop the body field → `{vector_store_id}` via header |
| `GET /v1/files`, `GET /v1/search` | query outranks header; both AS-readable | unchanged | `{vector_store_id}` via a 2-link chain |
| `POST /v1/vectorize`, `POST /v1/embeddings`, `GET /v1/events` | no per-request identity at all | — | never bindable; coarse or opaque |

The third group needs calling out: knowdb #327 established that `GET /v1/events`
**does not honor the header** — its handler has no `HeaderMap` extractor and
reads only `prefix`; a test asserts it must not document one
(`url_ingest_test.rs:684-690`). It is a class-wide read scoped server-side by
the caller's entitlements. Yet it is `NameDefault::System`, so the middleware
checks `vector_stores:system:read` on a request with no store to target. That
incoherence is #360's to resolve.

**Doc drift found:** `knowdrive-site/k8s/dev/function_knowdb_events.yaml:19-20`
still claims GET /v1/events is *"header-overridable via X-Vector-Store-Id"*.
Stale comment only — no real `in: header` declaration — but it contradicts #327
and should go with the migration.

## Consequence: extend #360

knowdb #360 already removes the `system` fallback on exactly these routes, with
the goal *"addressing a store becomes explicit."* The body override is the same
disease, and it is what made #60's re-check necessary. Fold it in as one
coherent change rather than a new issue:

> **The `X-Vector-Store-Id` header is the only unscoped targeting mechanism for
> the four body-overridable routes, and it is mandatory. The two GETs keep
> `?vector_store_id=` ahead of it.**

Blast radius:

- `effective_vs` drops its `body_vs` parameter — 6 call sites.
- The `vector_store_id` field leaves three request bodies (ingest multipart,
  uploads JSON, files multipart) and their CR OpenAPI
  (`function_knowdb_ingest.yaml:238-244` and siblings).
- Tests asserting body precedence update; the header-path tests
  (`unscoped_search_routing_test.rs`) survive unchanged.
- #60's re-check **stays** — it drops from load-bearing to defense in depth.

## Cross-repo order

Amends the predecessor's order with what the evidence now requires:

1. **entitlements v0.4.0** — shipped (`dba4916`).
2. **host-manager binder** — declaration-driven; re-match the pattern (see
   below). Inert until a CR declares a `{param}`. Independently deployable.
3. **knowdb #360 (extended)** — remove the `system` fallback *and* the body
   override. Makes the four flagship routes bindable.
4. **kdex-crds + host-manager** — opaque grants (#15). Both halves together.
5. **roles** — grant the opaque capabilities. Additive.
6. **CRs** — migrate per the three-way classification above. **The four
   body-overridable ops must not adopt `{param}` before step 3**: today a
   wildcard holder (`vector_stores::all`) who omits the header is defaulted to
   `system` and succeeds; under the binder they would be denied at the gate.
7. **entitlements v1.0.0** — flip strict once `WildcardRequirements` drains.

## Implementation notes for the binder

- **`r.PathValue` does not work at the gate.** `patternMux` has empty handlers
  and is consulted via `Handler(r)`, which returns the pattern but never
  populates path values. Re-match the pattern against `r.URL.Path` — port
  knowdb's `path_param_from_match` (`src/auth/entitlements.rs:358`), including
  its trailing-catch-all handling (#347): a `{*name}` segment absorbs one-or-more
  URI segments, so an exact segment-count match silently drops
  `{vector_store_id}` to the wildcard fallback.
- Parse `x-entitlement-binding` from `op.Extensions` at mux-build
  (`proxy.go:324-344`), alongside `ParseRequirements`; cache per route.
- Bind per request immediately before `VerifyResourceParsedEntitlements`
  (`proxy.go:512`), after the authContext enrichment invariant (#142,
  `proxy.go:496-498`).
- A binder that cannot resolve a value must **fail like an unbound placeholder,
  never widen** — do not port knowdb's `system` / `*` defaults, which are
  knowdb policy, not binder behavior.

## Authoring-time enforcement (still open)

Nothing catches a violation of the legality rule at `kubectl apply` time — an
author can put a body-derived requirement in `security` and it surfaces only as
a runtime error. `--dry-run=server` will not catch it, and CEL cannot see inside
`spec.api`'s `RawExtension`. The failure is loud and fail-closed, but late.

A lint check now has two things to enforce, not one:

1. the tier invariant (nothing AS-underivable in `security`), and
2. binding completeness (every non-path `{param}` has an
   `x-entitlement-binding` chain, and every link is AS-readable).

`scripts/knowdb-align-check.py --merge` remains a hazard: it injects a missing
entitlement across alternatives but cannot tell AS-derivable from underivable.
Review its output against the classification table above; a blind merge is the
trap, mechanized.

## Out of scope

- A CRD field for the binding (`spec.api` is opaque to CEL; the extension rides
  the existing `PreserveUnknownFields` path).
- Any change to `Dominates`, `VerifyAttenuation`, or `Compact`.
- knowdb's `Wildcard` default (#361, 39 routes) — its own track.
- MCP-surface entitlements (`/mcp` is exempt from the middleware; backend-enforced).

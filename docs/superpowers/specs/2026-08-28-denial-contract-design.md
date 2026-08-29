# Design: One denial contract — stop spelling "forbidden" as "not found"

**Date:** 2026-08-28
**Scope:** kdex-host-manager only — no CRD change, no `kdex-entitlements` change, one release
**Status:** design — awaiting review
**Retires:** the per-gate anti-enumeration 404 as a security posture

## Problem

host-manager answers "you may not have this" in five different vocabularies,
and the choice between them is not a policy decision — it is whichever branch
the request happened to fall into. Measured anonymously against dev on
2026-08-28:

| request | answer |
|---|---|
| `GET /-/openapi` | **200**, 182 paths — 36 of them `/api/v1/*` |
| `GET /api/v1/vector_stores` | **404** |
| `GET /api/v1/mcp` | **401** + `WWW-Authenticate: Bearer resource_metadata="…"` |
| `GET /api/v1/files` | **403** |

Three answers to one question on one host, from one caller, in the same second.

The 404 is deliberate — it conceals whether a path exists. That concealment has
a cost, and the cost is paid constantly. The `kdex-kcnas` skill documents the
same root cause as a trap in three independently-discovered places:

- *"This is the #1 non-obvious entitlement trap, and the symptom is a 404, not a
  403"* — the two-stage identity gate.
- *"a `security: []` endpoint works when called anonymously but silently 404s
  for a logged-in user"* — so the side effect never fires and the only trace is
  a `V(1)` DEBUG line.
- *"Anonymous and under-entitled callers silently fall through to a 404 —
  there's no 403, so the symptom is 'I hit the URL, expected a 303, got 404'"* —
  the Request Sniffer.

Every one of those is the same defect: a denial is spelled identically to a
typo in the URL, so nobody can tell them apart — least of all the person who
wrote the CR.

## Finding 1: the concealment is already void

`/-/openapi` has no entitlement check and no caller-based filtering
(`internal/host/openapi.go:10`). It serves every registered path of every
`Ready`, non-`Internal` function to anyone. Measured: **200 anonymous, 182
paths, 36 under `/api/v1`, including `/api/v1/vector_stores`** — the exact path
that 404s.

So the 404 conceals a path that is already published, and published *more
cheaply than probing*: one anonymous request enumerates 182 paths. Enumeration
is not merely possible by other means; it is easier by other means. The 404
costs an actionable rejection and buys nothing.

**This finding is the contract's load-bearing dependency.** If `/-/openapi` is
ever gated or caller-filtered, the trade reverses and this design is what should
be revisited. That dependency belongs in a code comment at the denial site, not
in tribal knowledge.

## Finding 2: the 404 is not a policy, it is an `else` branch

`internal/host/proxy.go:611` emits the 401 challenge only when
`fh.oauth2Protected && fh.oauth2Resource != ""`, which is true only when some
operation declares the `oauth2` scheme (`internal/host/oauth2_resources.go:27`).
`/api/v1/mcp` does; `/api/v1/vector_stores` declares only `apiKey*`/`bearer`, so
it falls through to the 404.

The status code a caller receives is therefore a side effect of which security
scheme the CR author happened to name. No one chose it per function, and no one
can predict it from the CR.

## Finding 3: `unwrap` already is the Accept negotiation — and it deletes the challenge

`DesignMiddleware` wraps the **whole mux** (`internal/host/host.go:618`), not
just DevMode hosts. Its `unwrap` (`internal/host/feedback.go:320`) buffers every
`>= 400` response and, when `Accept` contains `text/html`, re-renders it through
`serveError` (`internal/host/host.go:960`) as the `ErrorUtilityPage`. Otherwise
it writes plain text.

Two consequences, one good and one a live bug:

**Good:** the content negotiation this contract needs already exists and is
already global. Gates must **not** negotiate presentation. They choose a status
and a header; `unwrap` renders.

**Bug:** the HTML branch deletes *every* response header
(`internal/host/feedback.go:328-330`) before rendering. So the RFC 9728
challenge is destroyed for any client that accepts HTML. Verified live:

```
Accept: */*        -> HTTP/2 401  www-authenticate: Bearer resource_metadata="…"
Accept: text/html  -> HTTP/2 401     <- no challenge at all
```

That is a bare RFC 7235 violation (a 401 **MUST** carry `WWW-Authenticate`) and
it silently disables OAuth discovery for browser-shaped clients. A contract that
mandates a challenge cannot be built on top of a layer that deletes it, so
fixing this is part of the change, not a follow-up.

The blanket delete exists for a real reason — a stale `Content-Length` left by a
suppressed proxy body — so the fix is an **allow-list**, not a removal.

## Finding 4: the three-outcome split needs no library change

`VerifyResourceParsedEntitlements` runs two stages — the identity gate
(`<resource>:<resourceName>:read`) and then the operation requirement — and
returns a single `authorized` bool, so a caller cannot see which stage failed.

It does not need to. `internal/host/check.go:57-60` already documents and uses
the trick: *"An empty requirement set reduces `VerifyResourceParsedEntitlements`
to exactly that grant check."* `ParseRequirements(nil)` is a pure identity probe.

So a gate that has **already** failed can ask "identity or requirement?" with one
extra call **on the denial path only**. The happy path pays nothing, and the
distinction the skill says causes the most confusion is nearly free.

## The contract

| caller state | outcome | status | `WWW-Authenticate` |
|---|---|---|---|
| no credential presented | `Unauthenticated` | **401** | `Bearer realm="<issuer>"`, or `Bearer resource_metadata="<issuer>/.well-known/oauth-protected-resource<basePath>"` when the resource is oauth2-protected |
| credential present, fails the identity gate | `NoIdentity` | **403** | none |
| credential present, passes identity, fails the requirement | `InsufficientScope` | **403** | `Bearer error="insufficient_scope", scope="<required scopes>"` when oauth2-protected |

**No status is ever chosen to conceal.** Concealment is retired as a posture.

Three RFC details that make this precise rather than approximate:

1. **No `error=` on the `Unauthenticated` 401.** RFC 6750 §3.1 omits the
   parameter when no credentials were sent. `error="invalid_token"` would be a
   lie about a token that was never presented — which is why this challenge is
   *not* `Config.bearerChallenge` (`internal/auth/middleware.go:161`), whose job
   is the genuinely-invalid-token case and which stays as it is.
2. **`insufficient_scope` is a 403 that still carries a challenge.** RFC 6750
   §3.1 defines it that way. This is what stops the 401→403 move from costing an
   MCP client its step-up path: it gets the required scope by name instead of a
   dead end. `oauth2ProtectedResources()` already computes the de-duplicated
   scope union per basePath, so the `scope=` value costs nothing to produce.
3. **`NoIdentity` carries no challenge.** The caller cannot address the resource
   at all; naming a scope would imply a scope would fix it.

## What is a gate

**The contract applies to:** the function proxy (`internal/host/proxy.go:598`),
the page gate (`internal/host/page.go:37`), apitoken mint/revoke
(`internal/host/apitoken.go:133,249`), capabilities mint
(`internal/host/capabilities.go:199`), and `/-/state/`
(`internal/host/handlers.go:1059`).

`/-/state/` is the purest `Unauthenticated` row in the repo — it answers only a
caller who presented a credential, so its sole denial is "you presented none" —
and it answered a **bare 401**, violating both RFC 7235 and this contract's own
"every 401 carries a challenge" constraint. It was missing from both lists in
the first draft of this document.

**Explicit exceptions, documented so they read as decisions rather than
oversights:**

- **Real 404s stay 404** — `internal/host/host.go:611`,
  `internal/host/schema.go:74`, `internal/host/handlers.go:733`,
  `internal/host/navigation.go:162`, `internal/host/feedback.go:397`. The
  contract governs *denials*, never *absences*. A contract that turns a genuine
  not-found into a 401 is the same defect with the sign flipped.
- **`/-/check` stays 200 + verdict.** It is an API *about* entitlements, not a
  gate over a resource.
- **The navigation filter keeps omitting entries** (`internal/host/navigation.go:88`).
  Omitting a link the caller cannot use is not misreporting a status; the
  contract is about status codes, and a nav that advertises dead links is worse.
- **The sniffer keeps its 404** (`internal/host/feedback.go:254`). This one was
  listed under "contract applies" in the first draft and it does not belong
  there. `canGenerateSniffer` returning false does not deny a resource — it sets
  `invokeSniffer = false` and lets the request fall through to ordinary routing,
  which 404s because the path genuinely does not exist. That is precisely the
  absence the contract refuses to relabel, so promoting it to 403 would break
  the rule in the opposite direction. What was actually missing is the *reason*:
  the suppression is recorded only at `V(1)`. The gate gains a response header,
  `X-KDex-Sniffer-Suppressed: functions:create`, so `curl -i` answers the
  question the skill documents people asking ("I expected a 303, got 404")
  without misreporting the status. (When the path *does* exist — a mutable
  function plus `X-KDex-Function-*` headers — suppression falls through to the
  function handler, which is gated by the proxy under the contract, so no 404
  arises there at all.)
- **`/-/transfer` keeps its uniform 410** (`internal/host/transfer.go:170`). A
  256-bit capability handle appears in no OpenAPI document, so the
  anti-enumeration argument that fails everywhere else genuinely holds here.
- **The proxy's requirement-binding failure stays a bare 403**
  (`internal/host/proxy.go:594`), including for an anonymous caller, where the
  contract's first row would say 401. A bind failure is
  `entitlements.ErrUnboundPlaceholder`: the CR declared a requirement
  placeholder this layer cannot supply. That is a **server-side configuration
  fault, not a statement about the caller's credential** — no credential the
  caller could present would change the outcome, so telling an anonymous caller
  to authenticate would send them to fix something that is not theirs to fix.
  It sits four lines above the contract call and is now commented at the site so
  it reads as a decision rather than an oversight.
- **`apitokenVerifyHandler` keeps its bare 401** (`internal/host/apitoken.go:537`).
  It is not a gate: it is an *answer* about a token the caller submitted **in the
  request body**, so the 401 reports the verification outcome rather than
  refusing the request. Its own OpenAPI publishes exactly that — 400/401/500,
  with no 403 alongside — which is what distinguishes it from the mint and revoke
  operations next to it. `internal/auth/middleware.go:481,485` carry bare 401s of
  the same class (a capability token presented and found invalid or exhausted).
  Together they are a coherent **fourth outcome the contract does not model** —
  "a credential was presented and it is invalid" — not a local oversight. Folding
  them in would mean either inventing a challenge for a token that was already
  rejected, or (worse) `Config.bearerChallenge`'s `invalid_token`, which the
  contract deliberately keeps separate. Left as-is; if a fourth row is ever
  wanted, these are its sites.
- **The anonymous page-gate login redirect stays, for HTML callers**
  (`internal/host/page.go:68`). A 303 to `/-/login?return=…` *is* the browser
  rendering of `Unauthenticated`, and #184 reordered that branch deliberately —
  this design does not disturb its position. It does add one condition the
  branch lacks today: it fires only when the caller accepts `text/html`. An API
  client fetching a gated page anonymously gets the 401 the contract specifies,
  not a 303 to a login form it cannot render. This is the one place a gate
  legitimately inspects `Accept`, because the alternative here is a *redirect*
  rather than a status — `unwrap` only ever sees `>= 400`, so it cannot make
  this choice on the gate's behalf.

## Design

### `internal/auth/denial`

```go
type Outcome int // Unauthenticated | NoIdentity | InsufficientScope

// Classify runs only after a gate has already denied. `held` is the
// caller's parsed entitlements — the value the failed gate already
// computed — so the denial path re-derives nothing.
func Classify(ctx context.Context, c Checker,
              held entitlements.ParsedEntitlements,
              resource, name string, verbs ...string) Outcome

// Write sets status, Cache-Control and WWW-Authenticate. It never writes
// a body: presentation belongs to unwrap.
func Write(w http.ResponseWriter, r *http.Request, o Opts)

type Opts struct {
    Outcome          Outcome
    Issuer           string   // realm for the non-oauth2 challenge
    ResourceMetadata string   // RFC 9728 metadata URL, "" when not oauth2-protected
    Scopes           []string // required scopes, for insufficient_scope
}
```

`held` is a parameter rather than a `c.GetParsedEntitlements(ctx)` call because
both major gates (`internal/host/page.go`, `internal/host/proxy.go`) are holding
that exact value when they call `Classify`. Re-deriving it costs another
map+slice allocation, another claim re-parse, and another `RLock` on the
per-host pattern cache **shared by every concurrent request** — per denial, to
recompute something the caller already has. Where a gate genuinely has none in
scope (apitoken mint/revoke, which decide through `CheckAccess`) it derives one
once, on the denial path only.

**Anonymity is "no context, or a context that names nobody."** `Classify` tests
`auth.GetAuthContext` and then requires a non-empty `sub`. The context test is
sound because anonymous entitlements live inside the `AuthorizationChecker`
(`internal/host/host.go:697`) rather than as a synthetic auth context, so an
absent context really does mean "no credential presented". The subject test is
what makes the five gates agree: `hasEvaluatedSubject`
(`internal/host/feedback.go`), `apitokenRevokeHandler`
(`internal/host/apitoken.go`) and `capabilityMintHandler`
(`internal/host/capabilities.go`) all require a non-empty subject already.
An earlier draft of this document asserted the test was uniform while
`Classify` accepted any *present* context — it was not, and the disagreement
was observable: a caller with a context but an empty `sub` got `NoIdentity`
(403, no challenge) at the page and proxy gates, a 403 no credential they
could present would ever fix, while the other three gates called the same
caller anonymous. `Classify` now agrees with them and answers 401 + challenge.

The checker stays pure, so the navigation filter keeps its boolean and nothing
about it changes.

**The package owns statuses, never redirects.** Both of the page gate's 3xx
renderings — the anonymous login redirect and the `discover` mode's discovery
redirect — stay in `internal/host/page.go`. They are alternatives to writing a
status at all, so they precede `denial.Write` rather than being produced by it,
and `unwrap` (which only ever sees `>= 400`) never observes them. Keeping them
out of the package is what stops `denial` from acquiring a `LoginPath`, a
`firstAuthorizedPage` callback, and a mode flag — i.e. from becoming the page
gate with extra steps.

### Per-gate changes

| gate | today | after |
|---|---|---|
| function proxy | 404, or 401+challenge if oauth2 | `denial.Write` with the classified outcome |
| page gate | 302 login / 302 first-authorized / 404 | anonymous + HTML + a login page → 303 login (position unchanged, now `Accept`-conditional); anonymous otherwise → 401; authenticated → 403, rendered to HTML per the knob |
| sniffer | silent fall-through to 404 | 404 unchanged (a real absence) + `X-KDex-Sniffer-Suppressed: functions:create` |
| apitoken mint/revoke | 401 / 403 ad hoc | `denial.Write` (already contract-shaped; unified for one vocabulary) |
| capabilities mint | 401 | `denial.Write` |

`functionHandler` (`internal/host/types.go:185-216`) gains `oauth2Scopes []string`,
captured at `internal/host/proxy.go:395` from the `OAuth2Resource.Scopes` union
that is already computed there.

### `unwrap` header allow-list

Preserve `WWW-Authenticate` and `Retry-After` across the header wipe in
`internal/host/feedback.go:328-330`. Everything else keeps being deleted, for
the `Content-Length` reason the existing comment gives.

### The page-denial knob

`FORBIDDEN` is one decision with two browser renderings. **Non-HTML callers get
403 in both modes, always** — the knob never changes what an API client sees,
only how the decision is rendered to a browser.

```
--page-denial-mode=discover  # HTML -> 303 to the first authorized page (default)
--page-denial-mode=forbid    # HTML -> the 403 error page
```

Exposed as the helm value `pageDenialMode`, so it is settable per host with no
CRD change:

```yaml
KDexHost.spec.helm.hostManager.values: |
  pageDenialMode: forbid
```

**Default: `discover`.** It preserves today's browser behaviour byte-for-byte
while every API caller gets the contract, so the upgrade's blast radius is
confined to callers that were already being misled. `forbid` is the opt-in for
operators who want the truthful 403 in the browser too. (An earlier draft made
`forbid` the default because `discover` redirected *every* caller, API clients
included — which silently violated the contract it was supposed to be an
alternative rendering of. Confining the redirect to the HTML rendering is what
makes `discover` safe to lead with.)

The discovery redirect carries the denied path and is bounded to one hop:

```
GET /admin                     (authenticated, no grant)
  -> 303 /dashboard?denied=%2Fadmin
     Cache-Control: no-store
```

- **`?denied=` is the explanation.** A bare redirect tells the user nothing:
  they asked for `/admin`, landed on `/dashboard`, and were given no reason.
  The marker gives the theme or navigation script something to surface, which
  is what turns silent misdirection into an explained one.
- **It is also the loop guard.** `firstAuthorizedPage` can return a page that
  itself denies — the navigation walk and the page render are separate checks,
  so a requirement change or a race between them produces a redirect loop.
  Today's code carries that exposure with nothing bounding it. A request
  already carrying `denied=` never redirects again; it renders the 403 page
  instead. One hop, maximum.
- **`Cache-Control: no-store`**, because a cached denial follows the user past
  the grant change that fixed it.
- **The value is `r.URL.Path`, not `RequestURI()`**, `url.QueryEscape`d on
  write — the same treatment the login branch gives `return=`. It is a path on
  this host by construction and is never used as a redirect target, only as a
  label, so it needs no `SafeReturnPath` collapse. It *is* caller-influenceable,
  so any consumer that renders it must treat it as text: a bundled navigation
  or theme script must not `innerHTML` it.

`discover` falls back to the 403 page whenever it cannot redirect: no accessible
page exists (`firstAuthorizedPage` returns `""`), or the request already carries
`denied=`. So the 403 rendering is reachable in both modes and is never a
dead-end special case — it is the floor both modes stand on.

Both the marker and the loop guard exist **only in `discover` mode**. `forbid`
performs no redirect, so there is nothing to mark and no loop to bound; the
denied path is already the request URL the 403 page renders.

**Discovery is only ever a rendering of `FORBIDDEN`.** The anonymous branch does
not get it: anonymous is `UNAUTHENTICATED` and the fix is logging in, so sending
a logged-out visitor to some public page instead of the login form would be a
worse answer, not a friendlier one.

## Testing

TDD, RED first. Three contract rows against each gate, in both `Accept` shapes
(`*/*` and `text/html`), plus:

- a regression pinning the challenge's survival through `unwrap` — the bug this
  design found, which no existing test covers;
- both knob modes on the page gate, each in both `Accept` shapes — including
  the invariant that a non-HTML caller sees 403 regardless of mode;
- the discovery redirect's one-hop bound: a request carrying `denied=` renders
  the 403 page rather than redirecting again;
- `Cache-Control: no-store` on the discovery redirect;
- `Classify` unit tests covering the identity-vs-requirement split, driven
  through `ParseRequirements(nil)`.

Two existing tests encode the old posture and invert:

- `internal/host/proxy_challenge_test.go:132` — `TestUnauthorizedBearerOnlyPathStill404`
  becomes the 401+realm case.
- `internal/host/mcp_oauth2_e2e_test.go:463` — tightens from "401 or 404" to the
  exact code.

## Risk

- **Every enabled function basePath now returns an actionable 401 to an
  unauthenticated prober.** That is the intended consequence of Finding 1, and
  it holds exactly as long as `/-/openapi` stays ungated. Recorded in a comment
  at the denial site.
- **An authenticated MCP client with insufficient scope now sees 403, not 401.**
  Mitigated by `insufficient_scope` + `scope=`, which is a better step-up signal
  than the 401 it replaces — but it is an observable change for any client that
  branches on the status alone.
- **The page gate's browser behaviour changes in two ways on upgrade**, both
  intended, neither covered by the `discover` default. (An earlier draft of this
  section claimed browser behaviour was unchanged. It was wrong.)
  1. *An anonymous browser on a host with no `LoginUtilityPage` now gets 401
     instead of a discovery redirect.* The login branch is guarded on
     `hasLoginPage`, and anonymous never falls through to discovery any more —
     the discovery branch is guarded on `outcome != denial.Unauthenticated`.
     Before this change, anonymous-with-no-login-page fell through to
     `firstAuthorizedPage` and was sent to some arbitrary public page (or 404 if
     there was none). That is the misdirection the contract exists to stop, so
     the 401 is the point — but it *is* a browser-visible change, and it lands
     on exactly the hosts that configure no login page.
  2. *An authenticated browser's discovery redirect now carries `?denied=<path>`*
     (plus `Cache-Control: no-store`, and a one-hop bound). The destination page
     is the same; the URL is not. Anything that keys on the redirect target — a
     test, an analytics rule, a nav script — sees a query string that was not
     there before.

  The host's *API* behaviour changes far more, which is the point of the branch.
  Operators wanting the truthful 403 in the browser too flip one helm value, no
  rollback.

## Out of scope

- Any CRD change. The knob is a host-manager flag precisely to avoid one.
- `kdex-entitlements` (Go/Rust/Python). Finding 4 shows no library change is
  needed.
- Backends behind the proxy. knowdb keeps answering however it answers; this
  contract governs what host-manager says.
- The `err != nil` arm of **both** gates — the function proxy's and the page
  gate's. Both now fold it into the same `denial.Write` as `!authorized`, with
  one condition and one vocabulary, so the two gates agree; both keep
  `log.Error`, because an errored check IS a server fault even while it is
  rendered as a denial. Whether it should instead be a **500** at both sites is
  a real question and is filed separately, not settled here. (The page gate's
  arm answered `404 + r.URL.Path` until the final review caught it; leaving it
  alone would have preserved the exact defect this branch retires.)

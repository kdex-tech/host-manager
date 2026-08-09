# Streaming deadlines & OAuth token-endpoint conformance

**Date:** 2026-08-08
**Issues:** [#167](https://github.com/kdex-tech/host-manager/issues/167), [#168](https://github.com/kdex-tech/host-manager/issues/168), [#169](https://github.com/kdex-tech/host-manager/issues/169)
**Target release:** host-manager v0.5.0 (chart bumped alongside)
**Base:** `c845892` = `v0.4.28`

## Summary

Three independent defects, one release. Two of them (#168, #169) compound into a
client-visible deadlock and are filed as a pair; #167 is unrelated but ships in the
same cut.

| # | Defect | Site |
|---|---|---|
| 167 | `http.Server.WriteTimeout` is a whole-connection deadline, so it severs SSE/streaming responses at 60s | `internal/web/server/server.go:32` |
| 168 | Token endpoint reports every grant failure as `401` + `text/plain`, so clients cannot detect a dead refresh token | `internal/auth/oauth2.go:371` (and ~14 sibling sites) |
| 169 | Refresh-token rotation is strictly single-winner, so parallel refreshes race and all but one fail | `internal/auth/exchange.go:691` |

No CRD changes. `updateCrdUsage.sh` is not run and nexus-manager is not released.

---

## 1. #167 — inbound write deadline severs streams

### Problem

`internal/web/server/server.go` sets `WriteTimeout: 60 * time.Second` on the
`http.Server`. In Go this deadlines the **whole connection**, not a single slow
write, so an in-flight `text/event-stream` response is torn down mid-body at the
60s mark regardless of how healthily it is flushing. The issue's wire capture
shows keep-alives arriving on schedule at t+15/30/45s and the connection dying
before t+60s — flushing is fine; the deadline is the whole cause. Both production
SSE surfaces (knowdb `/api/v1/events` and MCP `GET /api/v1/mcp`) sit in a
permanent ~60s reconnect loop as a result.

The value is also unreachable from the chart: `proxy.*` exposes only the
*outbound* transport timeouts.

### Design

A new middleware, `middleware.WithStreamDeadline(writeTimeout time.Duration)`,
wraps the `http.ResponseWriter` and adjusts the **per-request** write deadline
through `http.ResponseController` (Go 1.20+; this module is on Go 1.26.0). The
decision is made at `WriteHeader` time, when the response headers are final. The
three cases are evaluated **in order, first match wins** — an SSE response also
has no `Content-Length`, so the ordering is what keeps it on the cleared path
rather than the sliding one:

1. **`Content-Type: text/event-stream`** → **sliding on its own, much larger
   window** (`server.streamStallTimeout`, default 5m), re-armed after each
   successful `Flush` exactly as case 2 does. The keep-alive cadence is chosen by
   the backend and may legitimately exceed `writeTimeout`, so the *cadence-sized*
   window is wrong — but a window still bounds a stalled stream.

   *(Corrected 2026-08-08 by the final whole-branch review. This originally said
   `SetWriteDeadline(time.Time{})` — cleared outright. The performance and
   security lenses independently found the same consequence: a consumer that
   stops reading, whether it vanished without an RST or is doing it on purpose,
   parks the proxy's `Flush`→`conn.Write` under TCP backpressure with nothing to
   cut it. The request context cancels on close, not on a stalled reader, and
   nothing else covers it — `ReadTimeout`/`ReadHeaderTimeout` bound the request
   only, `IdleTimeout` bounds inter-request idle only, and there is no
   `ConnState`/`LimitListener`/`TimeoutHandler` in the repo. Linux TCP keepalive
   reaps such a connection at ~2h11m, where before this branch it died at 60s;
   each one pins a goroutine, an FD, the upstream connection and a 32KB buffer.
   That is precisely the exposure #49's `WriteTimeout` existed to bound. Sliding
   on a generous window keeps a healthy stream unbounded — 5m is 20× the 15s
   keep-alive cadence of the affected backends — while killing a stalled one in
   minutes. Note the chunked path never had this problem: a blocked flush
   inherits the deadline armed by the previous flush.)*
2. **No `Content-Length` header** (chunked / unknown length) → **sliding mode**:
   after each successful `Flush`, re-arm the deadline to `now + writeTimeout`.
3. **Everything else** → untouched; the connection-level `WriteTimeout` applies
   as it does today.

Sliding rather than clearing is deliberate for the chunked case. It removes the
*total-duration* cap, which is the defect, while retaining a *stall* cap: a
connection that goes silent mid-body for longer than `writeTimeout` is still cut.
A stream that is actively making progress runs unbounded.

**The re-arm must happen after a flush, not before a write** — this is the one
place where the obvious implementation does not work. `http.response.Write`
copies into an internal `bufio` buffer and need not touch the socket at all, and
a deadline set to `now + writeTimeout` immediately *before* an I/O attempt is by
construction always in the future. Together those mean a write-keyed extension
overwrites the stale, already-elapsed deadline microseconds before the only code
that would have observed it — so the stall cap never fires and sliding mode
degrades silently into clearing. `Flush` is where bytes actually reach the
connection, so arming *after* a successful flush makes the armed window govern
the gap until the *next* flush: if that gap exceeds `writeTimeout`, the deadline
has already elapsed when the next flush is attempted and the connection is cut.

*(Corrected 2026-08-08 during implementation. The design originally specified
"before each `Write`"; `TestWithStreamDeadline_ChunkedStallIsStillCut` is what
catches the difference, and it exists precisely because the stall cap is the
property that distinguishes sliding from clearing.)*

A consequence worth stating: a chunked handler that **never** flushes gets no
extension, so the connection-level `WriteTimeout` still bounds it. That is
correct — streaming implies flushing, and `httputil.ReverseProxy` auto-flushes
for `ContentLength == -1`, which is every proxied streaming backend.

`WriteTimeout <= 0` disables the middleware's adjustments entirely (there is no
deadline to slide).

### Wrapper obligations

The wrapper is the only `ResponseWriter` wrapper in the chain — `WithLogger`
passes `w` through unmodified — so it carries three requirements, each of which
is a functional break if omitted:

1. **`Unwrap() http.ResponseWriter`** — without it `http.ResponseController`
   cannot reach the underlying writer and every `SetWriteDeadline` returns
   `http.ErrNotSupported`, silently restoring the bug.
2. **`Hijack() (net.Conn, *bufio.ReadWriter, error)`** — `httputil.ReverseProxy`
   hijacks the connection to service `Upgrade` requests. A wrapper that does not
   delegate `Hijack` breaks WebSocket proxying.
3. **No `io.ReaderFrom`** — deliberately *not* implemented. `io.Copy` prefers
   `ReadFrom` when available, which would bypass `Write` and `Flush` entirely,
   so the deadline policy would never be applied at all.

`Flush()` is delegated as well — it is both what keeps `ReverseProxy`'s
`maxLatencyWriter` flushing per chunk *and*, per the correction above, where the
sliding deadline is re-armed.

### Configuration

The chart gains a `server:` block mirroring the existing `proxy:` block, wired to
new flags on `cmd/main.go`:

```yaml
server:
  readHeaderTimeout: 10s
  readTimeout: 60s
  writeTimeout: 60s    # 0 = no deadline
  idleTimeout: 120s
```

Flags: `--server-read-header-timeout`, `--server-read-timeout`,
`--server-write-timeout`, `--server-idle-timeout`. `0` means "no deadline" for
each, matching stdlib semantics.

Defaults are exactly today's values, so `internal/web/server/server_test.go`'s
`> 0` assertions — which pin the #49 Slowloris fix — continue to pass unchanged.

### Relationship to #49

#49 added these timeouts to close a Slowloris vector. Slowloris is a **read**-side
attack (slow headers, slow body); `ReadHeaderTimeout`, `ReadTimeout` and
`IdleTimeout` are its mitigations and are untouched by this change.
`WriteTimeout` guards a different case — a client that stops draining the
response — and only that case is relaxed, only for streaming responses, and only
to a stall cap rather than to nothing.

### Verification required during implementation

`SetWriteDeadline` must be confirmed to take effect on **HTTP/2** streams, not
only HTTP/1.1. The issue's reproduction shows `HTTP/2` at the edge. The h1 path
is certain; the h2 path must be exercised by a test rather than assumed. If h2
does not honor it, the fallback is to document `server.writeTimeout: 0` as
required for h2 SSE deployments — but that is a fallback, not the plan.

### Tests

- SSE response (`text/event-stream`) continues past `writeTimeout` and terminates
  only when the handler ends.
- Chunked response writing steadily continues past `writeTimeout`.
- Chunked response that stalls for longer than `writeTimeout` is cut.
- Fixed-`Content-Length` response is still bounded by `writeTimeout`.
- `Unwrap`, `Hijack` and `Flush` are present; `io.ReaderFrom` is absent.
- Chart renders the `server.*` values onto the flags; `0` renders as `0`.
- HTTP/2 equivalent of the SSE case (see above).

---

## 2. #168 — token endpoint is not RFC 6749 §5.2 conformant

### Problem

`POST /-/token` answers every grant failure with `401` and a `text/plain`
`Authentication failed` body. RFC 6749 §5.2 requires `400` with an
`application/json` body carrying an `error` code. The specific code that matters
is **`invalid_grant`** — the spec-defined signal meaning *"this grant is expired
or revoked, start a fresh authorization flow."*

Because neither the status nor the code is emitted, a client keying its
re-authorization fallback on that signal cannot see it. One observed MCP client
(`codex-mcp-client/0.146.0-alpha.9.2`) retried the same dead refresh token 290
times with zero successes and never reached `initialize`.

The whole handler shares this shape: ~15 `http.Error` call sites with `text/plain`
bodies and ad-hoc statuses, several of which are independently non-conformant
(e.g. "Unauthorized grant type" returns `401` where §5.2 specifies `400`
`unauthorized_client`).

### Design

A helper writes §5.2-shaped errors:

```go
func writeOAuthError(w http.ResponseWriter, status int, code, description string)
```

It sets `Content-Type: application/json`, `Cache-Control: no-store`,
`Pragma: no-cache`, the status, and the body
`{"error":"<code>","error_description":"<description>"}`.

Every failure path in the token handler is mapped:

| Failure | Status | `error` |
|---|---|---|
| method not `POST` | 405 | `invalid_request` (see note) |
| form parse failure | 400 | `invalid_request` |
| missing `code` / `redirect_uri` / `refresh_token` | 400 | `invalid_request` |
| unknown `client_id`, or bad `client_secret` | 400 | `invalid_client` |
| grant type not allowed for this client | 400 | `unauthorized_client` |
| `client_credentials` on a public client | 400 | `unauthorized_client` |
| scope not allowed for this client | 400 | `invalid_scope` |
| unknown `grant_type` | 400 | `unsupported_grant_type` |
| dead/expired/unknown authorization code or refresh token | 400 | **`invalid_grant`** |
| mint / cache / encode failure | 500 | `server_error` |

**Note on 405.** §5.2 governs the token endpoint's *error responses*, not HTTP
method dispatch, so `405` is retained rather than folded into `400`. It carries
the JSON body purely so that every response from this endpoint has one shape and
a client never has to branch on content type.

### `invalid_client` is 400, not 401

§5.2 requires `401` **only** when client authentication was attempted through the
`Authorization` request header, and then obliges a `WWW-Authenticate` response
header. The affected clients are public PKCE clients that send no `Authorization`
header — the issue's own log line shows `client_secret_present: false` — so `400`
is both correct and the only form we can emit honestly, since we would have no
meaningful challenge to put in `WWW-Authenticate`.

The `401` + `WWW-Authenticate: Basic` form is reserved for the case where
credentials *did* arrive via the `Authorization` header (`r.BasicAuth()` returned
`ok`) and were rejected. That branch is implemented, but it is not the path any
current client takes.

### Separating `invalid_grant` from `server_error`

A mint failure, a cache read failure, or a signing failure inside
`RedeemRefreshToken` / `RedeemAuthorizationCode` must **not** be reported as
`invalid_grant`. Doing so would tell a client to discard a perfectly good
credential and re-authorize during a transient outage.

A sentinel error is added to the `auth` package:

```go
var ErrServerError = errors.New("server error")
```

The Exchanger wraps it at the infrastructure-failure sites — cache read failure,
`mintTokensFromSubject` failure, `createRefreshToken` failure, JSON unmarshal
failure of a stored record. The handler does `errors.Is(err, ErrServerError)` and
emits `500 server_error`.

**The classifier is default-closed.** An earlier revision of this design said
"every other error out of a redemption path is `invalid_grant` by definition" and
had the handler echo `err.Error()` for that case. That is wrong, and unsafe on an
unauthenticated endpoint. The reasoning only covers errors raised *inside*
`RedeemRefreshToken` and `RedeemAuthorizationCode`; both call out to
`mintTokensFromCode`, `LoginLocal` and `LoginClient`, whose own infrastructure
failures were never wrapped and would reach the caller verbatim — including, on
the HTTP-lookup path, an internal service URL and pod IP
(`httpLookup: request: Post "http://<svc>": dial tcp <ip>:8080: connect:
connection refused`). Signer and role-resolver failures leak unconditionally on
every `authorization_code` redemption, and are simultaneously misclassified as
`400 invalid_grant` — the precise "discard your working credentials during an
outage" failure `ErrServerError` exists to prevent.

So the rule is an allowlist, not a fallthrough:

| Error carries | Response | `error_description` |
|---|---|---|
| `ErrServerError` | 500 `server_error` | fixed generic string |
| `ErrGrantFailure` | 400 `invalid_grant` | the wrapped message — these are deliberately client-facing |
| neither | 400 `invalid_grant` | fixed generic string; full cause to the log only |

`ErrGrantFailure` marks the rejections that are *about the presented grant* and
are safe to describe: token not found, token expired, client mismatch, session
cap reached, code already consumed, PKCE mismatch. Both redemption functions
already funnel their rejections through a local `failed(...)` helper, which is
the natural single place to apply it.

The property that matters is the direction of the default: a future callee that
raises a new, unwrapped error discloses nothing. Under the old fallthrough it
would leak the moment it was written, with no test failing.

*(Corrected 2026-08-08 during implementation, after review found the callee
leak.)*

**`error_description` content is opt-in, per the allowlist above.** A message
reaches the caller only when its error is explicitly marked `ErrGrantFailure` —
those describe the *grant's* state (`refresh token not found or expired`,
`refresh token was not issued to this client`) and already go to the debug log.
Everything else — `server_error`, and any unmarked error — carries a fixed
generic string with the cause logged only. A signing, cache, or identity-provider
failure must never have its internals reflected to an unauthenticated caller.

The non-redemption failures in the handler itself (missing parameter, unknown
`client_id`, disallowed scope) keep the fixed descriptions given in the mapping
table above; they are authored constants, not propagated errors, so the
allowlist does not apply to them.

### Success path

Token responses also gain the `Cache-Control: no-store` and `Pragma: no-cache`
headers that §5.1 requires and which are currently absent.

### Tests

Table-driven over every row of the mapping above, asserting status,
`Content-Type`, and the decoded `error` field. Plus:

- A dead refresh token yields exactly `400` + `{"error":"invalid_grant"}` — the
  literal reproduction from the issue.
- An `ErrServerError`-wrapped failure yields `500 server_error`, **not**
  `invalid_grant`.
- Rejected `Authorization`-header credentials yield `401` + `WWW-Authenticate`.
- Success responses carry `Cache-Control: no-store`.

---

## 3. #169 — refresh rotation has no grace window

### Problem

`RedeemRefreshToken` consumes the refresh token with an atomic `GetAndDelete`,
which produces exactly one winner under concurrency. Real clients issue several
refresh requests in parallel — the issue documents repeated bursts of 4–5 within
250–600ms — so all but one fail with `refresh token not found or expired`.
Multiple otherwise-healthy clients show a minority of such failures interleaved
with successes, which is the signature of a race rather than of expiry (refresh
tokens carry a ~3-day TTL).

RFC 9700 §4.14 names this race and recommends tolerating it.

### Design: replay the result, do not re-issue

A new cache class `refresh-grace` (`Uncycled: true`, TTL = the grace window) holds
the *minted result* keyed by the *consumed* token id. `RedeemRefreshToken`
becomes:

1. `GetAndDelete(refresh-tokens, id)` — **unchanged**. Exactly one caller wins.
2. **Winner:** validate, mint, and rotate exactly as today. Before returning,
   `Set(refresh-grace, id, json(TokenSet), WithTTL(window))`.
3. **Loser** (`found == false`), when the window is enabled: read
   `refresh-grace, id`. On a hit **whose recorded `client_id` matches the
   caller's**, unmarshal and return the byte-identical `TokenSet`. On a
   client-id mismatch, reject exactly as strict rotation does
   (`refresh token was not issued to this client`). On a miss, return today's
   `refresh token not found or expired`.

**The grace record must carry the client id, and the replay must check it.**
This is not optional hardening — without it the window *removes* a validation
the strict path performs. Strict rotation consumes the record, unmarshals it,
and rejects when `claims.ClientID != clientID`. The replay path never reaches
that comparison, and a bare `TokenSet` carries no client id to compare against,
so a caller presenting a valid token id under a **different registered
client_id** would be handed the winner's access token, ID token, and *live
rotated refresh token* — and could then rotate that lineage indefinitely.
Registering a client is not a meaningful barrier: public clients need no
secret, and DCR lets a caller register one. So the stored value is
`{client_id, TokenSet}`, not a bare `TokenSet`, and a mismatch is a
`grantFailuref` rejection carrying the same message strict mode uses.

*(Added 2026-08-08 during implementation, after review found the replay was
keyed on the token id alone.)*

### Why #71's guarantee survives

#71 exists because a Get-then-Delete pattern let two concurrent redemptions each
mint a *parallel session lineage*, defeating rotation-based theft detection. This
design does not reintroduce that: `GetAndDelete` still admits exactly one caller
to the minting path, so exactly one rotation occurs and exactly one new lineage
exists. Losers receive a copy of the winner's result; they mint nothing.

The security properties, stated precisely:

- A thief presenting a stolen token **inside** the window receives the same pair
  the legitimate client already holds. No new lineage is created, and the thief
  gains nothing the legitimate client does not already have.
- A thief presenting it **after** the window is rejected exactly as today, and
  rotation-based reuse detection is unchanged.
- Only the *rejection* of concurrent presentations is relaxed, and only for the
  window's duration.

The rejected alternative — keeping the old token valid so that each use mints a
*fresh* pair — is precisely the condition #71 was filed to eliminate, and is not
implemented.

### The set-visibility sub-race

A loser can arrive after the winner's `GetAndDelete` but before the winner's
`Set(refresh-grace, ...)`, and would find neither entry. The interval is
sub-millisecond with the in-memory cache but is a network round trip under
Valkey.

Losers therefore poll the grace key before returning the not-found error:
**10 attempts at 20ms intervals, 200ms ceiling**, returning on the first hit.
This is bounded, adds no state, and cannot deadlock — the winner either publishes
within the interval or has failed, in which case the not-found error is correct.

**A rejected winner publishes nothing, so its losers see a different error.** If
the winner's redemption fails validation (client-id mismatch, absolute session
timeout), the token is already consumed but no grace entry is written, so
concurrent losers fall through to `refresh token not found or expired` rather
than the winner's more specific message. This asymmetry is accepted: under #168
both map to the same wire response (`400 invalid_grant`), and caching a rejection
would mean serving a failure from a cache.

### Configuration

`auth.refreshGraceWindow`, flag `--refresh-grace-window`, default **10s**.

**`0` disables the grace window entirely**, restoring today's strict
single-winner behavior. This is what allows #71's original assertion to survive
as a live test rather than being deleted.

### Multi-replica

The grace entry lives in the same `CacheManager` as the refresh tokens
themselves. Any deployment where refresh tokens already work across replicas
(i.e. Valkey is enabled) gets a working grace window for free; a single-replica
in-memory deployment — the chart default, `replicaCount: 1` — works as well. No
new deployment constraint is introduced.

### Tests

- **Rewritten** `TestRedeemRefreshToken_ConcurrentRedemptionsShareOneRotation`:
  32 concurrent redemptions all succeed, all receive an identical
  `RefreshToken`, and exactly one new refresh-token entry exists afterward.
- **Retained** #71 assertion, as `TestRedeemRefreshToken_StrictModeHasSingleWinner`:
  with `refreshGraceWindow = 0`, exactly one winner and 31 not-found.
- Grace entry expires: a redemption after the window returns not-found.
- A loser arriving during the set-visibility gap still succeeds (poll path).
- Client-id mismatch and absolute-session-timeout rejections are **not** cached
  into the grace window — a rejected redemption publishes nothing.

---

## Release

- **Version:** v0.5.0. #168 changes response status codes on a public endpoint;
  that is a behavior change and does not belong in a patch bump.
- **Chart:** version bumped alongside; new `server.*` and `auth.refreshGraceWindow`
  values documented in `values.yaml`.
- **No CRD change**, therefore no `./updateCrdUsage.sh` and no nexus-manager
  release.
- **After CI is green:** bump `hostDefault.chart.version` in the kcnas-operator
  config for dev, verify, then prod.

### Post-deploy verification

- `curl -N` the MCP SSE surface through the host and confirm the stream survives
  well past 60s with keep-alives at t+60/75/90s (#167).
- `curl -i -X POST /-/token -d grant_type=refresh_token -d refresh_token=DEAD...`
  returns `400` + `application/json` + `{"error":"invalid_grant"}` (#168).
- Fire 5 parallel refreshes with the same token; all 5 return `200` with an
  identical `refresh_token` (#169).
- Confirm `codex-mcp-client` reaches `initialize` — the end-to-end signal that
  #168 and #169 together resolved the deadlock.

## Out of scope

- Reworking `proxy.*` outbound timeouts. They are already configurable and are
  not implicated: `responseHeaderTimeout` bounds time-to-first-header only, and
  is disarmed for the life of a stream.
- RFC 6749 §5.2 conformance for endpoints other than `/-/token`
  (`/-/oauth/authorize` and friends have their own error-delivery rules under
  §4.1.2.1 — redirect-based, not body-based).
- Refresh-token replay *detection* and family revocation (RFC 9700 §4.14.2). The
  grace window neither adds nor removes this; it is absent today and stays
  absent.

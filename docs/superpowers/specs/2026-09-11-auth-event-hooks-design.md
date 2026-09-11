# Design: HTTP auth event hooks

**Date:** 2026-09-11
**Repo:** kdex-host-manager (host-manager only — no kdex-crds, no nexus-manager)
**Status:** approved design, pre-implementation

## Problem

There is today no way for a host to *react* to authentication lifecycle
events. A K-CNAS site cannot notify an external system when a user logs in or
out, cannot feed a security monitor with failed-login signals, and cannot gate
a login on an external policy decision. The only outbound auth call that exists
is the `Lookup` chain (credential/claims resolution), and the only side effect
at logout is refresh-token revocation.

We want a mechanism to react to login and logout (and, async-only, login-failed
and session-refresh) events by calling out to HTTP endpoints — endpoints that
are typically *implemented as* KDexFunctions but reached by host-manager as a
plain URL, exactly like the HTTP `Lookup` backend.

## Prior art: the HTTP `Lookup` backend (the pattern we parallel)

`internal/auth/lookup_http.go` + `internal/auth/roles.go`:

- Configured entirely through a **Kubernetes Secret** discovered by annotation
  (`kdex.dev/secret-type: http-lookup-auth`, `kdex.dev/active-key: "true"`),
  wired in `internal/controller/kdexinternalhost_controller.go:547-557`. **Not**
  a KDexFunction CR reference and **not** a typed KDexHost spec field.
- Secret `data`: `url` (required), `shared-secret` (required, ≥32 bytes),
  `timeout-ms` (optional, default 2000), plus a second `resolve-url`.
- Every call is `POST <url>`, `Content-Type: application/json`, authenticated
  with HMAC-SHA256: headers `X-K-CNAS-Lookup-Timestamp: <unix-ms>` and
  `X-K-CNAS-Lookup-Signature: hex(hmac-sha256(shared-secret, ts + "." + body))`
  (`computeSignature`, `lookup_http.go:200-206`).
- Sync/blocking: `http.Client{Timeout}` + `context.WithTimeout`, called inline
  on the login path.
- `ErrLookupUnavailable` (`roles.go:42`) distinguishes a backend *outage* (→ a
  server error) from a clean negative answer (`ok=false` → auth failure). This
  distinction is load-bearing and is reused here.

The event-hook feature deliberately mirrors this: Secret discovery, HMAC-signed
POST, `timeout-ms`, the outage-vs-answer discipline.

## Goals

- React to `login`, `logout`, `login-failed`, `session-refresh`.
- A hook is configurable **advisory** (async, fire-and-forget) or **enforcing**
  (sync) — but enforcing is honored only for `login` and `logout`.
- Enforcing `login` can **gate** (allow/deny + reason). It cannot mutate claims.
- Enforcing `logout` is a **barrier** (block until return/timeout) but never
  refuses the logout.
- Every blocking call has a **configurable timeout**.
- Blocking-call failure behavior is configurable per hook (fail-open /
  fail-closed) with secure defaults.

## Non-goals (YAGNI for v1)

- No retry queue / dead-letter / delivery guarantee for async events.
- No claim mutation/enrichment from a hook (that stays with `Lookup` +
  `ClaimMappings`).
- No enforcing mode for `login-failed` / `session-refresh`.
- No per-event separate URLs (one `url` per hook; the event type is in the body).
- No new CRD field.

## Configuration surface — Secret (exactly like Lookup)

Annotation-discovered Secret: `kdex.dev/secret-type: http-event-hook` and
`kdex.dev/active-key: "true"`. **Multiple such Secrets = multiple independent
hooks.** Secret `data` keys:

| key | required | default | meaning |
|---|---|---|---|
| `url` | yes | — | endpoint POSTed for each subscribed event |
| `shared-secret` | yes | — | HMAC-SHA256 key, ≥32 bytes |
| `events` | yes | — | comma-separated subset of `login,logout,login-failed,session-refresh` |
| `mode` | no | `advisory` | `advisory` \| `enforcing`; enforcing honored only for `login`/`logout` |
| `timeout-ms` | no | `2000` | bounds every call, sync and async |
| `failure-mode` | no | per-event | `fail-open` \| `fail-closed`; only meaningful for enforcing |

Validation at load (in the constructor, mirroring `NewHTTPLookup`):

- `url` present and parseable; `shared-secret` present and ≥32 bytes; `events`
  non-empty and every token in the known set.
- `mode=enforcing` with an `events` set containing only async-only events
  (`login-failed`/`session-refresh`) is accepted but logged as a warning; those
  events dispatch async regardless. When the set mixes (e.g.
  `login,session-refresh`, `enforcing`), enforcing applies to `login` only.
- `failure-mode` unset resolves per-event at call time: `login → fail-closed`,
  `logout → fail-open`. When set explicitly it applies to every enforcing event
  in that Secret.
- A malformed Secret is skipped with an error log (does not crash reconciliation
  or disable other hooks), matching how the Lookup chain tolerates a bad secret.

## Events × modes

| event | advisory (async) | enforcing (sync) | emission frame(s) |
|---|---|---|---|
| `login` | yes | yes — **gate** | `Exchanger.LoginLocal` success (`exchange.go:~957-976`); OIDC `ExchangeToken` success reachable from `OAuthGet` (`oauth2.go:235`) |
| `logout` | yes | yes — **barrier** | `LogoutPost` (`login.go:128-210`) / `RevokeRefreshToken` (`exchange.go:~679`) |
| `login-failed` | yes only | no | LoginLocal / OIDC failure path (carries `reason`) |
| `session-refresh` | yes only | no | refresh-token grant (`exchange.go:~560,1454`) |

## Request contract

`POST <url>`, `Content-Type: application/json`. Headers (reusing Lookup's
`computeSignature`, lifted to a shared helper):

- `X-K-CNAS-Event-Timestamp: <unix-ms>`
- `X-K-CNAS-Event-Signature: hex(hmac-sha256(shared-secret, ts + "." + body))`

Body envelope:

```json
{
  "event": "login",              // login | logout | login-failed | session-refresh
  "timestamp": 1699999999999,    // unix millis, matches the signature timestamp
  "host": "acme.example",        // the KDexHost identity
  "subject": "alice",            // sub; may be "" for logout when no token to decode
  "auth_method": "local",        // local | oidc | ...
  "client_id": "…",
  "scope": "openid profile …",
  "claims": { "…": "…" },        // rich for login/session-refresh; best-effort for logout
  "roles": ["…"],
  "entitlements": ["…"],
  "session_id": "…",             // refresh/session id where available
  "reason": "…"                  // login-failed only: why it failed
}
```

For `logout`, identity is recovered best-effort by decoding the refresh/session
token (whose `RefreshTokenClaims` carry Subject/ClientID/Scope/AuthMethod —
`exchange.go:~965-970`) before it is cleared. If the token is absent, `subject`
may be empty and the event still fires.

## Response contract

Read **only** for enforcing `login`:

```json
{ "ok": true, "reason": "" }
```

- `ok:false` → deny the login, surface `reason` (same discipline as Lookup's
  `ok=false`). No claims field is honored.
- Advisory calls, all async events, and enforcing `logout`: the response body is
  ignored; a 2xx means delivered, non-2xx/timeout/decode-failure is a delivery
  failure per the reliability rules below.

## Failure & reliability

- **Async** (all `login-failed`/`session-refresh`, plus advisory `login`/
  `logout`): dispatched in a background goroutine bounded by `timeout-ms`,
  best-effort. Failure (timeout/dial/non-2xx) emits an audit/log line. **No
  retry or queue in v1.** Never affects the user's flow.
- **Enforcing `login`**: inline on the login path, bounded by `timeout-ms`.
  `ok:false` → deny with `reason`. Timeout / dial / non-2xx / decode failure →
  resolve `failure-mode` (default `fail-closed` → deny with a generic reason; the
  outage is treated like `ErrLookupUnavailable`).
- **Enforcing `logout`**: barrier — block until return or `timeout-ms`. Timeout/
  error → proceed with logout (default `fail-open`), audited. The logout is never
  refused.

## Multiple-hook semantics

- **Async**: every matching hook fires concurrently and independently.
- **Enforcing `login`**: evaluated **sequentially in Secret-name order**,
  short-circuiting on the first `ok:false`; all must return `ok:true` to allow.
  (Sequential is deterministic and simple; enforcing login hooks are rare, so the
  summed latency is acceptable. Parallel all-must-pass, bounded by the max
  timeout, is a possible future change.)
- **Enforcing `logout`** barriers run sequentially in the same order; each is
  bounded by its own `timeout-ms` and cannot refuse the logout.

## Code shape (host-manager only)

- New `internal/auth/event_hook.go`:
  - An HMAC-signed POST client modeled on `lookup_http.go` (constructor
    `NewHTTPEventHook(secret corev1.Secret)` parsing the Secret schema above).
  - `computeSignature` lifted from `lookup_http.go` into a shared spot both use.
  - An `EventDispatcher` holding the parsed hooks and exposing
    `OnLoginSuccess(ctx, EventPayload)`, `OnLoginFailed(...)`, `OnLogout(...)`,
    `OnSessionRefresh(...)`. `OnLoginSuccess` returns an allow/deny error
    (enforcing); the others return nothing meaningful to the caller.
- Controller (`kdexinternalhost_controller.go`): discover the `http-event-hook`
  Secrets next to the Lookup secret (~`:547-557`), build the `EventDispatcher`,
  inject it into the Exchanger and the logout handler.
- Emission calls added at the frames listed in the events table. Enforcing login
  denial maps onto the existing login-failure response path; the barrier logout
  runs before cookies are cleared / the end-session redirect.

## Testing

Mirror `internal/auth/lookup_http_test.go` with an `httptest` server:

- Secret parsing/validation (missing url, short shared-secret, unknown event,
  enforcing-on-async-only warning, malformed secret skipped).
- Request contract per event: HMAC `X-K-CNAS-Event-Signature`/`-Timestamp`
  correct, envelope fields populated per event.
- Enforcing login: `ok:false` denies; timeout → fail-closed denies; explicit
  `failure-mode: fail-open` → allow on timeout.
- Enforcing logout: barrier waits; timeout → logout still proceeds (fail-open);
  logout never refused.
- Async best-effort: a 5xx/timeout on an advisory or async event does not affect
  the login/logout outcome.
- Multiple hooks: async fan-out fires all; enforcing login is AND with
  short-circuit in secret-name order.
- Logout identity: subject recovered from the refresh/session token; empty when
  absent, event still fires.

## Documentation

Authoritative documentation lives in host-manager (README / package docs for the
`http-event-hook` Secret), since there is no CRD field. The Lookup Secret is
documented as prose in `kdex-crds` `kdexhost_types.go:190-245`; adding a parallel
event-hook prose block there is an **optional follow-up** (docs-only, no schema
change) kept out of this host-only change.

## Blast radius

host-manager only. No kdex-crds change, no nexus-manager change, no 3-actor
release. New minor release: **v0.13.0 → v0.14.0**.

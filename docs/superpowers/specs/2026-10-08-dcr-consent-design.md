# Consent for dynamically registered clients (stage 1)

**Status:** approved design, 2026-10-08; revised 2026-10-09 after a four-lens review
**Repos:** kdex-host-manager only (stage 1). Stage 2, a themeable Consent utility page, spans
kdex-crds → kdex-nexus-manager → kdex-host-manager and is out of scope here.

## Problem

`/-/oauth/authorize` issues an authorization code to a client as soon as the browser has a session.
For operator-configured (static) clients that is acceptable. Dynamically registered (RFC 7591)
clients are registered anonymously and may use remote redirects, so issuing them a code without the
user's explicit agreement is not acceptable (RFC 6749 §10.2, RFC 7591 §5, RFC 9700 §2.1).

A related gap: `GetClient` re-applies the DCR grant policy to stored clients but not the redirect
policy, so tightening `allowedRedirectSchemes` does not affect clients already registered.

## Intent and success criteria

- A DCR client never receives a code for a user who has not explicitly allowed **that client at that
  redirect**.
- An Allow is remembered per (user, client, redirect) while the client is in use, so routine
  re-authorization does not prompt. A new registration always prompts.
- `prompt=none` without covering consent returns `consent_required`; `prompt=consent` always shows
  the page for a DCR client, and Allow then completes.
- A DCR session cannot outlive its consent: the refresh grant requires it.
- Static clients behave exactly as today.
- Tightening `allowedRedirectSchemes` takes effect on stored DCR clients immediately.
- claude.ai, Cursor, VS Code and codex keep working.

## Design

### 1. Which clients need consent

`AuthClient` gains `RequireConsent bool`, set only by the DCR branch of `Exchanger.GetClient`, and
pinned by a `GetClient` test. Every DCR client requires consent, whatever its redirect scheme.
Static clients never see the page; `prompt=consent` is ignored for them.

### 2. What a consent covers

A consent is recorded per **(subject, client_id, redirect_uri)** and holds the set of **granted
scopes**. Only scopes this host supports count: requested scopes are intersected with
`SupportedScopes` (what `applyScopeFilter` will actually issue) for display, storage and the covers
check, so attacker-written scope strings are neither shown nor recorded.

A request is *covered* when a record exists for its (subject, client_id, redirect_uri) and its
supported scopes are a subset of the granted set. An empty scope request is covered by any record
for that redirect (it yields the minimal token, `confineByScope`).

`resource` is not part of consent. The page states that the application gets access to the user's
account with the user's permissions, which is what both a host JWT and a resource PAT amount to.
Enforcing that a code's `resource` matches the token request's (RFC 8707 §2.2) is a separate,
pre-existing defect, filed and fixed on its own.

### 3. Authorize flow

`AuthorizeHandler`, for a client with `RequireConsent`, after the client, redirect, PKCE and
response-type checks:

1. **No session** → as today: `prompt=none` gives `login_required`, otherwise the login redirect.
2. **A session that did not come from the session cookie** (an `Authorization: Bearer` header) →
   treated as no session. Codes for DCR clients are only issued to a browser session; the middleware
   records the auth source in the context. A browser session is an allow-list: the token came from
   the cookie, its `auth_method` is `local` (`/-/login`) or `oidc` (the OIDC callback), both kept by
   cookie rotation, and it is not a capability (`kdx_cap`). `auth_method` is a signed claim: the
   signer projects it and a claimMappings rule cannot change, add or remove it. Every other token is
   not a browser session, even from the cookie: an OAuth client's tokens (`auth_method: oauth2`:
   authorization-code access and id tokens, password and client_credentials tokens), a capability,
   and a token with no `auth_method` (fail closed; a session signed before the claim was projected
   is signed out for DCR clients only, and the user logs in again). Only this gate reads
   `auth_method`: authorization decides exactly as before (scope bucketing by `auth_method` in
   `GetParsedEntitlements` stays off), and a claimMappings rule cannot change it on a FAT either
   (`EnrichAuthContext`). (Static clients unchanged.)
3. **`prompt=none` and no covering consent** → `consent_required`, decided **before** `login_hint` is
   evaluated, so an unconsented client cannot use `login_hint` to learn who is signed in.
4. Then the existing `prompt=login|select_account` / `login_hint` handling (ddba71e).
5. **Covered and `prompt` lacks `consent`** → issue the code as today.
6. **Otherwise** → render the consent page (200). No code is minted.

`prompt` rewriting goes through one helper used by both detours, so neither loops nor loses a value:
the **login** detour removes `login`, `select_account` and `none` from the return URL and **keeps
`consent`**; the **Allow** redirect removes `consent`.

### 4. `POST /-/oauth/consent`

Registered with the authentication middleware. Form fields: `request` (sealed) and `decision`
(`allow` | `deny`).

Refuse with **403** and no state change unless all hold:

- **Same origin, strictly.** `Origin` (else `Referer`) must name one of the host's domains with its
  scheme **and port**; a request with neither header, or `Origin: null`, is refused. Where present,
  `Sec-Fetch-Site` must be `same-origin`, together with `Sec-Fetch-Mode: navigate`,
  `Sec-Fetch-Dest: document` and `Sec-Fetch-User: ?1` (a user submitting the form in a top-level
  page, not a same-origin `fetch`, iframe or scripted submit). WebKit never sends `Sec-Fetch-User`
  (bugs.webkit.org 247697), so its absence is waived for WebKit User-Agents only. Safari and every
  iOS browser therefore keep every check except user activation (v0.28.2, kdex-tech/host-manager#264).
  The comparison is extracted from `login.go` into
  `kdexhttp.SameOrigin(raw, scheme, domains)`; `/-/login` keeps its lenient wrapper, consent uses a
  strict one, passed into `OAuth2` as a func field.
- **A browser session** (the §3 definition: `isBrowserSession`) whose subject equals the sealed request's subject.
- **The sealed request** opens, names this issuer, and has not expired.
- **The client still resolves**, still requires consent, and still lists the request's
  `redirect_uri`.

The sealed request is a JWE carrying only `{sub, iss, query, exp}` (10 minutes). Both authorize and
the POST derive client_id, redirect_uri and the supported-scope set from the query through one
`parseAuthorizeRequest` helper, so they cannot disagree. It is not single-use: replaying an Allow
needs the same user's browser session and a same-origin POST, and only re-records what that user
already allowed.

- `allow`: record the consent (section 6) and **303** to `/-/oauth/authorize?<query with consent
  removed from prompt>`. Authorize re-runs every check and mints the code.
- `deny`: delete any consent for (subject, client_id, redirect_uri), then **302** to `redirect_uri`
  with `error=access_denied` and `state`.

### 5. The consent page

**Flow-level headers**, set by the auth flow on every consent response before rendering:
`Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` (not
`no-referrer`: that makes the browser send `Origin: null` on the POST, which section 4 refuses), and
`Content-Security-Policy: frame-ancestors 'none'`.

**Renderer.** `OAuth2.RenderConsent func(http.ResponseWriter, *http.Request, ConsentView)`. When nil,
`auth.RenderBuiltinConsent` is used; it is exported so stage 2 falls back to it rather than to a copy.
Its own CSP adds `default-src 'none'; script-src 'sha256-<arm script>'; style-src 'unsafe-inline'`.
**No `form-action` directive**: browsers apply it to the redirects that follow the POST, which leave
the origin by design. Its template is parsed once at package init.

**Holding Allow back.** Framing is refused, but a double-click lure is not: a popup asks for a
double-click and swaps this page in under the second click. The page's one script, allowed only by
its hash, marks Allow `aria-disabled` and refuses its submit until a trusted pointer move or key
press on the page while it is visible and focused, plus 500 ms; losing focus or visibility holds it
back again. It never clicks, submits or navigates. Without script, the CSS hold (Allow inert for one
second after load) still applies. Stage 2's themeable page must allow no script on this response
other than this one by hash; a theme script on the consent page could click Allow.

**`ConsentView`** carries data, not copy, under fixed field names (they become the stage-2 template
contract):

- `RedirectDisplay`: for `https`, the ASCII (punycode) host and port, with `RegistrableDomain`
  (eTLD+1, `golang.org/x/net/publicsuffix`) for emphasis; for loopback or a private-use scheme,
  `RedirectKind: "device"` and the scheme, rendered as "an application on this device".
- `RedirectURI`: the full URI, shown small.
- `ClientName`: Unicode control and format characters (Cc, Cf, including bidi overrides) removed,
  capped at 64 characters, marked as provided by the application and unverified.
- `Scopes`: the supported requested scopes (empty means minimal access; the renderer words it).
- `Account`: the signed-in email, else subject.
- `Request`, `Action`.

**Against click hijacking:** Deny comes first and is the default; Allow is not focused and ignores
pointer events for its first second (a CSS animation, allowed under the CSP).

### 6. Consent store

`dcr.ConsentStore`, built beside `dcr.Store` in `buildDCRStore` with the same cache manager and the
DCR `ClientTTL`, `Uncycled` (it must survive a reconcile, #122), with an explicit `MaxItems` for the
in-memory backend (the default 1000 is too small; in-memory mode is documented as dev-only).

One record per **subject**, keyed `sha256(subject)`: `{client_id: {sha256(redirect_uri): {scopes, touched}}}`.
Redirects are stored as digests: they are only matched exactly, and a registered one may be 2 KB.
Per-subject keys let the follow-up list and revoke a user's consents without a cache scan. Bounds:
at most 64 clients per subject (oldest `touched` evicted), 4 redirects per client, 32 scopes of at
most 128 bytes. Methods: `Covers`, `Grant`, `Revoke(client, redirect)`, `Touch`.

The TTL is the client TTL and slides with use: `Covers` on authorize and the refresh check rewrite
the record only when `touched` is older than `min(24h, TTL/4)`, so a consent lives exactly as long as
its client is in use, at no more than one write per user per day once the TTL is long. Concurrent updates to one subject's record
are last-writer-wins; a lost update only means the user is asked again.

All store calls use the request context with a 2s deadline. A read error or timeout on authorize
means "not covered" (the page is shown; never skipped). Any store error in the POST, including the
client lookup, answers **503** with `Retry-After`. Errors are logged at error level.

### 7. The refresh grant requires consent

`RedeemRefreshToken`, for a client with `RequireConsent`, requires a consent record for (subject,
client_id) at a redirect the current policy still allows for the client, and touches it. Without one
the grant fails with `invalid_grant`. Revoking the consent at every allowed redirect (each Deny
revokes one), consent expiry, client expiry, and narrowing the policy past the consented redirect
therefore end the session.

At rollout no consent records exist, so **every existing DCR session's next refresh fails once** and
the client sends the user through authorize, where they consent. This is deliberate: it also ends any
session obtained before the fix.

### 8. Redirect policy on stored clients

`dcr.FilterRedirectURIs(uris, schemes) []string` replaces the per-URI `redirectAllowed`, beside
`FilterGrantTypes`, together with the dangerous-scheme list and the default schemes. It also refuses
a URI with userinfo, a fragment, an empty host, a non-ASCII host, or more than 2 KiB. Registration
and `GetClient` both use it. In `GetClient`, a stored client whose redirects all fail is **deleted**
from the store (not just hidden) and does not exist; tightening the policy therefore ends those
clients' sessions, which is the intent.

### 9. Shared plumbing

- One `sealJSON(purpose, v)` / `openJSON(purpose, s, &v)` (JWE `dir`+`A256GCM`, key
  `sha256(purpose ‖ 0x00 ‖ BlockKey)` derived once) for the consent request, the OIDC login state,
  and authorization codes. Codes keep an empty purpose so their key does not change at rollout.
- Path constants `OAuthAuthorizePath`, `OAuthConsentPath` beside `OAuthLoginPath` and
  `OAuthCallbackPath`.
- `hh.newOAuth2()` builds the one `auth.OAuth2` used by authorize, the callback and the token
  endpoint, so the hooks cannot be set on one and missed on another.
- `POST /-/oauth/consent` is registered in OpenAPI; the authorize operation documents the 200
  `text/html` response.
- Error redirects reuse `redirectAuthorizeError`.

## Error handling

| Case | Answer |
|---|---|
| DCR client, `prompt=none`, no covering consent | 302 `consent_required` (before `login_hint`) |
| DCR client, bearer-sourced session | as no session |
| DCR client, no covering consent | 200 consent page |
| Consent POST: cross-origin, null or missing Origin, cross-site `Sec-Fetch-Site`, no cookie session, subject mismatch, bad or expired seal, wrong issuer, client gone, redirect no longer listed | 403 |
| Consent POST, store error | 503 `Retry-After` |
| Consent POST `deny` | consent removed, 302 `access_denied` |
| Consent read error on authorize | page shown |
| Refresh for a DCR client without consent | `invalid_grant` |

## Rollout

- host-manager 0.23.0, together with ddba71e (OIDC login binding, #233/#234) and the quad fixes to it.
- Every existing DCR session refreshes into `invalid_grant` once; each user consents once per client.
- No CRD, chart or nexus change. `golang.org/x/net` becomes a direct dependency (already indirect).
- Keep this design, the code and the tests unpushed until the release is built, and push them
  together with the tag.

## Testing (TDD)

- Page, not a code: signed-in DCR client without consent; headers as in section 5.
- Allow → code. Same redirect with the same or fewer scopes → code without the page. A broader
  supported scope → page. Unsupported scope strings → not shown, not recorded, no new prompt.
- **A second redirect of the same client is not covered** by consent given for the first.
- `prompt=consent` → page → Allow → code (no loop). `prompt=login consent` keeps `consent` across
  login. `prompt=none` → `consent_required`; with consent → code.
- `prompt=none` + `login_hint` for an unconsented client → `consent_required` whether the hint
  matches or not.
- Bearer-sourced session at authorize for a DCR client → treated as signed out.
- Deny → `access_denied`, and a following authorize prompts again.
- POST refused (403) for: foreign Origin, `Origin: null`, no Origin and no Referer, cross-site
  `Sec-Fetch-Site`, no session, bearer session, another subject, tampered seal, expired seal, other
  issuer, deleted client, unregistered redirect. Store failure → 503.
- Refresh for a DCR client without consent → `invalid_grant`; with consent → rotates.
- Stored client whose redirects all fail the current policy → deleted, unknown at authorize and
  token. Registration refuses userinfo, fragment, empty, non-ASCII and over-long redirects.
- Rendering: a hostile `client_name` (bidi override, HTML) and a punycode host are shown safely;
  a private-use redirect is shown as an application on this device.
- Static client unchanged; `prompt=consent` ignored for it.
- The attack end to end: anonymous registration with a remote redirect, signed-in user follows the
  link, no code reaches the redirect; consent given for one redirect does not release a code to a
  second.

## Follow-ups (not in stage 1)

- Stage 2: `Consent` KDexUtilityPageType, `utilityPages.consentRef`, the bundled default page,
  translations; built-in page as fallback.
- List and revoke your consents (the per-subject record supports it).
- RFC 8707: bind a code's and a refresh token's `resource` to the token request (filed separately).
- Optionally `auth_time` in tokens, so a client can tell a fresh login after `prompt=login`.

## Out of scope

- Consent for static clients.
- Any change to what DCR registration accepts beyond the stricter shared redirect check.

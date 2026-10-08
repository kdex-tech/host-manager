# Consent for dynamically registered clients (stage 1)

**Status:** approved design, 2026-10-08
**Repos:** kdex-host-manager only (stage 1). Stage 2, a themeable Consent utility page, spans
kdex-crds → kdex-nexus-manager → kdex-host-manager and is out of scope here.

## Problem

`/-/oauth/authorize` issues an authorization code to any client the moment the browser carries a
session. There is no consent step. For operator-configured (static) clients that is acceptable: an
operator authored them. Dynamically registered (RFC 7591) clients are different: registration is
anonymous, and `allowedRedirectSchemes` admits `https` by default (and on knowdrive dev and prod).

So anyone can register a client whose redirect is their own `https` site, then send a signed-in
user a link to `/-/oauth/authorize?client_id=<theirs>&redirect_uri=<theirs>&code_challenge=<theirs>`.
The session cookie is `SameSite=Lax`, so it rides the top-level navigation, a code is issued to the
attacker's redirect, and the attacker redeems it with their own PKCE verifier for the user's access
and refresh tokens (or a resource PAT). One click, no prompt.

Removing `https` from the allowed schemes is not a usable mitigation: claude.ai MCP connectors
register an `https` callback.

A related gap (quad finding, 2026-10-08): `GetClient` re-applies the DCR **grant** policy to stored
clients (d3fa133) but not the **redirect** policy, so tightening `allowedRedirectSchemes` does not
affect clients already registered, and the store slides each client's TTL on use.

## Intent and success criteria

- A DCR client never receives a code for a user who has not explicitly allowed that client.
- An Allow is remembered per (user, client_id) until it expires (the DCR client TTL), so a client
  re-authorizing for no new scopes or resources does not prompt again. A new registration (new
  client_id) always prompts.
- `prompt=none` without stored consent returns `consent_required`; `prompt=consent` always shows
  the page for a DCR client.
- Static clients behave exactly as today.
- Tightening `allowedRedirectSchemes` takes effect on stored DCR clients immediately.
- claude.ai, Cursor, VS Code and codex keep working; their users see the page once per client.

## Design

### 1. Which clients need consent

`AuthClient` gains `Dynamic bool`, set only by the DCR branch of `Exchanger.GetClient`. Consent is
required for every dynamic client, whatever its redirect scheme (decided 2026-10-08: one rule; it
also covers a local app squatting a private-use scheme). Static clients never see the page, and
`prompt=consent` is ignored for them.

### 2. Authorize flow

In `AuthorizeHandler`, after the existing client, redirect, PKCE, session, `prompt`/`login_hint`
and subject checks, and before minting the code:

1. If the client is not dynamic: unchanged.
2. Let *requested* be the scope set (`strings.Fields(scope)`) plus the `resource` value if any.
   If `prompt` does not contain `consent` and the stored consent for (subject, client_id) covers
   *requested*: issue the code as today, and refresh the consent record's TTL.
3. Else if `prompt` contains `none`: redirect to `redirect_uri` with `error=consent_required` and
   `state` (RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.6).
4. Else: answer **200** with the consent page (section 4). No code is minted.

"Covers" means a consent record exists and *requested* ⊆ its stored set. An empty scope request
is covered by any existing record (it asks for the client's default access, which the first Allow
already showed).

### 3. `POST /-/oauth/consent`

Registered with the authentication middleware (like authorize), so the session is in context.

Form fields: `request` (sealed, below) and `decision` (`allow` | `deny`).

Refuse with **400** (no redirect, no state change) unless all hold:

- **Same origin.** `Origin`, else `Referer`, names one of the host's domains with its scheme. Unlike
  `originAllowed` for `/-/login`, a request carrying neither header is refused: browsers send
  `Origin` on every form POST. (Defence in depth: the `SameSite=Lax` session cookie is not sent on a
  cross-site POST, so a forged submission also arrives without a session.)
- **A session** whose subject equals the sealed request's subject.
- **The sealed request** decrypts, and has not expired.
- **The client still resolves** through `GetClient`, is dynamic, and still lists the request's
  `redirect_uri`.

Then:

- `allow`: union *requested* into the stored consent for (subject, client_id), with TTL = the DCR
  client TTL, and **303** to `/-/oauth/authorize?<original query>`. Authorize re-runs every check,
  finds the consent, and issues the code: minting stays in one place, and nothing in the sealed
  query is trusted beyond what authorize re-validates.
- `deny`: **302** to `redirect_uri` with `error=access_denied` and `state`.

**Sealed request.** A JWE (`dir` + `A256GCM`) under a key derived from the OIDC block key with its
own purpose label (`"dcr-consent\x00"`), carrying `{sub, client_id, redirect_uri, requested[],
query, exp}` with a 10-minute expiry. It is not single-use: replaying an Allow needs the same
user's session and a same-origin POST, and only re-records the consent that user already gave.

The block key is mandatory outside dev mode (`loaders.go`). The JWE seal/open is written once as a
purpose-keyed helper and also used by the OIDC login-state cookie (resolving the quad's duplicate
JWE finding in ddba71e).

### 4. The consent page (built-in)

Rendered through a hook, `OAuth2.RenderConsent func(http.ResponseWriter, *http.Request, ConsentView)`,
set by the host. Stage 2 swaps the implementation for the Consent utility page without touching
the flow; stage 1 renders a small `html/template` page in host-manager: English only, inline CSS,
no external assets.

`ConsentView` carries: the redirect **host** (shown most prominently; it is where the code goes),
the full `redirect_uri`, the client's self-declared `client_name` (labelled as provided by the
application and unverified), the requested scopes (an empty request shown as "basic access to your
account"), the requested resource if any, the signed-in account (email, else subject), the sealed
request, and the form action.

Response headers: `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-store`,
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self';
frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. Framing must be
impossible: a framed consent page is a clickjacking target.

All values are HTML-escaped by `html/template`; `client_name` is length-capped for display.

### 5. Consent store

A `dcr-consent` cache on the Exchanger: `Uncycled` (it must survive a config reconcile, like the DCR
client store, #122), TTL = `DCR.ClientTTL` (720h on knowdrive). Key: `sha256(subject + "\x00" +
client_id)` hex. Value: JSON `{"granted": [...]}`, the union of every allowed *requested* set.
Present only when DCR is enabled. A store error on read is treated as "no consent" (the page is
shown, never skipped); on write it is a 500 from the POST.

### 6. Stored-client redirect re-check

`redirectAllowed` and `dangerousSchemes` move from `internal/host/register.go` into
`internal/auth/dcr`, beside `FilterGrantTypes`, as `dcr.RedirectAllowed(uri, schemes)`.
`GetClient`'s DCR branch keeps only the stored `redirect_uris` the **current**
`DCR.AllowedRedirectSchemes` admit; if none survive, the client does not exist. Registration uses
the same function, so the two cannot drift.

## Error handling

| Case | Answer |
|---|---|
| DCR client, no covering consent, `prompt=none` | 302 `redirect_uri?error=consent_required&state=…` |
| DCR client, no covering consent | 200 consent page |
| Consent POST: cross-origin, no Origin/Referer, no session, subject mismatch, bad or expired seal, client gone, redirect no longer listed | 400 |
| Consent POST `deny` | 302 `redirect_uri?error=access_denied&state=…` |
| Consent POST `allow`, store write fails | 500 |
| Consent read fails | page shown (fail closed) |

## Rollout

- Every user of an existing DCR client sees the page once, the next time that client sends them
  through authorize. claude.ai connectors only do so when a refresh fails.
- Releases as host-manager 0.23.0 together with ddba71e (OIDC login binding, #233/#234) and the
  fixes the quad found in it.
- No CRD, chart or nexus change.

## Testing (TDD)

- Signed-in user + DCR client, no consent → 200 page, no code; headers in section 4 present.
- Allow → 303 to authorize → code issued; second authorize with the same or fewer scopes → code
  without the page; a broader scope or a new resource → page again.
- `prompt=consent` forces the page even with consent stored; `prompt=none` without consent →
  `consent_required`; with consent → code.
- Deny → `access_denied` with state.
- POST refused for: foreign Origin, missing Origin and Referer, no session, another subject,
  tampered seal, expired seal, client deleted, redirect no longer registered.
- Static client: unchanged, never shown the page, `prompt=consent` ignored.
- Stored DCR client whose only redirect scheme was removed from `allowedRedirectSchemes` → unknown
  client at authorize and token.
- End to end, the attack: anonymous registration with an `https` redirect, signed-in user follows
  the authorize link → no code reaches the redirect.
- Page escapes a hostile `client_name` and redirect.

## Follow-ups (not in stage 1)

- Stage 2: `Consent` KDexUtilityPageType (kdex-crds), `utilityPages.consentRef` and the bundled
  default page (nexus), host-manager renders it when bound, built-in page as fallback; translations.
- A way for a user to list and revoke their consents.

## Out of scope

- Consent for static clients.
- Changing what DCR registration accepts (other than the shared redirect check).

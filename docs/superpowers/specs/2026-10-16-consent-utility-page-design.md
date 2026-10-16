# A themeable Consent utility page (DCR consent, stage 2)

**Status:** approved design, 2026-10-16
**Repos:** kdex-crds → kdex-nexus-manager + kdex-host-manager (released together)
**Builds on:** [stage 1](2026-10-08-dcr-consent-design.md), shipped in host-manager 0.23.0

## Problem

Stage 1 shipped one consent page for every host: a fixed template in
`internal/auth/consent_page.go`. `OAuth2.RenderConsent` exists so a host can render its own, but
nothing sets it, so the consent page is unbranded on every host while the login page next to it
carries the host's theme. Operators need to brand the consent page with a CR, the way they brand
login, error and announcement.

The constraint that shapes everything: the consent page must run **no script except the one
hash-pinned script that holds Allow back**. Any other script on that page could click Allow. Utility
pages today can pull script from many places: the page's `rawHTML`, its `scriptLibraryRef`, KDexApp
content, and whatever the chosen archetype prints (`.HeadScript` with the importmap, `.FootScript`,
`.Navigation`, whose every entry emits an inline fetch script, and headers and footers, which are
free-form template HTML). Theme and host assets take free-form attributes (`onload=` included)
that are written out unescaped.

## Intent and success criteria

- A host's consent page carries its theme, header, footer and translated wording, with no
  configuration on an existing host.
- The disclosure (account, where the code goes, the full address, the unverified client name, the
  scopes, the warning), the Allow/Deny form and the hold-back script are always present and always
  host-manager's own. A consent CR can style and surround them, never alter, omit or duplicate them.
- No script runs on the consent page except the hold-back script, whatever the CRs, the archetype,
  the theme or the host assets contain.
- A broken or missing consent CR degrades to the stage-1 built-in page, never to a broken page.
- Consent is still required only for dynamically registered clients, and only DCR-enabled hosts ever
  render it. Static clients and DCR-disabled hosts are unaffected.

## Why not CEL or a webhook as the boundary

- **CEL** sees only the object being written. The consent page's script can come from referenced
  objects (archetype, header, footer, navigation, theme), which CEL cannot follow. Scanning
  `rawHTML` for script is both expensive (it has no `maxLength`, so a rule over it threatens the CRD's
  cost budget) and bypassable (`on*=` attributes, `javascript:` URLs, `<svg onload>`).
- **The nexus webhooks** are `failurePolicy=Ignore` (fail-open), check only at write time while the
  referenced objects can change later, and do not cover `KDexInternalUtilityPage`.

The boundary is therefore the consent response's own Content-Security-Policy, set by host-manager
at render time, plus render-time stripping of every script source. CEL is used only for exact
structural checks that catch obvious mistakes early.

## Design

### kdex-crds

- `KDexUtilityPageType` gains `Consent`, in the type's enum and in the `type` field's enum (the field
  repeats it).
- `KDexHost.spec.utilityPages` gains `consentRef`, with the same
  `KDexUtilityPage | KDexClusterUtilityPage` kind rule as the other three refs.
- `KDexInternalHost.spec` gains `consentRef` next to `announcementRef`, `errorRef` and `loginRef`.
- A new rule on `KDexUtilityPageSpec`, which the namespaced, cluster and internal kinds all share:

  ```
  self.type != 'Consent' || (!has(self.scriptLibraryRef) && self.contentEntries.all(e, !has(e.appRef)))
  ```

  Message: "a Consent page cannot reference scripts: no scriptLibraryRef and no appRef content". It
  touches no string content, so it adds no cost-budget risk.
- No rule over `rawHTML` content (see above).

This is a CRD schema change, so both nexus-manager and host-manager are released with it.

### kdex-nexus-manager

- `resolveUtilityPages` adds `Consent → consentRef` and writes `KDexInternalUtilityPage`
  `<host>-consent`; the host controller watches `spec.utilityPages.consentRef.name` and sets the
  internal host's `consentRef`. `isDefaultUtilityPage` learns the new default.
- The host defaulter fills an empty `consentRef` with `kdex-default-utility-page-consent` (a new
  constant in `internal/webhook/types.go`), exactly as for the other three, on every host whether or
  not DCR is enabled: it is only a reference, a host that turns DCR on later gets a branded page with
  nothing else to change, and the defaulter need not read the auth config. The cost is one internal
  utility page per host.
- Bundled `config/bundled/kdex-default-utility-page-consent.yaml`: a `KDexClusterUtilityPage`,
  `type: Consent`, on the existing `kdex-default-page-archetype-utility` (which prints no script).
  Its `main` slot wraps `[[ .Extra.consent.Block ]]` in the same container classes as the login page
  (`login-container`) so the default theme styles it, with the brand name and the organization
  footer. No script.
- `kdex-default-translation` gains the `consent.*` keys (below) in all 8 bundled languages.
- No new webhook logic; the existing template-parse validator already covers Consent pages.

### kdex-host-manager

**Wiring.** `newOAuth2` sets `OAuth2.RenderConsent` to `hh.renderConsentPage`. The utility-page
warm-up loop and the internal host watch gain `Consent`.

**The fixed block.** A new `auth.RenderConsentCore(v ConsentView, marker string, t Translator)
template.HTML` in `consent_page.go` renders the disclosure, the form (with the sealed request) and
the hold-back script. The built-in page is refactored to wrap this same block, so the codebase has
exactly one consent form and one hold-back script. The template never receives `ConsentView` or the
sealed request; it receives only the rendered block as `.Extra.consent.Block`.

**Wording.** Every string in the block is a `consent.*` key looked up through the host's `l10n`
printer, with a per-key fallback to the current English text in host-manager, so a stale or partial
translation never shows a raw key. Translations are plain text: the block escapes the translated
format string, then substitutes arguments that are themselves escaped (and wrapped in `<strong>`
where the stage-1 page bolds them). The keys, which are the contract between host-manager's
fallbacks and nexus's bundled translation:

| Key | English fallback |
|---|---|
| `consent.page-title` | Allow access? |
| `consent.title` | Allow access to your account? |
| `consent.signed-in-as` | Signed in as %s. |
| `consent.web.sends-to` | Allowing sends access to: |
| `consent.web.website` | Website: %s |
| `consent.device.sends-to` | Allowing sends access to %s (%s). |
| `consent.device.application` | an application on this device |
| `consent.full-address` | Full address: %s |
| `consent.client-name` | The application calls itself %s. This name is provided by the application and has not been verified. |
| `consent.permissions` | It will be able to act on your account with your permissions. |
| `consent.permissions-scopes` | It will be able to act on your account with your permissions and read: %s. |
| `consent.warning` | Only allow this if you started connecting this application yourself. |
| `consent.allow` | Allow |
| `consent.deny` | Deny |

The block keeps stage 1's conditions: the `web` or `device` lines by `RedirectKind`, the website
line only with a `RegistrableDomain`, the client-name line only with a `ClientName`, and
`consent.permissions` or `consent.permissions-scopes` by whether `Scopes` is empty.

An operator can reword these through their own translation; operators are trusted with the host.

**`renderConsentPage(w, r, v)`:**

1. Generate a per-render random marker and render the block for the request's language. The block's
   root carries the marker as an attribute.
2. Render the Consent utility page with `.Extra.consent.Block` set, through a **scriptless** option
   on the utility renderer that forces `.HeadScript`, `.FootScript` and `.Navigation` empty whatever
   the archetype prints. `.Theme`, `.Meta`, `.Header`, `.Footer` and the content slots render as
   usual.
3. If the rendered page does not contain the marker **exactly once**, serve the built-in page and log
   an error naming the utility page. The template cannot know the marker, so it cannot fake the
   block; a template that forgot the block, or printed it twice (two forms), degrades to the built-in
   page.
4. If the host has no Consent utility page, or rendering fails, serve the built-in page.

**Headers.** The flow headers are unchanged (`Cache-Control: no-store`, `X-Frame-Options: DENY`,
`Referrer-Policy: same-origin`, `Content-Security-Policy: frame-ancestors 'none'`). The branded page
adds:

```
default-src 'none'; script-src 'sha256-<hold-back script>'; style-src 'self' https: 'unsafe-inline';
font-src 'self' https: data:; img-src 'self' https: data:; base-uri 'none'
```

plus `Content-Language` and `Content-Type: text/html; charset=utf-8`. Scripts are locked to the hash;
`connect-src`, `frame-src` and `object-src` fall under `default-src 'none'`; `base-uri 'none'` stops a
`<base>` tag redirecting relative URLs. Styles, fonts and images are open to `'self'`, `https:` and
`data:` so any theme works with no configuration (the bundled default theme loads from
fonts.googleapis.com, fonts.gstatic.com and cdn.jsdelivr.net and uses `data:` images). As in stage
1, there is no `form-action`: browsers apply it to the redirects after the POST, which leave the
origin by design. The built-in page keeps its stricter stage-1 policy. The page is never cached: the
utility renderer already bypasses its cache when Extra is set.

**Hold-back script.** It guards **every** `button[value=allow]` on the page, not only the first
form's, so the exactly-once check is not the only defence against a second form. Its hash changes;
the CSP is computed from the constant.

**Accepted risks.**

- `<meta http-equiv=refresh>` in a theme or host asset cannot be blocked by CSP. At worst it
  navigates away from the consent page: a nuisance, not a bypass, and only the operator can author it.
- Theme CSS could in principle leak the hidden sealed request through attribute-selector image
  loads. The value is useless off-site: posting it still needs the user's session cookie and passes
  the same-origin and Fetch-Metadata checks. Theme CSS is operator-authored.
- Inline `onload=` and similar attributes on theme or host assets are blocked by the CSP (no
  `'unsafe-hashes'`).

## Error handling

| Condition | Result |
|---|---|
| Host has no Consent utility page | built-in page |
| Utility page render error | built-in page, error logged |
| Marker missing or present more than once | built-in page, error logged naming the utility page |
| Translation key missing in the host's catalog | that key's English fallback |
| Consent CR with `scriptLibraryRef` or `appRef` content | rejected at write time (CEL) |

## Rollout

1. `./updateCrdUsage.sh -t`: tag kdex-crds and repin nexus-manager and host-manager.
2. Release nexus-manager (bundled page, translation, defaulter, resolution) and host-manager
   (0.24.0) together, per the CRD release rule.

Either order of rollout is safe: a new host-manager with an old nexus never sees a `consentRef` and
serves the built-in page; a new nexus with an old host-manager writes a consent page that the old
host-manager never uses.

0.23.0 is pinned fleet-wide independently of this work; stage 2 adds branding only.

## Testing (TDD)

**kdex-crds** (envtest, which installs the CRD and runs CEL with its cost estimator; decode tests
alone do not catch a cost-budget failure):

- a Consent page with only `rawHTML` content is accepted;
- a Consent page with `scriptLibraryRef`, or with any `appRef` entry, is rejected with the message;
- Announcement, Error and Login pages are unaffected by the rule;
- `consentRef` accepts only the two utility-page kinds.

**kdex-nexus-manager:**

- `resolveUtilityPages` writes `<host>-consent` and the internal host's `consentRef`;
- the defaulter fills `consentRef` only when empty;
- the bundled consent page passes `ValidateContent`;
- the bundled translation has every `consent.*` key in all 8 languages, checked against the key list
  above.

**kdex-host-manager:**

- `RenderConsentCore` escapes every view field and argument, and falls back per key to English;
- the built-in page still renders, and its CSP hash matches the script in its output;
- `renderConsentPage` output contains `.Theme`, the header and the footer, and no head script, foot
  script, importmap or navigation, using a test archetype that prints all of them;
- the branded page's CSP header is exactly as specified;
- a missing marker, a doubled marker, no Consent page and a render error each serve the built-in page
  and log an error;
- the hold-back script holds back every Allow button on a page with two;
- the stage-1 consent flow tests pass through the `RenderConsent` hook.

**Live, after deploy** (public and spike2, browser): the consent page is themed; a CSP violation probe
shows scripts are locked to the hold-back hash; the hold-back holds (double-click, blur); Allow returns
a code.

## Out of scope

- Listing and revoking your consents (stage-1 follow-up; the per-subject record supports it).
- Letting a CR alter the disclosure, the form or the buttons' placement (rejected: option B).
- Per-host CSP allow-lists for theme origins (rejected in favour of open non-script sources).

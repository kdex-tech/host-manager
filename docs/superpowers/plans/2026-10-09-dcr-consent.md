# DCR Consent (stage 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A dynamically registered OAuth client only receives an authorization code (or refreshes a session) for a user who explicitly allowed that client at that redirect.

**Architecture:** `GetClient` marks DCR clients `RequireConsent` and re-applies the current redirect policy. `/-/oauth/authorize` checks a per-subject consent record (`dcr.ConsentStore`) and, when not covered, renders a built-in consent page whose form POSTs a sealed copy of the request to `/-/oauth/consent`; Allow records consent and 303s back to authorize, which mints the code. The refresh grant requires consent for DCR clients.

**Tech Stack:** Go 1.26, net/http, html/template, go-jose v4 (JWE dir+A256GCM), golang.org/x/net/idna + publicsuffix, internal cache (memory/valkey), testify.

**Spec:** `docs/superpowers/specs/2026-10-08-dcr-consent-design.md` (read it first; this plan argues from it).

## Global Constraints

- Repo: `/home/rotty/projects/kdex/workspace/kdex-host-manager`, branch `main`. **Never push.** Commit locally only; the user pushes with the release tag.
- Commit messages and test names stay neutral: describe behaviour ("require consent for dynamically registered clients"), never an attack recipe or a host name.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- TDD: every behaviour change starts with a failing test that you run and watch fail.
- After each task: `go build ./... && go vet ./internal/... ` and the touched packages' tests pass.
- Final gate: `make test` and `make lint` (golangci-lint) both clean.
- Use `rg`, not `grep`. Match surrounding comment density and style (comments explain *why*, cite issues).
- Consent bounds (verbatim from spec §6): at most 64 clients per subject (oldest `touched` evicted), 4 redirects per client, 32 scopes of at most 128 bytes; touch at most once per 24h; store calls use a 2s deadline.
- Redirect refusals (spec §8): userinfo, a fragment, an empty host (http/https), a non-ASCII host, more than 2 KiB.
- `client_name` display: Unicode Cc and Cf removed, capped at 64 characters.
- Sealed-request lifetime: 10 minutes. Seal purpose labels: `""` (authorization codes, legacy key `sha256(BlockKey)`), `"oidc-login-state"`, `"dcr-consent"`.

## Review Focus

- A DCR client whose stored record has **no** `redirect_uris` left after policy filtering must vanish everywhere (authorize, token, refresh), not 500. → Task 2 test `TestGetClientDeletesADCRClientWithNoAllowedRedirect`.
- The cookie session path (`AutoExtendSession`) redeems refresh tokens with `clientID == ""`; the new refresh consent check must not log every browser user out. → Task 10 test `TestRedeemRefreshToken_BrowserSessionNeedsNoConsent`.
- A consent-store outage during refresh must not destroy the session (the record must be restored): return `ErrServerError`, not a grant failure. → Task 10 test `TestRedeemRefreshToken_ConsentStoreErrorIsAServerError`.
- Allow → 303 → authorize must issue the code even when the original request had `prompt=consent` (no loop), and the 303 must not carry `consent`. → Task 9 test `TestConsentPost_AllowWithPromptConsentCompletes`.
- Existing tests that build `auth.Config{DCRStore: ...}` without the new consent store must still compile and behave (no nil deref): a nil `DCRConsent` means "never covered" at authorize and "no consent" at refresh. → Task 8 test `TestAuthorize_NilConsentStoreShowsThePage`.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/auth/dcr/redirects.go` (new) | Redirect policy: `FilterRedirectURIs`, scheme constants, defaults, dangerous schemes |
| `internal/auth/dcr/redirects_test.go` (new) | Policy tests (moved from host + new refusals) |
| `internal/auth/dcr/store.go` | add `Delete` |
| `internal/auth/dcr/consent.go` (new) | `ConsentStore`: per-subject record, `Covers`, `HasClient`, `Grant`, `Revoke` |
| `internal/auth/dcr/consent_test.go` (new) | Consent store tests |
| `internal/host/register.go` | use `dcr.FilterRedirectURIs`; drop local policy |
| `internal/auth/config.go` | `AuthClient.RequireConsent`; `Config.DCRConsent`; build it; default schemes from `dcr`; path constants |
| `internal/auth/exchange.go` | `GetClient`/`LookupClient` (RequireConsent, redirect re-check); auth code uses seal helpers; refresh consent check |
| `internal/auth/seal.go` (new) | `seal`/`open` (+JSON) keyed by purpose |
| `internal/auth/oidc_login.go` | use seal helpers |
| `internal/auth/context.go` | auth source in context |
| `internal/auth/middleware.go` | record auth source |
| `internal/auth/authorize_request.go` (new) | `parseAuthorizeRequest`, `supportedScopes`, `withoutPrompt` |
| `internal/auth/consent_page.go` (new) | `ConsentView`, `RenderBuiltinConsent`, redirect display, name sanitizing |
| `internal/auth/oauth2.go` | authorize consent gate; `authorizeLoginURL` via `withoutPrompt` |
| `internal/auth/oauth2_consent.go` (new) | `ConsentPost` handler, consent rendering glue |
| `internal/auth/oauth2_consent_test.go` (new) | authorize + POST + end-to-end tests, fixture |
| `internal/http/http.go` | `SameOrigin` |
| `internal/host/login.go` | `isSameOrigin` via `kdexhttp.SameOrigin`; `consentOriginAllowed` |
| `internal/host/handlers.go` | `hh.newOAuth2()`; register `POST /-/oauth/consent`; OpenAPI |

---

### Task 1: Redirect policy moves to `dcr` and gets stricter

**Files:**
- Create: `internal/auth/dcr/redirects.go`, `internal/auth/dcr/redirects_test.go`
- Modify: `internal/host/register.go` (delete `dangerousSchemes`, `schemeConfigLoopback`, `schemeConfigPrivateUse`, `redirectAllowed`; keep `schemeHTTP`/`schemeHTTPS`, which other host files use)
- Modify: `internal/auth/config.go:340-343` (default schemes)
- Test: move any `redirectAllowed` cases from `internal/host/register_test.go` into `redirects_test.go` (`rg -n "redirectAllowed" internal/host/*_test.go`)

**Interfaces:**
- Produces: `dcr.FilterRedirectURIs(uris, schemes []string) []string`; `dcr.DefaultRedirectSchemes []string`; `dcr.SchemeLoopback = "http-loopback"`; `dcr.SchemePrivateUse = "private-use"`.

- [ ] **Step 1: Write the failing tests**

```go
package dcr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterRedirectURIs_KeepsAllowedInOrderWithoutDuplicates(t *testing.T) {
	got := FilterRedirectURIs([]string{
		"https://app.example/cb",
		"http://127.0.0.1:3000/cb",
		"https://app.example/cb",
		"javascript://x",
	}, DefaultRedirectSchemes)
	assert.Equal(t, []string{"https://app.example/cb", "http://127.0.0.1:3000/cb"}, got)
}

func TestFilterRedirectURIs_RefusesAmbiguousURIs(t *testing.T) {
	for _, uri := range []string{
		"https://app.example@other.example/cb", // userinfo
		"https://app.example/cb#frag",           // fragment
		"https://app.example/cb#",               // empty fragment
		"https:///cb",                           // empty host
		"https://xn--clude-6ve.ai/cb#",          // fragment again (punycode host itself is fine)
		"https://clаude.ai/cb",             // non-ASCII host (Cyrillic a)
		"https://a‮b.example/cb",           // bidi override in host
		"https://app.example/" + strings.Repeat("a", 2100),
		"",
	} {
		assert.Empty(t, FilterRedirectURIs([]string{uri}, DefaultRedirectSchemes), uri)
	}
}

func TestFilterRedirectURIs_SchemePolicies(t *testing.T) {
	schemes := []string{"https", SchemeLoopback, SchemePrivateUse, "cursor"}
	for uri, want := range map[string]bool{
		"https://app.example/cb":          true,
		"http://localhost:8080/cb":        true,
		"http://app.example/cb":           false, // cleartext non-loopback
		"com.example.app:/oauth2redirect": true,  // private-use, no host
		"cursor://anysphere.cursor/cb":    true,  // explicit literal
		"vscode://x/cb":                   false, // not listed
		"data:text/html,x":                false,
	} {
		assert.Equal(t, want, len(FilterRedirectURIs([]string{uri}, schemes)) == 1, uri)
	}
	// a dangerous scheme is never honoured even when listed
	assert.Empty(t, FilterRedirectURIs([]string{"javascript:alert(1)"}, []string{"javascript"}))
	// a bare http literal is never honoured
	assert.Empty(t, FilterRedirectURIs([]string{"http://app.example/cb"}, []string{"http"}))
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/auth/dcr/ -run TestFilterRedirectURIs -v`
Expected: FAIL to compile, `undefined: FilterRedirectURIs`.

- [ ] **Step 3: Implement `internal/auth/dcr/redirects.go`**

```go
package dcr

import (
	"net/url"
	"slices"
	"strings"
)

// Named allowedRedirectSchemes policies. Every other entry is a literal URI
// scheme ("cursor" permits cursor://…).
const (
	SchemeLoopback   = "http-loopback" // http, loopback host only (RFC 8252 §7.3)
	SchemePrivateUse = "private-use"   // any dotted non-http(s) scheme (RFC 8252 §7.1)

	schemeHTTP        = "http"
	schemeHTTPS       = "https"
	maxRedirectURILen = 2048
)

// DefaultRedirectSchemes applies when a host configures none.
var DefaultRedirectSchemes = []string{schemeHTTPS, SchemeLoopback}

// dangerousSchemes are never honoured, even when listed: they are code
// execution / local file / data exfiltration vectors, not redirect targets.
var dangerousSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "blob": true,
}

// FilterRedirectURIs keeps the redirect URIs the policy admits, in order and
// without duplicates. It runs at registration AND whenever a stored client is
// read back, so tightening allowedRedirectSchemes takes effect on clients
// already registered. An empty result means no usable redirect: the caller
// refuses (registration) or treats the client as gone (read-back).
func FilterRedirectURIs(uris, schemes []string) []string {
	kept := make([]string, 0, len(uris))
	for _, u := range uris {
		if redirectAllowed(u, schemes) && !slices.Contains(kept, u) {
			kept = append(kept, u)
		}
	}
	return kept
}

// redirectAllowed reports whether one redirect URI is admitted. Beyond the
// scheme policy it refuses shapes a user cannot judge on a consent page:
// userinfo (https://trusted@other/), fragments (RFC 6749 §3.1.2 forbids them),
// an empty or non-ASCII host (homoglyphs, bidi overrides), and very long URIs.
func redirectAllowed(raw string, schemes []string) bool {
	if raw == "" || len(raw) > maxRedirectURILen || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return false
	}
	if host := u.Hostname(); host != "" && !isASCII(host) {
		return false
	}
	if (u.Scheme == schemeHTTP || u.Scheme == schemeHTTPS) && u.Hostname() == "" {
		return false
	}
	for _, s := range schemes {
		switch s {
		case SchemeLoopback:
			if u.Scheme == schemeHTTP {
				host := u.Hostname()
				if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
					return true
				}
			}
		case SchemePrivateUse:
			if u.Scheme != "" && u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS &&
				strings.Contains(u.Scheme, ".") {
				return true
			}
		default:
			// Literal: the entry IS the scheme. Never an empty scheme, a bare
			// "http" (cleartext non-loopback is an open redirect), or a
			// dangerous scheme, even if listed.
			if s == "" || s == schemeHTTP || dangerousSchemes[s] {
				continue
			}
			if u.Scheme == s {
				return true
			}
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Switch registration to it.** In `internal/host/register.go`, replace the `allowedRedirects` loop with:

```go
	allowedRedirects := dcr.FilterRedirectURIs(req.RedirectURIs, hh.authConfig.DCR.AllowedRedirectSchemes)
```

Delete `redirectAllowed`, `dangerousSchemes`, `schemeConfigLoopback`, `schemeConfigPrivateUse` from `register.go` (keep the long doc comment by moving its policy paragraph onto `redirectAllowed` in `dcr` — it is already reflected above). In `internal/auth/config.go` replace `schemes = []string{"https", "http-loopback"}` with `schemes = slices.Clone(dcr.DefaultRedirectSchemes)`. Move any host tests of `redirectAllowed` into `redirects_test.go` as `FilterRedirectURIs` cases.

- [ ] **Step 5: Run tests**

Run: `go test ./internal/auth/dcr/ ./internal/host/ -run 'Redirect|Register' -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/auth/dcr/redirects.go internal/auth/dcr/redirects_test.go internal/host/register.go internal/host/register_test.go internal/auth/config.go
git commit -m "refactor(dcr): one redirect policy, stricter about ambiguous URIs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `GetClient` marks DCR clients and re-applies the redirect policy

**Files:**
- Modify: `internal/auth/dcr/store.go` (add `Delete`)
- Modify: `internal/auth/config.go` (`AuthClient.RequireConsent bool`)
- Modify: `internal/auth/exchange.go` `GetClient` (~line 805)
- Test: `internal/auth/exchange_resource_test.go`

**Interfaces:**
- Consumes: `dcr.FilterRedirectURIs`, `dcr.DefaultRedirectSchemes` (Task 1).
- Produces: `AuthClient.RequireConsent bool`; `(*Exchanger).LookupClient(ctx context.Context, clientID string) (AuthClient, bool, error)`; `GetClient(clientID)` delegates to it; `(*dcr.Store).Delete(ctx, clientID string) error`.

- [ ] **Step 1: Write the failing tests** (append to `exchange_resource_test.go`; `registerStoredDCRClient` already exists there, extend it with a `redirects` variant)

```go
func registerStoredDCRClientWithRedirects(t *testing.T, ex *Exchanger, redirects []string) string {
	t.Helper()
	c, err := ex.config.DCRStore.Register(context.Background(), dcr.Client{
		RedirectURIs: redirects,
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	})
	require.NoError(t, err)
	return c.ClientID
}

func TestGetClientMarksDCRClientsAsRequiringConsent(t *testing.T) {
	ex, id := newTestExchangerWithDCR(t)
	c, ok := ex.GetClient(id)
	require.True(t, ok)
	assert.True(t, c.RequireConsent)

	ex.config.Clients["static"] = AuthClient{ClientID: "static"}
	s, ok := ex.GetClient("static")
	require.True(t, ok)
	assert.False(t, s.RequireConsent, "operator-configured clients never require consent")
}

func TestGetClientDropsRedirectsTheCurrentPolicyRefuses(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClientWithRedirects(t, ex, []string{"https://app.example/cb", "cursor://x/cb"})
	ex.config.DCR.AllowedRedirectSchemes = []string{"https"}

	c, ok := ex.GetClient(id)
	require.True(t, ok)
	assert.Equal(t, []string{"https://app.example/cb"}, c.RedirectURIs)
}

func TestGetClientDeletesADCRClientWithNoAllowedRedirect(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	id := registerStoredDCRClientWithRedirects(t, ex, []string{"cursor://x/cb"})
	ex.config.DCR.AllowedRedirectSchemes = []string{"https"}

	_, ok := ex.GetClient(id)
	assert.False(t, ok)

	// deleted, not merely hidden: re-allowing the scheme does not resurrect it
	ex.config.DCR.AllowedRedirectSchemes = []string{"https", "cursor"}
	_, ok = ex.GetClient(id)
	assert.False(t, ok)
}

func TestGetClientUsesDefaultSchemesWhenNoneConfigured(t *testing.T) {
	ex, id := newTestExchangerWithDCR(t) // registers https://example.com/cb, no DCR config
	_, ok := ex.GetClient(id)
	assert.True(t, ok)
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/auth/ -run 'TestGetClient' -v`
Expected: compile failure on `RequireConsent`, then (after adding the field) assertion failures.

- [ ] **Step 3: Implement**

`internal/auth/dcr/store.go`:

```go
// Delete removes a client record. Used when a stored client no longer has any
// redirect the current policy admits, so it cannot come back if the policy is
// relaxed again.
func (s *Store) Delete(ctx context.Context, clientID string) error {
	return s.cache.Delete(ctx, clientID)
}
```

`internal/auth/config.go`, in `AuthClient` (keep fields alphabetical as the struct is):

```go
	// RequireConsent is set only for dynamically registered clients: they are
	// registered anonymously, so a code is issued to them only after the
	// user allows the client at that redirect (/-/oauth/consent).
	RequireConsent    bool
```

`internal/auth/exchange.go`, replace `GetClient` with:

```go
func (e *Exchanger) GetClient(clientID string) (AuthClient, bool) {
	c, ok, _ := e.LookupClient(context.Background(), clientID)
	return c, ok
}

// LookupClient is GetClient that reports a store failure, for callers that
// must tell "no such client" from "cannot tell right now" (the consent POST
// answers 503 for the latter).
func (e *Exchanger) LookupClient(ctx context.Context, clientID string) (AuthClient, bool, error) {
	if e == nil {
		return AuthClient{}, false, nil
	}
	if c, ok := e.config.Clients[clientID]; ok {
		return c, true, nil
	}
	if e.config.DCRStore == nil {
		return AuthClient{}, false, nil
	}
	dc, ok, err := e.config.DCRStore.Get(ctx, clientID)
	if err != nil || !ok {
		return AuthClient{}, false, err
	}
	// Stored grants and redirects are not trusted: a record can predate the
	// current policy. Nothing usable left means no client at all, never an
	// empty (unrestricted) list. See GHSA-hm9g-w2cw-j7gg.
	grants := dcr.FilterGrantTypes(dc.GrantTypes)
	schemes := e.config.DCR.AllowedRedirectSchemes
	if len(schemes) == 0 {
		schemes = dcr.DefaultRedirectSchemes
	}
	redirects := dcr.FilterRedirectURIs(dc.RedirectURIs, schemes)
	if len(redirects) == 0 {
		// Delete rather than hide, so relaxing the policy later does not
		// resurrect the client together with its refresh tokens.
		if derr := e.config.DCRStore.Delete(ctx, clientID); derr != nil {
			logf.FromContext(ctx).Error(derr, "dcr: failed to delete a client with no allowed redirect", "clientID", clientID)
		}
		return AuthClient{}, false, nil
	}
	if len(grants) == 0 {
		return AuthClient{}, false, nil
	}
	return AuthClient{
		ClientID:          dc.ClientID,
		Public:            true,
		RequireConsent:    true,
		RequirePKCE:       true,
		RedirectURIs:      redirects,
		AllowedGrantTypes: grants,
		AllowedScopes:     strings.Fields(dc.Scope),
		Name:              dc.ClientName,
	}, true, nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/auth/... ./internal/host/ -v -run 'GetClient|DCR|Register|MCP'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/dcr/store.go internal/auth/config.go internal/auth/exchange.go internal/auth/exchange_resource_test.go
git commit -m "fix(dcr): re-apply the redirect policy to stored clients; mark them as requiring consent

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: One purpose-keyed JWE helper

**Files:**
- Create: `internal/auth/seal.go`, `internal/auth/seal_test.go`
- Modify: `internal/auth/oidc_login.go` (delete `loginStateKey`, `sealLoginState`/`openLoginState` bodies use the helper)
- Modify: `internal/auth/exchange.go` (auth-code seal ~line 1835, open ~line 1359-1385)

**Interfaces:**
- Produces: `(*Exchanger).seal(purpose string, payload []byte) (string, error)`; `(*Exchanger).open(purpose, sealed string) ([]byte, error)` returning `errSealParse` or `errSealDecrypt` (wrapped); `sealJSON(purpose, v any) (string, error)`; `openJSON(purpose, sealed string, v any) error`; constants `sealPurposeAuthCode = ""`, `sealPurposeLoginState = "oidc-login-state"`, `sealPurposeConsent = "dcr-consent"`.

- [ ] **Step 1: Failing tests** (`internal/auth/seal_test.go`)

```go
package auth

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealRoundTripsPerPurpose(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	s, err := ex.sealJSON(sealPurposeConsent, map[string]string{"a": "b"})
	require.NoError(t, err)

	var got map[string]string
	require.NoError(t, ex.openJSON(sealPurposeConsent, s, &got))
	assert.Equal(t, "b", got["a"])

	// a seal for one purpose does not open under another
	assert.ErrorIs(t, ex.openJSON(sealPurposeLoginState, s, &got), errSealDecrypt)
	assert.ErrorIs(t, ex.openJSON(sealPurposeConsent, "not-a-jwe", &got), errSealParse)
}

// Authorization codes keep the key they had before the helper existed, so
// codes minted just before the rollout still redeem after it.
func TestSealAuthCodeKeyIsUnchanged(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	legacy := sha256.Sum256([]byte(ex.config.OIDC.BlockKey))
	assert.Equal(t, legacy[:], ex.sealKey(sealPurposeAuthCode))
	assert.NotEqual(t, legacy[:], ex.sealKey(sealPurposeConsent))
	assert.False(t, errors.Is(nil, errSealParse))
}
```

- [ ] **Step 2: Run** `go test ./internal/auth/ -run TestSeal -v` → FAIL (undefined).

- [ ] **Step 3: Implement `internal/auth/seal.go`**

```go
package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Seal purposes. Each derives its own key from the OIDC block key, so a value
// sealed for one use can never be opened as another. Authorization codes keep
// the unlabelled legacy key so codes in flight survive the rollout.
const (
	sealPurposeAuthCode   = ""
	sealPurposeLoginState = "oidc-login-state"
	sealPurposeConsent    = "dcr-consent"
)

var (
	errSealParse   = errors.New("sealed value is malformed")
	errSealDecrypt = errors.New("sealed value does not open with this key")
)

func (e *Exchanger) sealKey(purpose string) []byte {
	var sum [32]byte
	if purpose == sealPurposeAuthCode {
		sum = sha256.Sum256([]byte(e.config.OIDC.BlockKey))
	} else {
		sum = sha256.Sum256([]byte(purpose + "\x00" + e.config.OIDC.BlockKey))
	}
	return sum[:]
}

// seal encrypts payload as a compact JWE (dir + A256GCM) under purpose's key.
func (e *Exchanger) seal(purpose string, payload []byte) (string, error) {
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: e.sealKey(purpose)}, nil)
	if err != nil {
		return "", err
	}
	obj, err := enc.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// open reverses seal. Its errors wrap errSealParse or errSealDecrypt and carry
// the library's cause only after the sentinel, so callers can choose what to
// show a client.
func (e *Exchanger) open(purpose, sealed string) ([]byte, error) {
	obj, err := jose.ParseEncrypted(sealed, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealParse, err)
	}
	payload, err := obj.Decrypt(e.sealKey(purpose))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealDecrypt, err)
	}
	return payload, nil
}

func (e *Exchanger) sealJSON(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return e.seal(purpose, payload)
}

func (e *Exchanger) openJSON(purpose, sealed string, v any) error {
	payload, err := e.open(purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}
```

- [ ] **Step 4: Migrate callers.**
  - `oidc_login.go`: delete `loginStateKey`; `sealLoginState` becomes `return e.sealJSON(sealPurposeLoginState, st)`; `openLoginState` becomes `var st loginState; err := e.openJSON(sealPurposeLoginState, sealed, &st); return st, err`. Remove now-unused imports (`crypto/sha256`, `encoding/json`, `go-jose`).
  - `exchange.go` auth-code mint (~1835): replace the key/encrypter/encrypt/serialize block with `return e.seal(sealPurposeAuthCode, payload)`.
  - `exchange.go` auth-code redeem (~1359-1385): replace parse+derive+decrypt with:

```go
	decrypted, err := e.open(sealPurposeAuthCode, code)
	if err != nil {
		// Only the fixed description goes on the wire; the cause goes to the
		// operator log (#168).
		if errors.Is(err, errSealParse) {
			logf.FromContext(ctx).V(1).Info("authorization code failed to parse", "cause", err.Error())
			return TokenSet{}, grantFailuref("failed to parse auth code")
		}
		logf.FromContext(ctx).V(1).Info("authorization code failed to decrypt", "cause", err.Error())
		return TokenSet{}, grantFailuref("failed to decrypt auth code")
	}
```
  Keep the two original explanatory comments above this block.

- [ ] **Step 5: Run** `go test ./internal/auth/... -v -run 'Seal|AuthorizationCode|OAuthGet|OAuthLogin|Redeem'` then `go test ./internal/auth/...` → PASS.

- [ ] **Step 6: Commit** `refactor(auth): one purpose-keyed JWE helper for codes, login state and consent`.

---

### Task 4: Same-origin check shared, with a strict variant for consent

**Files:**
- Modify: `internal/http/http.go` (add `SameOrigin`), test in `internal/http/http_test.go` (create if absent)
- Modify: `internal/host/login.go` (`isSameOrigin` uses it; add `consentOriginAllowed`)
- Test: `internal/host/login_csrf_test.go`

**Interfaces:**
- Produces: `kdexhttp.SameOrigin(raw, scheme string, domains []string) bool`; host func `consentOriginAllowed(r *http.Request, scheme string, domains []string) bool`.

- [ ] **Step 1: Failing tests**

`internal/http/http_test.go`:

```go
func TestSameOrigin(t *testing.T) {
	domains := []string{"app.example", "alt.example:8443"}
	for raw, want := range map[string]bool{
		"https://app.example":          true,
		"https://APP.example/path":     true,
		"https://app.example:443":      true,
		"https://alt.example:8443":     true,
		"https://alt.example":          false, // domain names a port
		"http://app.example":           false, // scheme
		"https://evil.example":         false,
		"null":                         false,
		"":                             false,
		"https://app.example.evil.com": false,
	} {
		assert.Equal(t, want, SameOrigin(raw, "https", domains), raw)
	}
}
```

`internal/host/login_csrf_test.go`:

```go
func TestConsentOriginAllowed(t *testing.T) {
	domains := []string{"app.example"}
	mk := func(h map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/-/oauth/consent", nil)
		for k, v := range h {
			r.Header.Set(k, v)
		}
		return r
	}
	assert.True(t, consentOriginAllowed(mk(map[string]string{"Origin": "https://app.example"}), "https", domains))
	assert.True(t, consentOriginAllowed(mk(map[string]string{"Referer": "https://app.example/-/oauth/authorize"}), "https", domains))
	assert.False(t, consentOriginAllowed(mk(nil), "https", domains), "no Origin and no Referer")
	assert.False(t, consentOriginAllowed(mk(map[string]string{"Origin": "null"}), "https", domains))
	assert.False(t, consentOriginAllowed(mk(map[string]string{"Origin": "https://evil.example"}), "https", domains))
	assert.False(t, consentOriginAllowed(mk(map[string]string{
		"Origin": "https://app.example", "Sec-Fetch-Site": "cross-site"}), "https", domains))
	assert.True(t, consentOriginAllowed(mk(map[string]string{
		"Origin": "https://app.example", "Sec-Fetch-Site": "same-origin"}), "https", domains))
}
```

- [ ] **Step 2: Run** `go test ./internal/http/ ./internal/host/ -run 'SameOrigin|ConsentOrigin' -v` → FAIL (undefined).

- [ ] **Step 3: Implement**

`internal/http/http.go`:

```go
// SameOrigin reports whether raw (an Origin value or a Referer URL) has the
// given scheme and names one of domains. A domain that carries a port must
// match it exactly; a domain without one matches the scheme's default port or
// no port. "null" and anything unparseable never match.
func SameOrigin(raw, scheme string, domains []string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	host, port := u.Hostname(), u.Port()
	defaultPort := (scheme == "https" && port == "443") || (scheme == "http" && port == "80")
	for _, d := range domains {
		if strings.EqualFold(u.Host, d) {
			return true
		}
		if (port == "" || defaultPort) && strings.EqualFold(host, d) {
			return true
		}
	}
	return false
}
```

`internal/host/login.go`: make `isSameOrigin` delegate (keep the nil-host guard):

```go
func (hh *HostHandler) isSameOrigin(raw string) bool {
	if hh.host == nil {
		return false
	}
	return kdexhttp.SameOrigin(raw, hh.scheme, hh.host.Routing.Domains)
}

// consentOriginAllowed is originAllowed without the leniency: the consent POST
// releases an authorization code, so a request that does not PROVE it came
// from this host's own page is refused. Browsers send Origin on every form
// POST; "null" (an opaque or no-referrer origin) is not proof.
func consentOriginAllowed(r *http.Request, scheme string, domains []string) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return kdexhttp.SameOrigin(o, scheme, domains)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return kdexhttp.SameOrigin(ref, scheme, domains)
	}
	return false
}
```

- [ ] **Step 4: Run** `go test ./internal/http/ ./internal/host/ -v -run 'Origin|Login'` → PASS.

- [ ] **Step 5: Commit** `refactor(http): shared same-origin check; strict variant for consent`.

---

### Task 5: The auth context records where the credential came from

**Files:**
- Modify: `internal/auth/context.go`, `internal/auth/middleware.go:~530`
- Test: `internal/auth/middleware_test.go` (or a new `auth_source_test.go`)

**Interfaces:**
- Produces: `func AuthSourceFromContext(ctx context.Context) string`; `func withAuthSource(ctx context.Context, source string) context.Context`; values are the existing `COOKIE` constant and `"header"`.

- [ ] **Step 1: Failing test** (`internal/auth/auth_source_test.go`). `newOIDCFixture` (oidc_refresh_test.go) builds a full middleware config through `ConfigBuilder`; a real session token comes from the same exchange the OIDC callback runs:

```go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationRecordsTheCredentialSource(t *testing.T) {
	f := newOIDCFixture(t)
	oidcTokens, err := f.ex.ExchangeCode(f.ctx, "alice")
	require.NoError(t, err)
	ts, err := f.ex.ExchangeToken(f.ctx, oidcTokens)
	require.NoError(t, err)

	var got string
	h := f.cfg.AddAuthentication(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = AuthSourceFromContext(r.Context())
	}), f.ex)

	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: f.cfg.CookieName, Value: ts.AccessToken})
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, COOKIE, got)

	got = ""
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+ts.AccessToken)
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "header", got)
}
```

- [ ] **Step 2: Run** → FAIL (undefined `AuthSourceFromContext`).

- [ ] **Step 3: Implement** in `context.go`:

```go
type authSourceKeyType struct{}

var authSourceKey authSourceKeyType

// withAuthSource records where the request's credential came from: COOKIE
// for the browser session cookie, "header" for an Authorization bearer token.
// Codes for dynamically registered clients are only issued to a browser
// session, so the authorization endpoint needs to know which it has.
func withAuthSource(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, authSourceKey, source)
}

// AuthSourceFromContext reports the credential source recorded by the
// authentication middleware, or "" when none was.
func AuthSourceFromContext(ctx context.Context) string {
	s, _ := ctx.Value(authSourceKey).(string)
	return s
}
```

In `middleware.go` at the injection point (`ctx := SetAuthContext(r.Context(), authContext)`):

```go
			ctx := withAuthSource(SetAuthContext(r.Context(), authContext), authSource)
```

- [ ] **Step 4: Run** `go test ./internal/auth/ -v -run 'Source|Authentication'` → PASS; then `go test ./internal/auth/...`.

- [ ] **Step 5: Commit** `feat(auth): record the credential source in the auth context`.

---

### Task 6: `dcr.ConsentStore`

**Files:**
- Create: `internal/auth/dcr/consent.go`, `internal/auth/dcr/consent_test.go`
- Modify: `internal/auth/config.go` (`Config.DCRConsent *dcr.ConsentStore`; build it in `buildDCRStore`'s sibling)

**Interfaces:**
- Produces:
  - `dcr.NewConsentStore(cm cache.CacheManager, ttl time.Duration, maxItems int) *ConsentStore`
  - `(*ConsentStore).Covers(ctx, subject, clientID, redirectURI string, scopes []string) (bool, error)` (touches if stale)
  - `(*ConsentStore).HasClient(ctx, subject, clientID string) (bool, error)` (touches if stale)
  - `(*ConsentStore).Grant(ctx, subject, clientID, redirectURI string, scopes []string) error`
  - `(*ConsentStore).Revoke(ctx, subject, clientID, redirectURI string) error`
  - constants `MaxConsentClients = 64`, `MaxConsentRedirects = 4`, `MaxConsentScopes = 32`, `MaxConsentScopeLen = 128`
  - `Config.DCRConsent *dcr.ConsentStore`

- [ ] **Step 1: Failing tests** (`consent_test.go`)

```go
package dcr

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConsentStore(t *testing.T) *ConsentStore {
	t.Helper()
	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "consent-test", &ttl)
	require.NoError(t, err)
	return NewConsentStore(cm, ttl, 10000)
}

func TestConsentCoversOnlyTheRedirectAndScopesAllowed(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"openid", "email"}))

	ok, err := s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"email"})
	require.NoError(t, err)
	assert.True(t, ok, "subset of granted scopes")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	assert.True(t, ok, "empty request is covered by any record for the redirect")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"roles"})
	assert.False(t, ok, "broader scope")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://b.example/cb", nil)
	assert.False(t, ok, "another redirect of the same client")

	ok, _ = s.Covers(ctx, "bob", "c1", "https://a.example/cb", nil)
	assert.False(t, ok, "another subject")
}

func TestConsentGrantUnionsAndRevokeRemoves(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"openid"}))
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"email"}))
	ok, _ := s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"openid", "email"})
	assert.True(t, ok)

	has, err := s.HasClient(ctx, "alice", "c1")
	require.NoError(t, err)
	assert.True(t, has)

	require.NoError(t, s.Revoke(ctx, "alice", "c1", "https://a.example/cb"))
	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	assert.False(t, ok)
	has, _ = s.HasClient(ctx, "alice", "c1")
	assert.False(t, has)
}

func TestConsentRecordIsBounded(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }

	for i := 0; i < MaxConsentClients+5; i++ {
		now = now.Add(time.Minute)
		require.NoError(t, s.Grant(ctx, "alice", fmt.Sprintf("c%03d", i), "https://a.example/cb", nil))
	}
	ok, _ := s.Covers(ctx, "alice", "c000", "https://a.example/cb", nil)
	assert.False(t, ok, "the oldest client was evicted")
	ok, _ = s.Covers(ctx, "alice", fmt.Sprintf("c%03d", MaxConsentClients+4), "https://a.example/cb", nil)
	assert.True(t, ok)

	for i := 0; i < MaxConsentRedirects+2; i++ {
		now = now.Add(time.Minute)
		require.NoError(t, s.Grant(ctx, "bob", "c1", fmt.Sprintf("https://r%d.example/cb", i), nil))
	}
	ok, _ = s.Covers(ctx, "bob", "c1", "https://r0.example/cb", nil)
	assert.False(t, ok, "the oldest redirect was evicted")

	long := make([]string, 0, MaxConsentScopes+10)
	for i := 0; i < MaxConsentScopes+10; i++ {
		long = append(long, fmt.Sprintf("s%d", i))
	}
	require.NoError(t, s.Grant(ctx, "carol", "c1", "https://a.example/cb", long))
	rec, err := s.load(ctx, "carol")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(rec.Clients["c1"]["https://a.example/cb"].Scopes), MaxConsentScopes)
}

func TestConsentTouchWritesAtMostDaily(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", nil))

	now = now.Add(time.Hour)
	_, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	rec, _ := s.load(ctx, "alice")
	assert.Equal(t, time.Unix(1_000_000, 0).Unix(), rec.Clients["c1"]["https://a.example/cb"].Touched, "not stale yet")

	now = now.Add(25 * time.Hour)
	_, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	rec, _ = s.load(ctx, "alice")
	assert.Equal(t, now.Unix(), rec.Clients["c1"]["https://a.example/cb"].Touched)
}
```

- [ ] **Step 2: Run** `go test ./internal/auth/dcr/ -run TestConsent -v` → FAIL (undefined).

- [ ] **Step 3: Implement `consent.go`**

```go
package dcr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

// Bounds on one subject's consent record (spec 2026-10-08 §6). Without them an
// authenticated user could grow a single cache value without limit.
const (
	MaxConsentClients   = 64
	MaxConsentRedirects = 4
	MaxConsentScopes    = 32
	MaxConsentScopeLen  = 128

	consentTouchEvery = 24 * time.Hour
	consentTimeout    = 2 * time.Second
)

type consentGrant struct {
	Scopes  []string `json:"s,omitempty"`
	Touched int64    `json:"t"`
}

// consentRecord is ONE subject's consents: client_id -> redirect_uri -> grant.
// One key per subject lets a future "list and revoke your consents" read it
// without a cache scan, which cache.Cache does not offer.
type consentRecord struct {
	Clients map[string]map[string]consentGrant `json:"c"`
}

// ConsentStore remembers which dynamically registered clients a user allowed,
// at which redirect, for which scopes. Uncycled (it must survive a reconcile,
// like the client store, #122), with the client TTL, sliding with use.
//
// Concurrent updates to one subject's record are last-writer-wins. A lost
// update only means the user is asked again, so no locking.
type ConsentStore struct {
	cache cache.Cache
	ttl   time.Duration
	now   func() time.Time
}

// NewConsentStore builds the store. maxItems bounds the in-memory backend
// (one item per subject); valkey ignores it. In-memory mode is for dev only.
func NewConsentStore(cm cache.CacheManager, ttl time.Duration, maxItems int) *ConsentStore {
	return &ConsentStore{
		cache: cm.GetCache("dcr-consent", cache.CacheOptions{TTL: &ttl, Uncycled: true, MaxItems: &maxItems}),
		ttl:   ttl,
		now:   time.Now,
	}
}

func consentKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

func (s *ConsentStore) load(ctx context.Context, subject string) (consentRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, consentTimeout)
	defer cancel()
	rec := consentRecord{Clients: map[string]map[string]consentGrant{}}
	val, ok, _, err := s.cache.Get(ctx, consentKey(subject))
	if err != nil || !ok {
		return rec, err
	}
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		// An unreadable record is treated as no consent: the user is asked again.
		return consentRecord{Clients: map[string]map[string]consentGrant{}}, nil
	}
	if rec.Clients == nil {
		rec.Clients = map[string]map[string]consentGrant{}
	}
	return rec, nil
}

func (s *ConsentStore) save(ctx context.Context, subject string, rec consentRecord) error {
	ctx, cancel := context.WithTimeout(ctx, consentTimeout)
	defer cancel()
	if len(rec.Clients) == 0 {
		return s.cache.Delete(ctx, consentKey(subject))
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, consentKey(subject), string(b), cache.WithTTL(s.ttl))
}

// Covers reports whether subject allowed clientID at redirectURI for every
// scope in scopes (an empty scopes is covered by any grant for the redirect).
// A stale grant (untouched for a day) is touched, so consent lives as long as
// the client is in use.
func (s *ConsentStore) Covers(ctx context.Context, subject, clientID, redirectURI string, scopes []string) (bool, error) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return false, err
	}
	g, ok := rec.Clients[clientID][redirectURI]
	if !ok {
		return false, nil
	}
	for _, sc := range scopes {
		if !slices.Contains(g.Scopes, sc) {
			return false, nil
		}
	}
	s.touch(ctx, subject, rec, clientID, redirectURI)
	return true, nil
}

// HasClient reports whether subject holds any consent for clientID. The
// refresh grant uses it: a session cannot outlive its consent.
func (s *ConsentStore) HasClient(ctx context.Context, subject, clientID string) (bool, error) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return false, err
	}
	for redirect := range rec.Clients[clientID] {
		s.touch(ctx, subject, rec, clientID, redirect)
		return true, nil
	}
	return false, nil
}

func (s *ConsentStore) touch(ctx context.Context, subject string, rec consentRecord, clientID, redirectURI string) {
	g := rec.Clients[clientID][redirectURI]
	now := s.now()
	if now.Sub(time.Unix(g.Touched, 0)) < consentTouchEvery {
		return
	}
	g.Touched = now.Unix()
	rec.Clients[clientID][redirectURI] = g
	_ = s.save(ctx, subject, rec) // best effort: a failed touch only shortens the consent
}

// Grant records that subject allowed clientID at redirectURI for scopes,
// adding to what was allowed before, within the record's bounds.
func (s *ConsentStore) Grant(ctx context.Context, subject, clientID, redirectURI string, scopes []string) error {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	redirects := rec.Clients[clientID]
	if redirects == nil {
		redirects = map[string]consentGrant{}
	}
	g := redirects[redirectURI]
	merged := slices.Clone(g.Scopes)
	for _, sc := range scopes {
		if len(sc) <= MaxConsentScopeLen && !slices.Contains(merged, sc) {
			merged = append(merged, sc)
		}
	}
	if len(merged) > MaxConsentScopes {
		// Past the cap, keep only what was just allowed (itself capped).
		merged = merged[len(merged)-MaxConsentScopes:]
	}
	slices.Sort(merged)
	redirects[redirectURI] = consentGrant{Scopes: merged, Touched: now}
	evictOldest(redirects, MaxConsentRedirects, func(g consentGrant) int64 { return g.Touched })
	rec.Clients[clientID] = redirects
	evictOldest(rec.Clients, MaxConsentClients, func(r map[string]consentGrant) int64 {
		var newest int64
		for _, g := range r {
			newest = max(newest, g.Touched)
		}
		return newest
	})
	return s.save(ctx, subject, rec)
}

// Revoke removes subject's consent for clientID at redirectURI.
func (s *ConsentStore) Revoke(ctx context.Context, subject, clientID, redirectURI string) error {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return err
	}
	delete(rec.Clients[clientID], redirectURI)
	if len(rec.Clients[clientID]) == 0 {
		delete(rec.Clients, clientID)
	}
	return s.save(ctx, subject, rec)
}

func evictOldest[V any](m map[string]V, limit int, touched func(V) int64) {
	for len(m) > limit {
		var oldestKey string
		oldest := int64(1<<63 - 1)
		for k, v := range m {
			if t := touched(v); t < oldest || (t == oldest && k < oldestKey) {
				oldest, oldestKey = t, k
			}
		}
		delete(m, oldestKey)
	}
}
```

In `internal/auth/config.go` add to `Config` after `DCRStore`:

```go
	// DCRConsent remembers which dynamically registered clients each user
	// allowed. nil when DCR is off; callers treat nil as "never consented".
	DCRConsent *dcr.ConsentStore
```

and next to `cfg.DCRStore = cb.buildDCRStore(cfg.DCR)`:

```go
		if cfg.DCRStore != nil {
			// One record per subject; sized for many users on the in-memory
			// (dev) backend. valkey ignores the bound.
			cfg.DCRConsent = dcr.NewConsentStore(cb.CacheManager, cfg.DCR.ClientTTL, 100_000)
		}
```

- [ ] **Step 4: Run** `go test ./internal/auth/dcr/ ./internal/auth/ -v -run 'Consent|Config'` → PASS.

- [ ] **Step 5: Commit** `feat(dcr): a bounded per-subject consent store`.

---

### Task 7: Authorize-request helpers and `prompt` rewriting

**Files:**
- Create: `internal/auth/authorize_request.go`, `internal/auth/authorize_request_test.go`
- Modify: `internal/auth/oauth2.go` (`authorizeLoginURL` uses `withoutPrompt`; it now keeps `consent`)

**Interfaces:**
- Produces:
  - `type authorizeRequest struct { ClientID, RedirectURI, State, LoginHint string; Prompt, Scopes []string }`
  - `parseAuthorizeRequest(q url.Values) authorizeRequest` (Scopes = supported scopes only, sorted, unique)
  - `supportedScopes(scope string) []string`
  - `withoutPrompt(q url.Values, drop ...string) url.Values` (returns a copy)

- [ ] **Step 1: Failing tests**

```go
package auth

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSupportedScopesDropsUnknownAndDuplicates(t *testing.T) {
	assert.Equal(t, []string{"email", "openid"}, supportedScopes("openid read-only email openid"))
	assert.Empty(t, supportedScopes(""))
}

func TestWithoutPromptRemovesOnlyTheNamedValues(t *testing.T) {
	q := url.Values{"prompt": {"login consent"}, "state": {"x"}}
	got := withoutPrompt(q, "login", "select_account", "none")
	assert.Equal(t, "consent", got.Get("prompt"))
	assert.Equal(t, "login consent", q.Get("prompt"), "the input is not modified")

	got = withoutPrompt(url.Values{"prompt": {"consent"}}, "consent")
	assert.False(t, got.Has("prompt"), "an emptied prompt is removed entirely")
}

func TestAuthorizeLoginURLKeepsConsent(t *testing.T) {
	r := httptest.NewRequest("GET", "/-/oauth/authorize?prompt=login+consent&login_hint=a%40b.c&state=x", nil)
	loc, _ := url.Parse(authorizeLoginURL(r, []string{"login", "consent"}, "a@b.c"))
	ret, _ := url.Parse(loc.Query().Get("return"))
	assert.Equal(t, "consent", ret.Query().Get("prompt"), "consent survives the login detour")
	assert.Empty(t, ret.Query().Get("login_hint"))
	assert.Equal(t, "login", loc.Query().Get("prompt"), "only login/select_account go on to the provider")
}
```

(add `"net/http/httptest"` to the imports.)

- [ ] **Step 2: Run** `go test ./internal/auth/ -run 'SupportedScopes|WithoutPrompt|AuthorizeLoginURL' -v` → FAIL.

- [ ] **Step 3: Implement `authorize_request.go`**

```go
package auth

import (
	"net/url"
	"slices"
	"strings"
)

// authorizeRequest is the part of an /-/oauth/authorize request the consent
// step reasons about. Authorize and the consent POST both derive it from the
// query with parseAuthorizeRequest, so they cannot disagree about what was
// asked for.
type authorizeRequest struct {
	ClientID    string
	RedirectURI string
	State       string
	LoginHint   string
	Prompt      []string
	// Scopes are the requested scopes this host supports (what
	// applyScopeFilter would issue), sorted and unique. Anything else is
	// neither shown nor recorded.
	Scopes []string
}

func parseAuthorizeRequest(q url.Values) authorizeRequest {
	return authorizeRequest{
		ClientID:    q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"),
		State:       q.Get("state"),
		LoginHint:   q.Get("login_hint"),
		Prompt:      strings.Fields(q.Get("prompt")),
		Scopes:      supportedScopes(q.Get("scope")),
	}
}

func supportedScopes(scope string) []string {
	var out []string
	for s := range strings.FieldsSeq(scope) {
		if slices.Contains(SupportedScopes, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// withoutPrompt returns a copy of q with the given prompt values removed, and
// prompt itself removed when nothing is left. The login detour drops
// login/select_account/none (they are satisfied by logging in) and keeps
// consent; the Allow redirect drops consent (it is satisfied by allowing).
// Either way the request cannot loop back into the step it just finished.
func withoutPrompt(q url.Values, drop ...string) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = slices.Clone(v)
	}
	kept := slices.DeleteFunc(strings.Fields(q.Get("prompt")), func(p string) bool {
		return slices.Contains(drop, p)
	})
	if len(kept) == 0 {
		out.Del("prompt")
	} else {
		out.Set("prompt", strings.Join(kept, " "))
	}
	return out
}
```

Replace `authorizeLoginURL` in `oauth2.go`:

```go
func authorizeLoginURL(r *http.Request, prompt []string, loginHint string) string {
	ret := *r.URL
	q := withoutPrompt(r.URL.Query(), "login", "select_account", "none")
	q.Del("login_hint")
	ret.RawQuery = q.Encode()

	v := url.Values{"return": {ret.String()}}
	// Only what the provider can act on goes upstream; consent is ours.
	if upstream := slices.DeleteFunc(slices.Clone(prompt), func(p string) bool {
		return p != "login" && p != "select_account"
	}); len(upstream) > 0 {
		v.Set("prompt", strings.Join(upstream, " "))
	}
	if loginHint != "" {
		v.Set("login_hint", loginHint)
	}
	return "/-/login?" + v.Encode()
}
```

Update its doc comment: consent is kept so a `prompt=login consent` request still shows the consent page after login.

- [ ] **Step 4: Run** `go test ./internal/auth/ -v -run 'Authorize|Prompt|Scopes'` → PASS (the ddba71e `TestAuthorize_*` tests still pass).

- [ ] **Step 5: Commit** `feat(auth): shared authorize-request parsing and prompt rewriting`.

---

### Task 8: The built-in consent page

**Files:**
- Create: `internal/auth/consent_page.go`, `internal/auth/consent_page_test.go`
- Modify: `go.mod` (`golang.org/x/net` becomes direct: run `go mod tidy`)

**Interfaces:**
- Produces:
  - `type ConsentView struct { RedirectKind, RedirectDisplay, RegistrableDomain, RedirectURI, ClientName, Account, Request, Action string; Scopes []string }`
  - `func RenderBuiltinConsent(w http.ResponseWriter, r *http.Request, v ConsentView)`
  - `func newConsentView(clientName, redirectURI, account, sealed string, scopes []string) ConsentView`
  - `func sanitizeClientName(s string) string`; `func describeRedirect(raw string) (kind, display, registrable string)`

- [ ] **Step 1: Failing tests**

```go
package auth

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDescribeRedirect(t *testing.T) {
	kind, display, reg := describeRedirect("https://auth.claude.ai:8443/api/cb")
	assert.Equal(t, "web", kind)
	assert.Equal(t, "auth.claude.ai:8443", display)
	assert.Equal(t, "claude.ai", reg)

	kind, display, _ = describeRedirect("http://127.0.0.1:5000/cb")
	assert.Equal(t, "device", kind)
	assert.Equal(t, "http", display)

	kind, display, _ = describeRedirect("cursor://anysphere.cursor/cb")
	assert.Equal(t, "device", kind)
	assert.Equal(t, "cursor", display)

	_, display, reg = describeRedirect("https://xn--clude-6ve.ai/cb")
	assert.Equal(t, "xn--clude-6ve.ai", display, "shown in ASCII, never decoded to look-alike Unicode")
	assert.Equal(t, "xn--clude-6ve.ai", reg)
}

func TestSanitizeClientName(t *testing.T) {
	assert.Equal(t, "Claude", sanitizeClientName("Cl‮aude\u0000"))
	assert.Equal(t, 64, len([]rune(sanitizeClientName(strings.Repeat("é", 100)))))
}

func TestRenderBuiltinConsentEscapesAndAddsItsCSP(t *testing.T) {
	w := httptest.NewRecorder()
	v := newConsentView(`<script>alert(1)</script>`, "https://app.example/cb", "alice@example.com", "SEALED", []string{"email"})
	RenderBuiltinConsent(w, httptest.NewRequest("GET", "/-/oauth/authorize", nil), v)

	body := w.Body.String()
	assert.NotContains(t, body, "<script>alert(1)</script>")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Contains(t, body, "app.example")
	assert.Contains(t, body, `name="request" value="SEALED"`)
	assert.Contains(t, body, `action="/-/oauth/consent"`)
	// Deny comes first and is the default; Allow is armed by CSS after a second.
	assert.Less(t, strings.Index(body, `value="deny"`), strings.Index(body, `value="allow"`))
	assert.Contains(t, w.Header().Values("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	assert.NotContains(t, strings.Join(w.Header().Values("Content-Security-Policy"), ";"), "form-action")
}
```

- [ ] **Step 2: Run** `go test ./internal/auth/ -run 'DescribeRedirect|SanitizeClientName|RenderBuiltinConsent' -v` → FAIL.

- [ ] **Step 3: Implement `consent_page.go`**

```go
package auth

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// ConsentView is the data a consent page renders. Its field names are the
// template contract for the stage-2 Consent utility page, so do not rename
// them casually. It carries data, not copy: an empty Scopes means minimal
// access, and the renderer words that.
type ConsentView struct {
	// RedirectKind is "web" (an https redirect: the code leaves this device)
	// or "device" (loopback or a private-use scheme: an app on this device).
	RedirectKind string
	// RedirectDisplay is the ASCII host[:port] for "web", the scheme for "device".
	RedirectDisplay   string
	RegistrableDomain string
	RedirectURI       string
	ClientName        string
	Account           string
	Scopes            []string
	Request           string
	Action            string
}

const maxClientNameRunes = 64

func newConsentView(clientName, redirectURI, account, sealed string, scopes []string) ConsentView {
	kind, display, registrable := describeRedirect(redirectURI)
	return ConsentView{
		RedirectKind:      kind,
		RedirectDisplay:   display,
		RegistrableDomain: registrable,
		RedirectURI:       redirectURI,
		ClientName:        sanitizeClientName(clientName),
		Account:           account,
		Scopes:            scopes,
		Request:           sealed,
		Action:            OAuthConsentPath,
	}
}

// describeRedirect says where a code will go, in a form a person can judge.
// The host is shown exactly as registered: redirects with non-ASCII hosts are
// refused at registration (dcr.FilterRedirectURIs), and a punycode host is
// never decoded, so a look-alike shows as the xn-- form it really is.
func describeRedirect(raw string) (kind, display, registrable string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "web", raw, raw
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme != "https" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "device", u.Scheme, ""
	}
	display = u.Host
	registrable, err = publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		registrable = host
	}
	return "web", strings.ToLower(display), registrable
}

// sanitizeClientName removes control and format characters (including bidi
// overrides) from the self-declared client name and caps its length.
func sanitizeClientName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxClientNameRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// builtinConsentCSP is added to the flow's own frame-ancestors policy. No
// form-action: browsers apply it to the redirects after the POST, and those
// leave this origin by design. No script anywhere on this page.
const builtinConsentCSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"

var builtinConsentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Allow access?</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}
.where{font-size:1.4rem;font-weight:600;word-break:break-all}
.small{color:#555;font-size:.85rem;word-break:break-all}
form{display:flex;gap:1rem;margin-top:2rem}
button{font-size:1rem;padding:.6rem 1.4rem;border-radius:.4rem;border:1px solid #888;background:#fff}
.allow{background:#1a56db;color:#fff;border-color:#1a56db;animation:arm 1s steps(1,end)}
@keyframes arm{from{pointer-events:none;opacity:.5}to{pointer-events:auto;opacity:1}}
</style></head><body>
<h1>Allow access to your account?</h1>
<p>Signed in as <strong>{{.Account}}</strong>.</p>
{{if eq .RedirectKind "web"}}
<p>Allowing sends access to:</p>
<p class="where">{{.RedirectDisplay}}</p>
{{if .RegistrableDomain}}<p>Website: <strong>{{.RegistrableDomain}}</strong></p>{{end}}
{{else}}
<p>Allowing sends access to <strong>an application on this device</strong> ({{.RedirectDisplay}}).</p>
{{end}}
<p class="small">Full address: {{.RedirectURI}}</p>
{{if .ClientName}}<p>The application calls itself <strong>{{.ClientName}}</strong>. This name is provided by the application and has not been verified.</p>{{end}}
<p>It will be able to act on your account with your permissions{{if .Scopes}} and read: {{range $i, $s := .Scopes}}{{if $i}}, {{end}}{{$s}}{{end}}{{end}}.</p>
<p>Only allow this if you started connecting this application yourself.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="request" value="{{.Request}}">
<button type="submit" name="decision" value="deny" autofocus>Deny</button>
<button type="submit" name="decision" value="allow" class="allow">Allow</button>
</form>
</body></html>`))

// RenderBuiltinConsent is the consent page used when the host supplies none
// (stage 2 falls back to it). The flow has already set the no-store, framing
// and referrer headers.
func RenderBuiltinConsent(w http.ResponseWriter, _ *http.Request, v ConsentView) {
	w.Header().Add("Content-Security-Policy", builtinConsentCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = builtinConsentTemplate.Execute(w, v)
}
```

Add path constants to `internal/auth/config.go` next to `OAuthCallbackPath`:

```go
// OAuthAuthorizePath and OAuthConsentPath are served by internal/host and
// referenced from internal/auth (the consent redirect, the consent form).
const (
	OAuthAuthorizePath = "/-/oauth/authorize"
	OAuthConsentPath   = "/-/oauth/consent"
)
```

Run `go mod tidy` (x/net moves from indirect to direct).

- [ ] **Step 4: Run** `go test ./internal/auth/ -v -run 'DescribeRedirect|SanitizeClientName|RenderBuiltinConsent'` → PASS.

- [ ] **Step 5: Commit** `feat(auth): built-in consent page`.

---

### Task 9: Authorize requires consent; the consent POST

**Files:**
- Create: `internal/auth/oauth2_consent.go`, `internal/auth/oauth2_consent_test.go`
- Modify: `internal/auth/oauth2.go` (`OAuth2` fields; `AuthorizeHandler` gate)

**Interfaces:**
- Consumes: Tasks 2 (`RequireConsent`, `LookupClient`), 3 (`sealJSON`/`openJSON`, `sealPurposeConsent`), 5 (`AuthSourceFromContext`, `COOKIE`), 6 (`Config.DCRConsent`), 7 (`parseAuthorizeRequest`, `withoutPrompt`), 8 (`newConsentView`, `RenderBuiltinConsent`, path constants).
- Produces: `OAuth2.RenderConsent func(http.ResponseWriter, *http.Request, ConsentView)`; `OAuth2.ConsentOriginAllowed func(*http.Request) bool`; `(*OAuth2).ConsentPost(w, r)`; `type consentRequest struct { Sub, Iss, Query string; Exp int64 }`.

- [ ] **Step 1: Write the fixture and failing tests** (`oauth2_consent_test.go`)

```go
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	consentIssuer = "https://host.example"
	appRedirect   = "https://app.example/cb"
	otherRedirect = "https://other.example/cb"
)

type consentFixture struct {
	o        *OAuth2
	ex       *Exchanger
	clientID string
	verifier string
}

func newConsentFixture(t *testing.T) *consentFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, consentIssuer, &cs, "kid", nil)
	require.NoError(t, err)

	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "consent-flow-test", &ttl)
	require.NoError(t, err)
	store := dcr.NewStore(cm, consentIssuer, ttl, 100)
	consent := dcr.NewConsentStore(cm, ttl, 1000)

	cfg := Config{
		Issuer:     consentIssuer,
		Audience:   "test-aud",
		CookieName: "kdex-auth",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "kid", Private: cs},
		Clients:    map[string]AuthClient{},
		DCR:        DCRConfig{Enabled: true, ClientTTL: ttl, AllowedRedirectSchemes: []string{"https"}},
		DCRStore:   store,
		DCRConsent: consent,
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"
	ex, err := NewExchanger(context.Background(), cfg, cm, resourceStubIdentityProvider{}, nil)
	require.NoError(t, err)

	c, err := store.Register(context.Background(), dcr.Client{
		RedirectURIs: []string{appRedirect, otherRedirect},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		ClientName:   "Example App",
	})
	require.NoError(t, err)

	o := &OAuth2{
		AuthConfig:    &ex.config,
		AuthExchanger: ex,
		ConsentOriginAllowed: func(r *http.Request) bool {
			return r.Header.Get("Origin") == consentIssuer
		},
	}
	return &consentFixture{o: o, ex: ex, clientID: c.ClientID, verifier: "v-0123456789-0123456789-0123456789-0123"}
}

func (f *consentFixture) query(redirect string, extra url.Values) url.Values {
	sum := sha256.Sum256([]byte(f.verifier))
	q := url.Values{
		"client_id":             {f.clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"state":                 {"st"},
		"scope":                 {"openid email"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

var aliceSession = jwt.MapClaims{"sub": "alice", "email": "alice@example.com"}

func sessionRequest(method, target string, body *strings.Reader, session jwt.MapClaims, source string) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if session != nil {
		r = r.WithContext(withAuthSource(SetAuthContext(r.Context(), AuthContext(session)), source))
	}
	return r
}

func (f *consentFixture) authorize(q url.Values, session jwt.MapClaims, source string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.o.AuthorizeHandler(w, sessionRequest("GET", OAuthAuthorizePath+"?"+q.Encode(), nil, session, source))
	return w
}

var sealedRe = regexp.MustCompile(`name="request" value="([^"]+)"`)

func sealedFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	m := sealedRe.FindStringSubmatch(w.Body.String())
	require.Len(t, m, 2, "the consent page carries a sealed request")
	return m[1]
}

func (f *consentFixture) post(sealed, decision string, headers map[string]string, session jwt.MapClaims, source string) *httptest.ResponseRecorder {
	form := url.Values{"request": {sealed}, "decision": {decision}}
	r := sessionRequest("POST", OAuthConsentPath, strings.NewReader(form.Encode()), session, source)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.o.ConsentPost(w, r)
	return w
}

var sameOrigin = map[string]string{"Origin": consentIssuer}

func codeFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := w.Result().Location()
	require.NoError(t, err)
	return loc.Query().Get("code")
}

// allow drives page -> POST allow -> follow the 303 back to authorize.
func (f *consentFixture) allow(t *testing.T, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	sealed := sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
	w := f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, OAuthAuthorizePath, loc.Path)
	return f.authorize(loc.Query(), aliceSession, COOKIE)
}

func TestAuthorize_DCRClientWithoutConsentGetsThePage(t *testing.T) {
	f := newConsentFixture(t)
	w := f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE)

	sealedFrom(t, w)
	assert.Empty(t, w.Header().Get("Location"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "same-origin", w.Header().Get("Referrer-Policy"))
	assert.Contains(t, w.Header().Values("Content-Security-Policy"), "frame-ancestors 'none'")
}

func TestConsentPost_AllowThenAuthorizeIssuesACode(t *testing.T) {
	f := newConsentFixture(t)
	assert.NotEmpty(t, codeFrom(t, f.allow(t, f.query(appRedirect, nil))))

	// same redirect, same or fewer scopes: no page
	q := f.query(appRedirect, url.Values{"scope": {"email read-only"}})
	assert.NotEmpty(t, codeFrom(t, f.authorize(q, aliceSession, COOKIE)))

	// a broader supported scope: the page again
	q = f.query(appRedirect, url.Values{"scope": {"openid email roles"}})
	sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
}

func TestConsentForOneRedirectDoesNotCoverAnother(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	w := f.authorize(f.query(otherRedirect, nil), aliceSession, COOKIE)
	sealedFrom(t, w) // page, not a code
}

func TestConsentPost_AllowWithPromptConsentCompletes(t *testing.T) {
	f := newConsentFixture(t)
	q := f.query(appRedirect, url.Values{"prompt": {"consent"}})
	sealed := sealedFrom(t, f.authorize(q, aliceSession, COOKIE))
	w := f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE)
	loc, _ := url.Parse(w.Header().Get("Location"))
	assert.Empty(t, loc.Query().Get("prompt"), "consent is removed from the redirect, so it cannot loop")
	assert.NotEmpty(t, codeFrom(t, f.authorize(loc.Query(), aliceSession, COOKIE)))
}

func TestAuthorize_PromptConsentForcesThePageWhenConsented(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))
	sealedFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"consent"}}), aliceSession, COOKIE))
}

func TestAuthorize_PromptNoneWithoutConsentIsConsentRequired(t *testing.T) {
	f := newConsentFixture(t)
	for _, hint := range []string{"", "alice@example.com", "bob@example.com"} {
		q := f.query(appRedirect, url.Values{"prompt": {"none"}, "login_hint": {hint}})
		w := f.authorize(q, aliceSession, COOKIE)
		require.Equal(t, http.StatusFound, w.Code, hint)
		loc, _ := w.Result().Location()
		assert.Equal(t, "consent_required", loc.Query().Get("error"), "same answer whatever the hint: %q", hint)
	}
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))
	assert.NotEmpty(t, codeFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"none"}}), aliceSession, COOKIE)))
}

func TestAuthorize_BearerSessionIsTreatedAsSignedOutForDCRClients(t *testing.T) {
	f := newConsentFixture(t)
	w := f.authorize(f.query(appRedirect, nil), aliceSession, "header")
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "/-/login?"))
}

func TestAuthorize_NilConsentStoreShowsThePage(t *testing.T) {
	f := newConsentFixture(t)
	f.ex.config.DCRConsent = nil
	sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
}

func TestConsentPost_DenyRemovesConsent(t *testing.T) {
	f := newConsentFixture(t)
	codeFrom(t, f.allow(t, f.query(appRedirect, nil)))

	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, url.Values{"prompt": {"consent"}}), aliceSession, COOKIE))
	w := f.post(sealed, "deny", sameOrigin, aliceSession, COOKIE)
	require.Equal(t, http.StatusFound, w.Code)
	loc, _ := w.Result().Location()
	assert.Equal(t, "access_denied", loc.Query().Get("error"))
	assert.Equal(t, "st", loc.Query().Get("state"))

	sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE)) // asks again
}

func TestConsentPost_Refusals(t *testing.T) {
	f := newConsentFixture(t)
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	bob := jwt.MapClaims{"sub": "bob"}

	expired, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(-time.Minute).Unix()})
	require.NoError(t, err)
	otherIss, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: "https://elsewhere",
		Query: f.query(appRedirect, nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)
	unregistered, err := f.ex.sealJSON(sealPurposeConsent, consentRequest{Sub: "alice", Iss: consentIssuer,
		Query: f.query("https://nope.example/cb", nil).Encode(), Exp: time.Now().Add(time.Minute).Unix()})
	require.NoError(t, err)

	for name, w := range map[string]*httptest.ResponseRecorder{
		"foreign origin":   f.post(sealed, "allow", map[string]string{"Origin": "https://evil.example"}, aliceSession, COOKIE),
		"no session":       f.post(sealed, "allow", sameOrigin, nil, ""),
		"bearer session":   f.post(sealed, "allow", sameOrigin, aliceSession, "header"),
		"another subject":  f.post(sealed, "allow", sameOrigin, bob, COOKIE),
		"tampered seal":    f.post(sealed[:len(sealed)-4]+"AAAA", "allow", sameOrigin, aliceSession, COOKIE),
		"expired seal":     f.post(expired, "allow", sameOrigin, aliceSession, COOKIE),
		"other issuer":     f.post(otherIss, "allow", sameOrigin, aliceSession, COOKIE),
		"unregistered uri": f.post(unregistered, "allow", sameOrigin, aliceSession, COOKIE),
		"bad decision":     f.post(sealed, "maybe", sameOrigin, aliceSession, COOKIE),
	} {
		assert.Equal(t, http.StatusForbidden, w.Code, name)
		assert.Empty(t, w.Header().Get("Location"), name)
	}
	// nothing was recorded by any of them
	ok, _ := f.ex.config.DCRConsent.Covers(context.Background(), "alice", f.clientID, appRedirect, nil)
	assert.False(t, ok)
}

func TestConsentPost_DeletedClientIsRefused(t *testing.T) {
	f := newConsentFixture(t)
	sealed := sealedFrom(t, f.authorize(f.query(appRedirect, nil), aliceSession, COOKIE))
	require.NoError(t, f.ex.config.DCRStore.Delete(context.Background(), f.clientID))
	assert.Equal(t, http.StatusForbidden, f.post(sealed, "allow", sameOrigin, aliceSession, COOKIE).Code)
}

func TestAuthorize_StaticClientsNeverSeeThePage(t *testing.T) {
	o := authorizeOAuth2(t) // static public client "client-1" (oidc_login_test.go)
	w := authorize(o, url.Values{"prompt": {"consent"}}, alice)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, _ := w.Result().Location()
	assert.NotEmpty(t, loc.Query().Get("code"))
}
```

Note: `authorize(...)` in `oidc_login_test.go` sets the auth context without a source. Static clients must not depend on the source, so that is correct as-is.

- [ ] **Step 2: Run** `go test ./internal/auth/ -run 'Consent|TestAuthorize_' -v` → FAIL (undefined `ConsentPost`, `ConsentOriginAllowed`, `consentRequest`).

- [ ] **Step 3: Implement.** Add to the `OAuth2` struct in `oauth2.go`:

```go
	// RenderConsent renders the consent page for a dynamically registered
	// client. nil means RenderBuiltinConsent. The host may set its own
	// (stage 2: the Consent utility page); it must keep a script-free CSP.
	RenderConsent func(http.ResponseWriter, *http.Request, ConsentView)
	// ConsentOriginAllowed decides whether a consent POST provably came from
	// this host's own page. nil refuses every POST (fail closed).
	ConsentOriginAllowed func(*http.Request) bool
```

Create `oauth2_consent.go`:

```go
package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const consentRequestTTL = 10 * time.Minute

// consentRequest is what the consent page's form carries back, sealed. Only
// the subject, issuer, original query and expiry: everything else is derived
// from the query with parseAuthorizeRequest, exactly as authorize derives it.
type consentRequest struct {
	Sub   string `json:"sub"`
	Iss   string `json:"iss"`
	Query string `json:"q"`
	Exp   int64  `json:"exp"`
}

// consentCovers reports whether stored consent covers this request. Any
// store problem means "not covered": the page is shown, never skipped.
func (o *OAuth2) consentCovers(ctx context.Context, subject string, req authorizeRequest) bool {
	store := o.AuthConfig.DCRConsent
	if store == nil {
		return false
	}
	ok, err := store.Covers(ctx, subject, req.ClientID, req.RedirectURI, req.Scopes)
	if err != nil {
		logf.FromContext(ctx).Error(err, "dcr consent: read failed; showing the consent page", "clientID", req.ClientID)
		return false
	}
	return ok
}

// renderConsent answers an authorize request with the consent page.
func (o *OAuth2) renderConsent(w http.ResponseWriter, r *http.Request, client AuthClient, subject, account string, req authorizeRequest) {
	sealed, err := o.AuthExchanger.sealJSON(sealPurposeConsent, consentRequest{
		Sub:   subject,
		Iss:   o.AuthConfig.Issuer,
		Query: r.URL.RawQuery,
		Exp:   time.Now().Add(consentRequestTTL).Unix(),
	})
	if err != nil {
		logf.FromContext(r.Context()).Error(err, "dcr consent: failed to seal the request")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Flow-level headers, whoever renders: never cached, never framed (a
	// framed consent page is a click-hijacking target), and a referrer policy
	// that still lets the POST carry a real Origin (no-referrer would make it
	// "null", which the POST refuses).
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Add("Content-Security-Policy", "frame-ancestors 'none'")

	render := o.RenderConsent
	if render == nil {
		render = RenderBuiltinConsent
	}
	render(w, r, newConsentView(client.Name, req.RedirectURI, account, sealed, req.Scopes))
}

// ConsentPost records the user's decision on a consent page.
func (o *OAuth2) ConsentPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logf.FromContext(ctx)
	forbidden := func(reason string) {
		log.V(1).Info("refusing a consent decision", "reason", reason)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
	unavailable := func(err error) {
		log.Error(err, "dcr consent: store unavailable")
		w.Header().Set("Retry-After", "5")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	}

	if o.ConsentOriginAllowed == nil || !o.ConsentOriginAllowed(r) {
		forbidden("not same-origin")
		return
	}
	authCtx, ok := GetAuthContext(ctx)
	if !ok || AuthSourceFromContext(ctx) != COOKIE {
		forbidden("no browser session")
		return
	}
	subject, err := authCtx.GetSubject()
	if err != nil || subject == "" {
		forbidden("session names nobody")
		return
	}
	if err := r.ParseForm(); err != nil {
		forbidden("unparseable form")
		return
	}
	decision := r.PostFormValue("decision")
	if decision != "allow" && decision != "deny" {
		forbidden("unknown decision")
		return
	}
	var sealed consentRequest
	if err := o.AuthExchanger.openJSON(sealPurposeConsent, r.PostFormValue("request"), &sealed); err != nil {
		forbidden("sealed request does not open")
		return
	}
	if sealed.Sub != subject || sealed.Iss != o.AuthConfig.Issuer || time.Now().Unix() > sealed.Exp {
		forbidden("sealed request is for another session or has expired")
		return
	}
	q, err := url.ParseQuery(sealed.Query)
	if err != nil {
		forbidden("sealed query does not parse")
		return
	}
	req := parseAuthorizeRequest(q)
	client, ok, err := o.AuthExchanger.LookupClient(ctx, req.ClientID)
	if err != nil {
		unavailable(err)
		return
	}
	if !ok || !client.RequireConsent || !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		forbidden("client or redirect no longer registered")
		return
	}
	store := o.AuthConfig.DCRConsent
	if store == nil {
		unavailable(errors.New("no consent store"))
		return
	}

	if decision == "deny" {
		if err := store.Revoke(ctx, subject, req.ClientID, req.RedirectURI); err != nil {
			unavailable(err)
			return
		}
		callbackURL, _ := url.Parse(req.RedirectURI) // registered, so it parses
		redirectAuthorizeError(w, r, callbackURL, req.State, "access_denied")
		return
	}
	if err := store.Grant(ctx, subject, req.ClientID, req.RedirectURI, req.Scopes); err != nil {
		unavailable(err)
		return
	}
	// Back to authorize, which re-runs every check and mints the code, so
	// minting stays in one place. consent is removed so it cannot loop.
	http.Redirect(w, r, OAuthAuthorizePath+"?"+withoutPrompt(q, "consent").Encode(), http.StatusSeeOther)
}
```

Now the gate in `AuthorizeHandler` (`oauth2.go`). Replace the block from `ctx := r.Context()` through the end of the `login_hint` check with the following, and move the existing "We need the Subject" block (its comment and code) up into the marked place so the subject is known before consent is evaluated:

```go
	ctx := r.Context()
	authCtx, ok := GetAuthContext(ctx)
	// Codes for dynamically registered clients go only to a browser session.
	// A bearer token at authorize (a script holding some token for the user)
	// is treated as signed out, so "the user allowed it" cannot be automated.
	if ok && authClient.RequireConsent && AuthSourceFromContext(ctx) != COOKIE {
		ok = false
	}
	if !ok {
		if slices.Contains(prompt, "none") {
			err = fmt.Errorf("prompt=none without a session")
			redirectAuthorizeError(w, r, callbackURL, state, "login_required")
			return
		}
		http.Redirect(w, r, authorizeLoginURL(r, prompt, loginHint), http.StatusSeeOther)
		return
	}

	// <<< the existing "We need the Subject" block moves here, unchanged >>>

	areq := parseAuthorizeRequest(r.URL.Query())
	covered := true
	if authClient.RequireConsent {
		covered = o.consentCovers(ctx, subject, areq)
		// Decided before login_hint is looked at, with one answer whatever
		// the hint, so an unconsented client cannot use prompt=none +
		// login_hint to learn who is signed in.
		if !covered && slices.Contains(prompt, "none") {
			err = fmt.Errorf("prompt=none without consent")
			redirectAuthorizeError(w, r, callbackURL, state, "consent_required")
			return
		}
	}

	if slices.Contains(prompt, "login") || slices.Contains(prompt, "select_account") ||
		(loginHint != "" && !sessionMatchesHint(authCtx, loginHint)) {
		if slices.Contains(prompt, "none") {
			err = fmt.Errorf("prompt=none with a session for another account than login_hint")
			redirectAuthorizeError(w, r, callbackURL, state, "login_required")
			return
		}
		http.Redirect(w, r, authorizeLoginURL(r, prompt, loginHint), http.StatusSeeOther)
		return
	}

	if authClient.RequireConsent && (!covered || slices.Contains(prompt, "consent")) {
		account, _ := authCtx["email"].(string)
		if account == "" {
			account = subject
		}
		o.renderConsent(w, r, authClient, subject, account, areq)
		return
	}
```

(`subject` is the variable the moved block assigns; keep it declared where it is declared today.)

- [ ] **Step 4: Run** `go test ./internal/auth/ -v -run 'Consent|TestAuthorize_|OAuthGet|OAuthLogin'` → PASS. Then `go test ./internal/auth/...`.

- [ ] **Step 5: Commit** `feat(auth): require the user's consent before issuing a code to a dynamically registered client`.

---

### Task 10: The refresh grant requires consent

**Files:**
- Modify: `internal/auth/exchange.go` `RedeemRefreshToken` (after `if claims.ClientID != clientID`)
- Test: `internal/auth/oauth2_consent_test.go`

**Interfaces:**
- Consumes: `LookupClient`, `Config.DCRConsent.HasClient`.

- [ ] **Step 1: Failing tests** (append to `oauth2_consent_test.go`). `createRefreshToken(ctx, RefreshTokenClaims) (string, error)` (exchange.go:937) stores a record exactly as the code grant does:

```go
func (f *consentFixture) refreshToken(t *testing.T) string {
	t.Helper()
	id, err := f.ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		Subject:          "alice",
		ClientID:         f.clientID,
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		OriginalIssuedAt: time.Now().Unix(),
	})
	require.NoError(t, err)
	return id
}

func TestRedeemRefreshToken_DCRClientWithoutConsentFails(t *testing.T) {
	f := newConsentFixture(t)
	_, err := f.ex.RedeemRefreshToken(context.Background(), f.refreshToken(t), f.clientID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGrantFailure), "invalid_grant, so the client re-authorizes")
}

func TestRedeemRefreshToken_DCRClientWithConsentRotates(t *testing.T) {
	f := newConsentFixture(t)
	require.NoError(t, f.ex.config.DCRConsent.Grant(context.Background(), "alice", f.clientID, appRedirect, nil))
	ts, err := f.ex.RedeemRefreshToken(context.Background(), f.refreshToken(t), f.clientID)
	require.NoError(t, err)
	assert.NotEmpty(t, ts.RefreshToken)
}

func TestRedeemRefreshToken_BrowserSessionNeedsNoConsent(t *testing.T) {
	f := newConsentFixture(t)
	id, err := f.ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		Subject: "alice", ClientID: "", ExpiresAt: time.Now().Add(time.Hour).Unix(), OriginalIssuedAt: time.Now().Unix(),
	})
	require.NoError(t, err)
	_, err = f.ex.RedeemRefreshToken(context.Background(), id, "")
	assert.NoError(t, err)
}

func TestRedeemRefreshToken_ConsentStoreErrorIsAServerError(t *testing.T) {
	f := newConsentFixture(t)
	f.ex.config.DCRConsent = dcr.NewConsentStoreFromCache(failingCache{}, time.Hour)
	_, err := f.ex.RedeemRefreshToken(context.Background(), f.refreshToken(t), f.clientID)
	assert.True(t, errors.Is(err, ErrServerError), "a store outage restores the refresh token instead of ending the session")
}
```

Add `"errors"` to the test imports.

- [ ] **Step 2: Run** `go test ./internal/auth/ -run TestRedeemRefreshToken_ -v` → FAIL.

- [ ] **Step 3: Implement.** In `RedeemRefreshToken`, right after the client-id check:

```go
	// A dynamically registered client's session cannot outlive the user's
	// consent: Deny, a future revoke, or the consent expiring ends it at the
	// next refresh. A store failure is a server error, so the deferred
	// restore puts the refresh token back instead of logging the user out.
	if clientID != "" {
		client, ok, lerr := e.LookupClient(ctx, clientID)
		if lerr != nil {
			return failed("%w: client lookup failed: %v", ErrServerError, lerr)
		}
		if ok && client.RequireConsent {
			held := false
			if e.config.DCRConsent != nil {
				h, cerr := e.config.DCRConsent.HasClient(ctx, claims.Subject, clientID)
				if cerr != nil {
					return failed("%w: consent lookup failed: %v", ErrServerError, cerr)
				}
				held = h
			}
			if !held {
				return grantFailed("the user's consent for this client is not held")
			}
		}
	}
```

For the failing-store test, add an exported constructor to `internal/auth/dcr/consent.go` (and have `NewConsentStore` call it):

```go
// NewConsentStoreFromCache builds a ConsentStore over an existing cache.
func NewConsentStoreFromCache(c cache.Cache, ttl time.Duration) *ConsentStore {
	return &ConsentStore{cache: c, ttl: ttl, now: time.Now}
}
```

and in `oauth2_consent_test.go` a cache whose every call fails:

```go
type failingCache struct{}

var errCacheDown = errors.New("cache unavailable")

func (failingCache) Checksum() string { return "" }
func (failingCache) Class() string    { return "failing" }
func (failingCache) Delete(context.Context, string) error { return errCacheDown }
func (failingCache) Get(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errCacheDown
}
func (failingCache) GetAndDelete(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errCacheDown
}
func (failingCache) DecrementIfPositive(context.Context, string) (int64, bool, error) {
	return -1, false, errCacheDown
}
func (failingCache) Host() string { return "" }
func (failingCache) Set(context.Context, string, string, ...cache.SetOption) error { return errCacheDown }
func (failingCache) TTL() time.Duration { return time.Hour }
```

If `cache.Cache` has methods beyond these (`rg -n "^\t[A-Z].*\(" internal/cache/cache.go` inside the interface), add them returning zero values or `errCacheDown`.

- [ ] **Step 4: Run** `go test ./internal/auth/... -v -run 'Redeem|Refresh|Consent'` → PASS, then `go test ./internal/auth/...`.

- [ ] **Step 5: Commit** `feat(auth): a dynamically registered client's refresh requires the user's consent`.

---

### Task 11: Host wiring: one OAuth2 constructor, the consent route, OpenAPI

**Files:**
- Modify: `internal/host/handlers.go` (three `&auth.OAuth2{` sites at ~391, ~977, ~1386; authorize registration ~399)
- Test: `internal/host/system_path_init_test.go` (route registered), plus a host-level consent test in `internal/host/consent_route_test.go`

**Interfaces:**
- Consumes: `auth.OAuth2.ConsentOriginAllowed`, `auth.OAuthConsentPath`, `auth.OAuthAuthorizePath`, `consentOriginAllowed` (Task 4), `(*auth.OAuth2).ConsentPost`.
- Produces: `func (hh *HostHandler) newOAuth2() *auth.OAuth2`.

- [ ] **Step 1: Failing test** (`internal/host/consent_route_test.go`), in the style of `TestLoginHandler_CatchAllClientRoute` (system_path_init_test.go):

```go
package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizeHandler_RegistersTheConsentRoute(t *testing.T) {
	hh := &HostHandler{log: logr.Discard(), scheme: "https", authConfig: &auth.Config{ActivePair: &keys.KeyPair{}}}
	mux := http.NewServeMux()
	paths := map[string]ko.PathInfo{}
	hh.authorizeHandler(mux, paths)

	_, p := mux.Handler(httptest.NewRequest(http.MethodPost, auth.OAuthConsentPath, nil))
	assert.Equal(t, "POST "+auth.OAuthConsentPath, p)
	assert.Contains(t, paths, auth.OAuthConsentPath, "documented in /-/openapi")

	off := http.NewServeMux()
	(&HostHandler{log: logr.Discard()}).authorizeHandler(off, map[string]ko.PathInfo{})
	_, p = off.Handler(httptest.NewRequest(http.MethodPost, auth.OAuthConsentPath, nil))
	assert.Empty(t, p, "not registered when auth is off")
}
```

If `authorizeHandler` needs more fields to run (e.g. `oauth2ResourceAudiences` reading `hh.host`), set the minimum it dereferences; `rg -n "func \(hh \*HostHandler\) (oauth2ResourceAudiences|exchangeTargetAudiences)" internal/host` shows what they read.

- [ ] **Step 2: Run** → FAIL (route missing).

- [ ] **Step 3: Implement** in `handlers.go`:

```go
// newOAuth2 builds the auth.OAuth2 every OAuth route uses, so a hook set for
// one (consent rendering, the consent origin check) cannot be missed on
// another. The host's scheme and domains are snapshotted at mux build, like
// ResourceAudiences, so the request path takes no host lock.
func (hh *HostHandler) newOAuth2() *auth.OAuth2 {
	scheme := hh.scheme
	var domains []string
	if hh.host != nil {
		domains = slices.Clone(hh.host.Routing.Domains)
	}
	return &auth.OAuth2{
		AuthConfig:        hh.authConfig,
		AuthExchanger:     hh.authExchanger,
		ResourceAudiences: hh.oauth2ResourceAudiences(),
		ExchangeTargets:   hh.exchangeTargetAudiences(),
		AccessTokenTTL:    hh.authConfig.TokenTTL,
		ConsentOriginAllowed: func(r *http.Request) bool {
			return consentOriginAllowed(r, scheme, domains)
		},
	}
}
```

Replace all three `&auth.OAuth2{...}` literals with `hh.newOAuth2()`. In the authorize registration, replace `const path = "/-/oauth/authorize"` with `const path = auth.OAuthAuthorizePath`, add the 200 `text/html` response to its OpenAPI operation, and after it register the consent POST:

```go
	consentHandler := hh.authConfig.AddAuthentication(http.HandlerFunc(oauth2.ConsentPost), hh.authExchanger)
	mux.Handle("POST "+auth.OAuthConsentPath, consentHandler)
	hh.registerPath(auth.OAuthConsentPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: auth.OAuthConsentPath,
			Paths: map[string]ko.PathItem{
				auth.OAuthConsentPath: {
					Description: "Records the signed-in user's decision on a consent page",
					Post: &openapi.Operation{
						Description: "Allow or deny a dynamically registered client; same-origin browser form posts only",
						OperationID: "oauth-consent-post",
						Responses: openapi.NewResponses(
							openapi.WithStatus(302, &openapi.ResponseRef{Ref: ko.RespRefFound}),
							openapi.WithStatus(303, &openapi.ResponseRef{Ref: ko.RespRefSeeOther}),
							openapi.WithStatus(403, &openapi.ResponseRef{Ref: ko.RespRefUnauthorized}),
							openapi.WithStatus(500, &openapi.ResponseRef{Ref: ko.RespRefInternalServerError}),
						),
						Summary: "OAuth2 consent decision",
						Tags:    []string{"system", "oauth2", "auth"},
					},
					Summary: "OAuth2 consent",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
```

Also replace the literal `"/-/oauth/authorize"` in `internal/auth/discovery.go:41` and `internal/host/host.go:~819` with `auth.OAuthAuthorizePath` (in `auth` itself, `OAuthAuthorizePath`). If `system_path_init_test.go` lists expected system paths, add `"/-/oauth/consent"`.

- [ ] **Step 4: Run** `go test ./internal/host/ ./internal/auth/... -v -run 'Consent|SystemPath|OpenAPI|MCP|Register'` → PASS; then `go test ./internal/host/`.

- [ ] **Step 5: Commit** `feat(host): wire the consent route; one OAuth2 constructor`.

---

### Task 12: End-to-end check and the full gate

**Files:**
- Test: `internal/auth/oauth2_consent_test.go`

- [ ] **Step 1: Write the end-to-end test**

```go
// A client registered anonymously with two redirects: one a user would trust,
// one they would not. No code may reach either redirect without the user's
// Allow, and an Allow for one releases nothing to the other.
func TestDCRClientGetsNoCodeWithoutConsentAtThatRedirect(t *testing.T) {
	f := newConsentFixture(t)

	for _, redirect := range []string{appRedirect, otherRedirect} {
		w := f.authorize(f.query(redirect, nil), aliceSession, COOKIE)
		assert.Empty(t, w.Header().Get("Location"), redirect)
		sealedFrom(t, w)
	}

	assert.NotEmpty(t, codeFrom(t, f.allow(t, f.query(appRedirect, nil))))

	for _, prompt := range []string{"", "none"} {
		w := f.authorize(f.query(otherRedirect, url.Values{"prompt": {prompt}}), aliceSession, COOKIE)
		if loc, err := w.Result().Location(); err == nil {
			assert.Empty(t, loc.Query().Get("code"), "prompt=%q", prompt)
		}
	}
}
```

- [ ] **Step 2: Run** `go test ./internal/auth/ -run TestDCRClientGetsNoCodeWithoutConsentAtThatRedirect -v` → PASS (Tasks 1-11 implement it; if it fails, the failure points at the task whose behaviour is wrong; fix there).

- [ ] **Step 3: Full gate**

Run: `make test` → all packages PASS.
Run: `make lint` → `0 issues.`
Run: `git status -s` → only intended files.

- [ ] **Step 4: Commit** `test(auth): end-to-end consent coverage for dynamically registered clients`.

- [ ] **Step 5: Do not push.** Report the commit list (`git log --oneline origin/main..HEAD`) to the user.

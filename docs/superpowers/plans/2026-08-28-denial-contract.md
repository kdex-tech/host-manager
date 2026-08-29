# Denial Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace host-manager's five ad-hoc denial vocabularies with one contract — 401 for an unauthenticated caller, 403 for an authenticated one — retiring the anti-enumeration 404 that concealed nothing.

**Architecture:** A new `internal/auth/denial` package owns the status code and the `WWW-Authenticate` challenge for every gate. Each gate classifies its outcome (`Unauthenticated` / `NoIdentity` / `InsufficientScope`) and makes one call. Presentation is *not* negotiated by gates — `unwrap` already re-renders every `>= 400` per `Accept` for the whole mux. The page gate keeps its two 3xx renderings (login redirect, discovery redirect) locally, because a redirect is an alternative to writing a status rather than a kind of status.

**Tech Stack:** Go 1.26.0, `github.com/kdex-tech/entitlements/go`, `net/http`, envtest for controller suites, Helm chart under `chart/`.

**Spec:** `docs/superpowers/specs/2026-08-28-denial-contract-design.md`

## Global Constraints

- **host-manager only.** No `kdex-crds` change, no `kdex-entitlements` change, no cross-repo release. If a task appears to need one, stop and raise it.
- **Go is pinned to 1.26.0.** Do not bump it.
- **Run `make lint` from the workspace root** (`/home/rotty/projects/kdex/workspace`) after code changes; it fans out to every module.
- **Run `make test` inside `kdex-host-manager`** for the module's own suite (includes envtest).
- **Never widen the `unwrap` header allow-list beyond the three headers named in Task 2.** The blanket delete exists to drop a stale `Content-Length` from a suppressed proxy body; that reason still holds for everything else.
- **Challenge values must never carry caller-supplied bytes.** They land inside HTTP quoted-strings. This mirrors the existing discipline at `internal/auth/middleware.go:161`.
- **Commit inside `kdex-host-manager`**, not at the workspace root.

---

### Task 1: The `denial` package

**Files:**
- Create: `internal/auth/denial/denial.go`
- Test: `internal/auth/denial/denial_test.go`

**Interfaces:**
- Consumes: `github.com/kdex-tech/entitlements/go` (`ParsedEntitlements`, `ParsedRequirements`), `kdex.dev/crds/api/v1alpha1` (`SecurityRequirement`), `internal/auth` (`GetAuthContext`).
- Produces: `denial.Outcome` (`Unauthenticated`, `NoIdentity`, `InsufficientScope`); `denial.Checker` interface; `denial.Classify(ctx, Checker, resource, name string, verbs ...string) Outcome`; `denial.Write(w http.ResponseWriter, r *http.Request, o Opts)`; `denial.Opts{Outcome Outcome; Issuer string; ResourceMetadata string; Scopes []string}`.

Note on package placement: `internal/auth/denial` imports its parent `internal/auth`. Child-imports-parent is legal Go and acyclic **as long as `internal/auth` never imports `internal/auth/denial`**. Do not add such an import.

Note on `ResourceMetadata`: it is the full RFC 9728 metadata **URL** (`<issuer>/.well-known/oauth-protected-resource<basePath>`), not the bare resource URI, so no caller has to re-derive it. Empty means "this resource is not oauth2-protected".

- [ ] **Step 1: Write the failing test**

Create `internal/auth/denial/denial_test.go`:

```go
package denial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// fakeChecker reports a fixed answer for the identity probe. Classify calls
// VerifyResourceParsedEntitlements exactly once, with an EMPTY requirement set
// (the identity probe), so identityOK is the only knob a test needs.
type fakeChecker struct {
	identityOK bool
	err        error
	calls      int
}

func (f *fakeChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (f *fakeChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (f *fakeChecker) VerifyResourceParsedEntitlements(
	_ string, _ string,
	_ entitlements.ParsedEntitlements, _ entitlements.ParsedRequirements,
	_ ...string,
) (bool, error) {
	f.calls++
	return f.identityOK, f.err
}

func authedCtx() context.Context {
	return auth.SetAuthContext(context.Background(), auth.AuthContext{"sub": "alice"})
}

func TestClassifyAnonymousIsUnauthenticated(t *testing.T) {
	c := &fakeChecker{identityOK: true}
	if got := Classify(context.Background(), c, "functions", "/api/v1/x"); got != Unauthenticated {
		t.Fatalf("Classify = %v, want Unauthenticated", got)
	}
	if c.calls != 0 {
		t.Fatalf("identity probe ran %d times for an anonymous caller, want 0", c.calls)
	}
}

func TestClassifyAuthenticatedWithoutIdentityIsNoIdentity(t *testing.T) {
	c := &fakeChecker{identityOK: false}
	if got := Classify(authedCtx(), c, "functions", "/api/v1/x"); got != NoIdentity {
		t.Fatalf("Classify = %v, want NoIdentity", got)
	}
}

func TestClassifyAuthenticatedWithIdentityIsInsufficientScope(t *testing.T) {
	c := &fakeChecker{identityOK: true}
	if got := Classify(authedCtx(), c, "functions", "/api/v1/x"); got != InsufficientScope {
		t.Fatalf("Classify = %v, want InsufficientScope", got)
	}
}

func TestClassifyNilCheckerIsNoIdentity(t *testing.T) {
	if got := Classify(authedCtx(), nil, "functions", "/api/v1/x"); got != NoIdentity {
		t.Fatalf("Classify = %v, want NoIdentity", got)
	}
}

func TestWriteUnauthenticatedNonOAuth2UsesRealm(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome: Unauthenticated,
		Issuer:  "https://example.test",
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	want := `Bearer realm="https://example.test"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestWriteUnauthenticatedOAuth2UsesResourceMetadataAndNoErrorParam(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          Unauthenticated,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
	})
	got := rr.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
	// RFC 6750 3.1: the error parameter is omitted when no credentials were sent.
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestWriteNoIdentityIs403WithoutChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome:          NoIdentity,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/x",
		Scopes:           []string{"users:*:admin"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none: naming a scope implies a scope would fix it", got)
	}
}

func TestWriteInsufficientScopeIs403WithScope(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          InsufficientScope,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		Scopes:           []string{"users:*:admin", "vector_stores:*:read"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	want := `Bearer error="insufficient_scope", scope="users:*:admin vector_stores:*:read", ` +
		`resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestWriteInsufficientScopeNonOAuth2HasNoChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome: InsufficientScope,
		Issuer:  "https://example.test",
		Scopes:  []string{"users:*:admin"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none for a non-oauth2 resource", got)
	}
}

func TestWriteUnauthenticatedWithNoIssuerUsesBareBearer(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/gated", nil), Opts{Outcome: Unauthenticated})
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf(`challenge = %q, want a bare "Bearer": realm="" is worse than none`, got)
	}
}

func TestChallengeDropsUnsafeScopeValues(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          InsufficientScope,
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		Scopes:           []string{`bad"quote`, "good:scope", `back\slash`, "has space"},
	})
	want := `Bearer error="insufficient_scope", scope="good:scope", ` +
		`resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/denial/... -v`
Expected: FAIL — the package does not compile (`undefined: Classify`, `undefined: Write`, `undefined: Opts`, `undefined: Unauthenticated`).

- [ ] **Step 3: Write minimal implementation**

Create `internal/auth/denial/denial.go`:

```go
// Package denial implements host-manager's single denial contract.
//
// One question — "may this caller have this?" — gets one answer shape:
//
//	no credential presented            -> 401 + WWW-Authenticate
//	credential, fails the identity gate -> 403, no challenge
//	credential, fails the requirement   -> 403 + insufficient_scope
//
// No status is ever chosen to conceal that a resource exists. The
// anti-enumeration 404 this replaces concealed nothing: /-/openapi serves
// every Ready function's paths to anonymous callers with no entitlement
// check (internal/host/openapi.go), so enumeration was already cheaper by
// GET than by probing. If /-/openapi is ever gated or caller-filtered, that
// trade reverses and this package is what should be revisited.
//
// This package owns statuses and challenges, never bodies and never
// redirects. Presentation belongs to the mux-wide unwrap layer
// (internal/host/feedback.go), which re-renders every >= 400 per Accept.
// Redirects belong to the page gate, because a redirect is an alternative
// to writing a status rather than a kind of status.
//
// Design: docs/superpowers/specs/2026-08-28-denial-contract-design.md
package denial

import (
	"context"
	"net/http"
	"strings"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Outcome is which of the three contract rows a denial fell into.
type Outcome int

const (
	// Unauthenticated: no credential was presented at all.
	Unauthenticated Outcome = iota
	// NoIdentity: a credential was presented but cannot address the
	// resource at all -- it fails the <resource>:<resourceName>:read
	// identity gate.
	NoIdentity
	// InsufficientScope: a credential was presented and clears the
	// identity gate, but does not satisfy the declared requirement.
	InsufficientScope
)

func (o Outcome) String() string {
	switch o {
	case Unauthenticated:
		return "unauthenticated"
	case NoIdentity:
		return "no-identity"
	case InsufficientScope:
		return "insufficient-scope"
	}
	return "unknown"
}

// Checker is the subset of the host's authorization checker that Classify
// needs. Declared here (rather than imported) so the package depends on
// behaviour, not on the HostHandler.
type Checker interface {
	GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements
	ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements
	VerifyResourceParsedEntitlements(
		string, string,
		entitlements.ParsedEntitlements, entitlements.ParsedRequirements,
		...string,
	) (bool, error)
}

// Opts carries everything Write needs to render a denial.
type Opts struct {
	Outcome Outcome
	// Issuer is the host's issuer address, used as the realm when the
	// resource is not oauth2-protected.
	Issuer string
	// ResourceMetadata is the full RFC 9728 metadata URL
	// (<issuer>/.well-known/oauth-protected-resource<basePath>).
	// Empty when the resource is not oauth2-protected.
	ResourceMetadata string
	// Scopes are the requirement's declared scopes, named in an
	// insufficient_scope challenge so a client can step up.
	Scopes []string
}

// Classify decides which contract row a denial falls into. It runs ONLY
// after a gate has already denied, so the extra identity probe below is
// never on the happy path.
//
// Anonymity is tested with auth.GetAuthContext rather than by inspecting
// entitlements: anonymous entitlements live inside the AuthorizationChecker
// itself, not as a synthetic auth context, so !ok really does mean "no
// credential presented".
//
// The identity/requirement split needs no library change. An EMPTY
// requirement set reduces VerifyResourceParsedEntitlements to exactly the
// identity check -- the same reduction /-/check relies on and documents
// (internal/host/check.go).
func Classify(ctx context.Context, c Checker, resource, name string, verbs ...string) Outcome {
	if _, authenticated := auth.GetAuthContext(ctx); !authenticated {
		return Unauthenticated
	}
	if c == nil {
		return NoIdentity
	}
	hasIdentity, err := c.VerifyResourceParsedEntitlements(
		resource, name,
		c.GetParsedEntitlements(ctx),
		c.ParseRequirements(nil),
		verbs...,
	)
	if err != nil || !hasIdentity {
		return NoIdentity
	}
	return InsufficientScope
}

// Write sets the status and, where the contract calls for one, the
// WWW-Authenticate header. It uses http.Error so the status text becomes
// unwrap's statusMsg; it never renders HTML itself.
func Write(w http.ResponseWriter, r *http.Request, o Opts) {
	switch o.Outcome {
	case Unauthenticated:
		// RFC 7235: a 401 MUST carry a challenge. RFC 6750 3.1: the error
		// parameter is omitted when no credentials were sent -- claiming
		// invalid_token would be a lie about a token never presented.
		switch {
		case o.ResourceMetadata != "":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+o.ResourceMetadata+`"`)
		case o.Issuer != "":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+o.Issuer+`"`)
		default:
			// A host with no routing domain yet has no issuer to name.
			// RFC 7235 permits a bare scheme, and a bare Bearer is a valid
			// challenge -- realm="" would be worse than none.
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

	case InsufficientScope:
		// RFC 6750 3.1 defines insufficient_scope as a 403 that still
		// carries a challenge, which is what gives a client a step-up path
		// instead of a dead end.
		if o.ResourceMetadata != "" {
			c := `Bearer error="insufficient_scope"`
			if scope := safeScope(o.Scopes); scope != "" {
				c += `, scope="` + scope + `"`
			}
			c += `, resource_metadata="` + o.ResourceMetadata + `"`
			w.Header().Set("WWW-Authenticate", c)
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)

	default: // NoIdentity
		// No challenge: the caller cannot address the resource at all, so
		// naming a scope would imply a scope would fix it.
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

// safeScope joins scopes RFC 6749 style (space-delimited), dropping any
// value that cannot sit in an HTTP quoted-string or would break the
// delimiter. Scopes are operator-authored CR data, not caller-supplied --
// but the same discipline the invalid_token challenge follows applies:
// nothing unvalidated reaches a header.
func safeScope(scopes []string) string {
	safe := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "" || strings.ContainsAny(s, "\"\\ \t\r\n,") {
			continue
		}
		safe = append(safe, s)
	}
	return strings.Join(safe, " ")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/auth/denial/... -v`
Expected: PASS — all ten tests.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/auth/denial/
git commit -m "feat(auth): add the denial package — one contract for every gate"
```

---

### Task 2: `unwrap` must not delete the challenge

**Files:**
- Modify: `internal/host/feedback.go:320-344` (`unwrap`)
- Test: `internal/host/unwrap_headers_test.go` (create)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: nothing new. Behavioural guarantee only — a `WWW-Authenticate`, `Retry-After` or `X-KDex-Sniffer-Suppressed` header set by any handler survives the HTML error rendering.

This is a live bug, not a hypothetical. `DesignMiddleware` wraps the whole mux (`internal/host/host.go:618`), and `unwrap`'s HTML branch deletes every response header before rendering. Verified against dev on 2026-08-28:

```
Accept: */*        -> HTTP/2 401  www-authenticate: Bearer resource_metadata="…"
Accept: text/html  -> HTTP/2 401     <- no challenge at all
```

A 401 without `WWW-Authenticate` violates RFC 7235 and silently disables OAuth discovery for browser-shaped clients. Every later task in this plan depends on the challenge surviving, so this lands first.

- [ ] **Step 1: Write the failing test**

Create `internal/host/unwrap_headers_test.go`:

```go
package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A handler that denies the way the denial contract requires: a status and a
// challenge. unwrap must not destroy the challenge on its way to rendering
// the HTML error page.
func denyingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://example.test"`)
		w.Header().Set("Retry-After", "120")
		w.Header().Set("Content-Length", "999") // the stale header unwrap exists to drop
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func TestUnwrapPreservesChallengeForHTMLClients(t *testing.T) {
	hh := &HostHandler{}

	req := httptest.NewRequest(http.MethodGet, "/gated", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	denyingHandler().ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://example.test"` {
		t.Fatalf("WWW-Authenticate = %q; a 401 without a challenge violates RFC 7235", got)
	}
	if got := rr.Header().Get("Retry-After"); got != "120" {
		t.Fatalf("Retry-After = %q, want 120", got)
	}
	if got := rr.Header().Get("Content-Length"); got == "999" {
		t.Fatal("stale Content-Length survived; unwrap must still drop it")
	}
}

func TestUnwrapPreservesChallengeForNonHTMLClients(t *testing.T) {
	hh := &HostHandler{}

	req := httptest.NewRequest(http.MethodGet, "/gated", nil)
	req.Header.Set("Accept", "*/*")
	rr := httptest.NewRecorder()

	ew := &errorResponseWriter{ResponseWriter: rr}
	denyingHandler().ServeHTTP(ew, req)
	hh.unwrap(ew, req, rr)

	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="https://example.test"` {
		t.Fatalf("WWW-Authenticate = %q, want the challenge preserved", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestUnwrapPreserves -v`
Expected: `TestUnwrapPreservesChallengeForHTMLClients` FAILS with `WWW-Authenticate = ""`. The non-HTML test passes already (that branch never deleted headers) — keep it as the regression that pins the working half.

- [ ] **Step 3: Write minimal implementation**

In `internal/host/feedback.go`, replace the header-wipe block inside `unwrap`:

```go
		if strings.Contains(accept, "text/html") {
			// Clear headers before calling serveError: previous handlers
			// (like ReverseProxy) may have set headers -- notably
			// Content-Length -- describing a body we've suppressed.
			//
			// Three headers are exempt. WWW-Authenticate is REQUIRED on a
			// 401 (RFC 7235); deleting it produced a bare 401 for every
			// HTML-accepting client and silently disabled OAuth discovery
			// for browsers. Retry-After and X-KDex-Sniffer-Suppressed are
			// likewise about the rejection itself, not about the body being
			// replaced. Do not widen this list: everything else is exactly
			// what the wipe exists for.
			header := w.Header()
			preserved := map[string]string{}
			for _, k := range []string{"WWW-Authenticate", "Retry-After", "X-KDex-Sniffer-Suppressed"} {
				if v := header.Get(k); v != "" {
					preserved[k] = v
				}
			}
			for k := range header {
				delete(header, k)
			}
			for k, v := range preserved {
				header.Set(k, v)
			}

			// Write the buffered status code structure
			hh.serveError(w, r, ew.statusCode, ew.statusMsg)
		} else {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestUnwrap -v`
Expected: PASS.

Then run the module suite to be sure nothing depended on the wipe:
Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/feedback.go internal/host/unwrap_headers_test.go
git commit -m "fix(host): preserve WWW-Authenticate through the HTML error rendering

unwrap deleted every response header before rendering the error page, so a
401 reached any HTML-accepting client with no challenge at all -- an RFC 7235
violation that silently disabled OAuth discovery for browsers."
```

---

### Task 3: The function proxy adopts the contract

**Files:**
- Modify: `internal/host/types.go:185-216` (add `oauth2Scopes` to `functionHandler`)
- Modify: `internal/host/proxy.go:395-398` (capture the scopes)
- Modify: `internal/host/proxy.go:600-618` (the denial branch)
- Test: `internal/host/proxy_challenge_test.go:132` (invert `TestUnauthorizedBearerOnlyPathStill404`)
- Test: `internal/host/mcp_oauth2_e2e_test.go:463` (tighten)

**Interfaces:**
- Consumes: `denial.Classify`, `denial.Write`, `denial.Opts` from Task 1.
- Produces: `functionHandler.oauth2Scopes []string`, populated at handler-build time from `OAuth2Resource.Scopes`.

- [ ] **Step 1: Write the failing test**

Rename and rewrite the test at `internal/host/proxy_challenge_test.go:132`. Read the existing `TestUnauthorizedBearerOnlyPathStill404` first and reuse its fixture verbatim — only the assertions change:

```go
// A bearer-only (non-oauth2) function used to return the anti-enumeration
// 404 here. That concealed nothing -- /-/openapi publishes the same path to
// the same anonymous caller -- so the contract returns an actionable 401
// with a realm challenge instead.
func TestUnauthorizedBearerOnlyPathReturns401WithRealm(t *testing.T) {
	// ... same fixture as the former TestUnauthorizedBearerOnlyPathStill404 ...

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (anti-enum 404 retired)", rr.Code)
	}
	got := rr.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(got, `Bearer realm="`) {
		t.Fatalf("challenge = %q, want a Bearer realm challenge", got)
	}
	if strings.Contains(got, "error=") {
		t.Fatalf("challenge = %q; RFC 6750 3.1 omits error= when no credentials were sent", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestUnauthorizedBearerOnlyPath -v`
Expected: FAIL with `status = 404, want 401`.

- [ ] **Step 3: Write minimal implementation**

**3a.** In `internal/host/types.go`, add the field to `functionHandler` immediately after `oauth2Resource`:

```go
	// oauth2Scopes is the de-duplicated union of the oauth2 scheme's scopes
	// across this function's operations -- the same union
	// oauth2ProtectedResources() already computes. Named in an
	// insufficient_scope challenge so a client can step up rather than
	// dead-end. Empty when the function is not oauth2-protected.
	oauth2Scopes []string
```

**3b.** In `internal/host/proxy.go`, extend the oauth2 capture at ~line 395:

```go
	if res, ok := hh.oauth2ProtectedResources()[fn.Spec.API.BasePath]; ok {
		fh.oauth2Protected = true
		fh.oauth2Resource = res.Resource
		fh.oauth2Scopes = res.Scopes
	}
```

**3c.** In `internal/host/proxy.go`, replace the denial branch (the `if err != nil || !authorized {` block ending in the 404):

```go
			if err != nil || !authorized {
				if err != nil {
					log.Error(err, "authorization check failed", "function", fn.Name)
				} else {
					log.V(1).Info("unauthorized access attempt", "function", fn.Name)
				}
				// The denial contract retires the anti-enumeration 404 that
				// used to be this branch's else. It concealed nothing:
				// /-/openapi serves every Ready function's paths to
				// anonymous callers with no entitlement check
				// (internal/host/openapi.go), so enumeration was already
				// cheaper by GET than by probing. If /-/openapi is ever
				// gated or caller-filtered, revisit this.
				// docs/superpowers/specs/2026-08-28-denial-contract-design.md
				var meta string
				if fh.oauth2Protected && fh.oauth2Resource != "" {
					meta = fh.issuer + "/.well-known/oauth-protected-resource" + fn.Spec.API.BasePath
				}
				denial.Write(w, r, denial.Opts{
					Outcome: denial.Classify(
						r.Context(), authChecker, "functions", fn.Spec.API.BasePath),
					Issuer:           fh.issuer,
					ResourceMetadata: meta,
					Scopes:           fh.oauth2Scopes,
				})
				return
			}
```

Add the import `"github.com/kdex-tech/host-manager/internal/auth/denial"` to `internal/host/proxy.go`.

Note the empty-`oauth2Resource` guard is preserved: an empty resource would produce a metadata URL that is just the issuer root, so `meta` stays empty and the caller gets the realm challenge instead. That degenerate case used to fall through to the 404.

**3d.** Tighten `internal/host/mcp_oauth2_e2e_test.go:463`:

```go
		assert.Equal(t, http.StatusForbidden, mcpRec.Code,
			"an authenticated subject lacking the required entitlement gets 403, not 401: "+
				"re-authenticating would not help them")
```

If the fixture's subject is anonymous rather than authenticated, assert `http.StatusUnauthorized` instead — read the fixture before choosing. Do not leave the assertion accepting a set of codes; the point of the contract is that exactly one is correct.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run 'TestUnauthorizedBearerOnlyPath|TestMCP' -v`
Expected: PASS.

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && make test`
Expected: PASS. Any other test asserting a 404 from the proxy gate is now asserting the retired posture — update it to the contract, do not weaken the new assertion to accommodate it.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/types.go internal/host/proxy.go internal/host/proxy_challenge_test.go internal/host/mcp_oauth2_e2e_test.go
git commit -m "feat(host): the function proxy answers 401/403, not the anti-enum 404"
```

---

### Task 4: API token and capability gates adopt the contract

**Files:**
- Modify: `internal/host/apitoken.go:133-146` (revoke), `internal/host/apitoken.go:249-260` (mint)
- Modify: `internal/host/capabilities.go:196-201`
- Test: `internal/host/apitoken_denial_test.go` (create)

**Interfaces:**
- Consumes: `denial.Classify`, `denial.Write`, `denial.Opts` from Task 1; `hh.issuerAddress()` (existing, used at `internal/host/oauth2_resources.go:29`).
- Produces: nothing new.

These three already return 401/403, so this task changes little behaviourally. It exists so there is exactly **one** vocabulary: an anonymous caller here gets 401 with a challenge rather than a bare 403, which is the row the ad-hoc code got wrong.

- [ ] **Step 1: Write the failing test**

`internal/host/apitoken_test.go` already has the fixture to mirror — `TestHostHandler_ApitokenRevokeHandler_Forbidden` (`:96`) and `TestHostHandler_ApitokenRevokeHandler_NoSubject` (`:64`). Reuse `mockApitokenAuthChecker` and the `apitoken.NewTokenManager` setup verbatim.

Create `internal/host/apitoken_denial_test.go`:

```go
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// An anonymous caller presented no credential, so the answer is 401 -- and a
// 401 MUST carry a challenge (RFC 7235). This endpoint returned a bare one.
func TestApitokenRevokeAnonymousGets401WithChallenge(t *testing.T) {
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		host:       &kdexv1alpha1.KDexHostSpec{},
	}

	reqBody, _ := json.Marshal(RevokeRequest{Token: "irrelevant"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	hh.apitokenRevokeHandler(rr, req) // no auth context

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an anonymous caller", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
}

// An authenticated caller who may not revoke for another subject gets 403 and
// no challenge: re-authenticating as the same subject would not help.
func TestApitokenRevokeUnderEntitledGets403WithoutChallenge(t *testing.T) {
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		host:       &kdexv1alpha1.KDexHostSpec{},
		authChecker: &mockApitokenAuthChecker{
			CheckAccessFn: func(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
				return false, nil
			},
		},
	}

	token, _ := tm.MintStatelessKey("aud", "other-user", "act", "scope", time.Hour)
	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "test-user"}))
	rr := httptest.NewRecorder()

	hh.apitokenRevokeHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none on a NoIdentity 403", got)
	}
}
```

If `mockApitokenAuthChecker` does not implement the three methods `denial.Classify` needs (`GetParsedEntitlements`, `ParseRequirements`, `VerifyResourceParsedEntitlements`), add them returning zero values and `false, nil` — mirroring `pageMockAuthChecker` in `internal/host/page_test.go:22-48`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestApitokenMint -v`
Expected: `TestApitokenMintAnonymousGets401WithChallenge` FAILS with `status = 403, want 401`.

- [ ] **Step 3: Write minimal implementation**

**4a.** `internal/host/apitoken.go:76-88` — the two anonymous rejections, which returned a bare 401 with no challenge:

```go
	ac, ok := auth.GetAuthContext(r.Context())
	if !ok {
		log.V(1).Info("no auth context; rejecting")
		denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
		return
	}

	requestingSub, err := ac.GetSubject()
	if err != nil || requestingSub == "" {
		log.V(1).Info("no subject in auth context; rejecting")
		denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
		return
	}
```

**4b.** `internal/host/apitoken.go`, the revoke gate:

```go
		if err != nil || !authorized {
			log.V(1).Info("revoke denied: caller may not revoke for another subject",
				"subject", requestingSub)
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Classify(
					r.Context(), hh.authChecker, "apitokens", requestingSub, "revoke"),
				Issuer: hh.issuerAddress(),
			})
			return
		}
```

Note the log drops from `Error` to `V(1)`: an under-entitled caller is an expected outcome, not a server fault — the same reasoning recorded at `internal/auth/middleware.go` for the expired-token path (#181).

**4c.** `internal/host/apitoken.go`, the mint gate:

```go
	if err != nil || !authorized {
		log.V(1).Info("mint denied", "subject", subject)
		denial.Write(w, r, denial.Opts{
			Outcome: denial.Classify(r.Context(), hh.authChecker, "apitokens", subject, "mint"),
			Issuer:  hh.issuerAddress(),
		})
		return
	}
```

**4d.** `internal/host/capabilities.go`:

```go
	if sub == "" {
		denial.Write(w, r, denial.Opts{
			Outcome: denial.Unauthenticated,
			Issuer:  hh.issuerAddress(),
		})
		return
	}
```

Add the `denial` import to both files.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run 'TestApitoken|TestCapabilit' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/apitoken.go internal/host/capabilities.go internal/host/apitoken_denial_test.go
git commit -m "feat(host): apitoken and capability gates speak the denial contract"
```

---

### Task 5: The page gate — statuses, and an `Accept`-conditional login redirect

**Files:**
- Create: `internal/host/accept.go`
- Modify: `internal/host/feedback.go` (use the shared helper in `unwrap`)
- Modify: `internal/host/page.go:35-90`
- Test: `internal/host/page_denial_test.go` (create)

**Interfaces:**
- Consumes: `denial.*` from Task 1.
- Produces: `acceptsHTML(r *http.Request) bool` in package `host`, used by both `unwrap` and the page gate.

This task delivers the contract's statuses for pages and makes the login redirect `Accept`-conditional. It deliberately leaves `firstAuthorizedPage` exactly as it is — Task 6 puts it behind the knob. Splitting here means a reviewer can accept the status change without also accepting the knob.

- [ ] **Step 1: Write the failing test**

`internal/host/page_test.go` already provides everything this needs — `gatedHostFixture(pages...)`, `newPage(name, label, basePath)`, `denyPath(basePath)` and `pageMockAuthChecker`. Reuse them; do not build a second harness.

**Decide the no-`Accept` case first, because it changes two existing tests.** `acceptsHTML` requires an explicit `text/html`. A request with no `Accept` header, and one sending `*/*` (curl's default), both fall to the 401. RFC 9110 says an absent `Accept` means any type is acceptable, so the looser reading would redirect them — but sending an API client to an HTML login form is the exact failure this contract exists to end, and every real browser sends `Accept: text/html` on a navigation. Requiring the explicit signal is the sharper rule and the safe one.

Consequently `TestPageHandlerFunc_UnauthenticatedPrefersLoginOverAuthorizedPage` (`internal/host/page_test.go:94`) and `TestPageHandlerFunc_LoginReturnPreservesQueryString` (`:114`) must set the header they always meant: add `req.Header.Set("Accept", "text/html")` to each. They test browser behaviour, so making the browser signal explicit is more faithful, not a weakening — #184's assertions stay exactly as they are.

Create `internal/host/page_denial_test.go`:

```go
package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// authedReq returns a request carrying an auth context -- a caller who
// presented a credential. Anonymity is what separates 401 from 403, and
// anonymous entitlements live inside the checker rather than the context,
// so the presence of the context is the whole test.
func authedReq(method, target, accept string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", accept)
	return req.WithContext(
		auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "alice"}))
}

func anonReq(method, target, accept string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Accept", accept)
	return req
}

// An anonymous API client asking for a gated page gets the contract's 401,
// not a 303 to a login form it cannot render.
func TestPageGateAnonymousNonHTMLGets401(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q; an API client must not be sent to a login form", loc)
	}
}

// A browser asking for the same page still gets the login redirect: that is
// the HTML rendering of Unauthenticated, and #184 put it here deliberately.
func TestPageGateAnonymousHTMLStillRedirectsToLogin(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/-/login?return=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want the login redirect with a return trip", got)
	}
}

// An anonymous caller on a host with NO login page has nothing to redirect
// to, so the contract's 401 is the answer even for a browser.
func TestPageGateAnonymousNoLoginPageGets401(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 when there is no login page to send them to", w.Code)
	}
}

// An authenticated, under-entitled caller gets 403 -- no redirect, no 404.
// Task 6 makes the HTML rendering of this switchable; the non-HTML answer
// stays 403 in every mode.
func TestPageGateAuthenticatedUnderEntitledGets403(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatal("NoIdentity carries no challenge: naming a scope would imply a scope would fix it")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestPageGate -v`
Expected: FAIL — the anonymous non-HTML case currently returns 303, and the authenticated case currently returns 303-to-first-authorized or 404.

- [ ] **Step 3: Write minimal implementation**

**5a.** Create `internal/host/accept.go`:

```go
package host

import (
	"net/http"
	"strings"
)

// acceptsHTML reports whether the caller can render an HTML response.
//
// It is the single test behind two decisions that must never disagree:
// which denials unwrap re-renders as the error utility page, and whether the
// page gate answers Unauthenticated with a login redirect or a 401. A caller
// that cannot render HTML must never be sent to a login form.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}
```

**5b.** In `internal/host/feedback.go`, replace `unwrap`'s inline test:

```go
		if acceptsHTML(r) {
```

and drop the now-unused `accept := r.Header.Get("Accept")` line above it. Leave the sniffer's own three-way format chooser (`isAgent` / `isCLI`) alone — it answers a different question (which *representation* of a sniffer result to serve) and has three outcomes, not two.

**5c.** In `internal/host/page.go`, replace the `!authorized` block. The anonymous branch gains one condition; the tail becomes the contract:

```go
			if !authorized {
				log.V(2).Info("unauthorized access attempt",
					"resource", "pages", "resourceName", ph.BasePath(), "l10n", l.String())

				outcome := denial.Classify(r.Context(), hh.authChecker, "pages", ph.BasePath())

				// An anonymous caller gets the login page with a return trip
				// -- but only if it can render one. This branch used to
				// redirect every anonymous caller, so an API client asking
				// for a gated page received a 303 to an HTML form instead of
				// the 401 that would have told it what to do. See #184 for
				// why the branch sits here, ahead of discovery.
				_, hasLoginPage := hh.utilityPages[v1alpha1.LoginUtilityPageType]
				if outcome == denial.Unauthenticated && hasLoginPage && acceptsHTML(r) {
					log.V(2).Info("unauthenticated, redirecting to login")
					// RequestURI, not Path: the return trip has to carry the
					// query string too, or a gated /search?q=foo sends the
					// user back to a bare /search. SafeReturnPath round-trips
					// a query and still collapses anything cross-origin.
					http.Redirect(w, r,
						"/-/login?return="+url.QueryEscape(r.URL.RequestURI()),
						http.StatusSeeOther)
					return
				}

				denial.Write(w, r, denial.Opts{
					Outcome: outcome,
					Issuer:  hh.issuerAddress(),
				})
				return
			}
```

Delete the `firstAuthorizedPage` discovery block and the trailing 404 from this function — Task 6 reintroduces discovery behind the knob. Leave `firstAuthorizedPage` itself in place; it is still called there.

Leave the `err != nil` 404 a few lines above (`internal/host/page.go:42`) exactly as it is. It is arguably a 500 — an authorization check that *errored* is a server fault, not a denial — but the spec deferred that question for the proxy's identical arm, and the same deferral applies here. It is listed as a follow-up below, not smuggled into this task.

Add the `denial` import to `internal/host/page.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run 'TestPage|TestUnwrap' -v`
Expected: PASS.

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && make test`
Expected: PASS. Existing page tests asserting the discovery redirect will fail here — that behaviour returns in Task 6. Mark them `t.Skip("restored behind --page-denial-mode in Task 6")` rather than deleting them, and un-skip in Task 6.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/accept.go internal/host/page.go internal/host/feedback.go internal/host/page_denial_test.go internal/host/page_test.go
git commit -m "feat(host): the page gate answers 401/403; login redirect is now Accept-conditional"
```

---

### Task 6: The page-denial knob and the discovery redirect

**Files:**
- Modify: `internal/host/types.go` (add `PageDenialMode` type, field, and setter)
- Modify: `internal/host/page.go` (the discovery rendering)
- Modify: `cmd/main.go:95-130` (flag), `cmd/main.go:334` (wire it)
- Modify: `chart/values.yaml:55-58` area, `chart/templates/deployment.yaml:42-48` area
- Test: `internal/host/page_denial_test.go` (extend), `internal/host/page_test.go` (un-skip)

**Interfaces:**
- Consumes: `denial.Outcome` from Task 1; `acceptsHTML` from Task 5.
- Produces: `host.PageDenialMode` (`PageDenialDiscover`, `PageDenialForbid`); `(*HostHandler).SetPageDenialMode(PageDenialMode) *HostHandler`, mirroring `SetProxyTimeouts` at `internal/host/types.go:163`.

`FORBIDDEN` is one decision with two browser renderings. **Non-HTML callers get 403 in both modes, always** — the knob never changes what an API client sees.

- [ ] **Step 1: Write the failing test**

Append to `internal/host/page_denial_test.go`, reusing the same fixtures:

```go
// discover mode: a browser is sent to a page it can reach, and told which
// page it was denied.
func TestPageGateDiscoverModeRedirectsHTMLWithDeniedMarker(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/pricing?denied=%2Fdeveloper-keys" {
		t.Fatalf("Location = %q, want /pricing?denied=%%2Fdeveloper-keys", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store: a cached denial outlives the grant that fixes it", got)
	}
}

// The knob is about the HTML rendering only.
func TestPageGateDiscoverModeStill403sNonHTML(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "application/json"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the knob never changes what an API client sees", w.Code)
	}
}

// One hop, maximum. firstAuthorizedPage can return a page that itself denies
// -- the navigation walk and the page render are separate checks -- so a
// request already carrying denied= renders the 403 rather than looping.
func TestPageGateDiscoverModeDoesNotLoop(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(
		w, authedReq("GET", "/developer-keys?denied=%2Fsomething", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 on a request already carrying denied=", w.Code)
	}
}

// Nothing to discover -> the 403 page, which is the floor both modes stand on.
func TestPageGateDiscoverModeFallsBackTo403(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated) // the only page is the denied one
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 when no accessible page exists", w.Code)
	}
}

// forbid mode: the truthful 403 in the browser too, and no redirect at all.
func TestPageGateForbidModeReturns403ToHTML(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialForbid)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, authedReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect in forbid mode", loc)
	}
}

// Discovery is only ever a rendering of FORBIDDEN. An anonymous caller is
// UNAUTHENTICATED -- the fix is logging in, not being sent elsewhere.
func TestPageGateDiscoverModeNeverDiscoversForAnonymous(t *testing.T) {
	gated := newPage("developer-keys", "Developer Keys", "/developer-keys")
	hh := gatedHostFixture(gated, newPage("pricing", "Pricing", "/pricing"))
	hh.authChecker = denyPath("/developer-keys")
	hh.SetPageDenialMode(PageDenialDiscover)
	delete(hh.utilityPages, kdexv1alpha1.LoginUtilityPageType)

	w := httptest.NewRecorder()
	hh.pageHandlerFunc(gated, &hh.Translations)(w, anonReq("GET", "/developer-keys", "text/html"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: anonymous never discovers", w.Code)
	}
}
```

Also un-skip any page test skipped in Task 5 and set `hh.SetPageDenialMode(PageDenialDiscover)` on its fixture.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestPageGate -v`
Expected: FAIL — `undefined: PageDenialDiscover`, `undefined: SetPageDenialMode`.

- [ ] **Step 3: Write minimal implementation**

**6a.** In `internal/host/types.go`, next to `ProxyTimeouts`:

```go
// PageDenialMode selects how the page gate renders FORBIDDEN to a browser.
// It governs the HTML rendering ONLY -- a non-HTML caller gets 403 in every
// mode, because the knob is about presentation, not about the contract.
type PageDenialMode string

const (
	// PageDenialDiscover sends a browser to the first page it can reach,
	// carrying ?denied=<path>. Preserves the behaviour that predates the
	// denial contract. Default.
	PageDenialDiscover PageDenialMode = "discover"
	// PageDenialForbid renders the 403 error page instead.
	PageDenialForbid PageDenialMode = "forbid"
)
```

Add the field to `HostHandler` next to `proxyTimeouts`:

```go
	pageDenialMode            PageDenialMode
```

And the setter, mirroring `SetProxyTimeouts`:

```go
// SetPageDenialMode replaces the HostHandler's page-denial rendering mode.
// An empty or unrecognised value resolves to PageDenialDiscover.
func (hh *HostHandler) SetPageDenialMode(m PageDenialMode) *HostHandler {
	if m != PageDenialForbid {
		m = PageDenialDiscover
	}
	hh.pageDenialMode = m
	return hh
}
```

**6b.** In `internal/host/page.go`, insert the discovery rendering between the login branch and `denial.Write`:

```go
				// FORBIDDEN has two browser renderings, selected by the
				// knob. Non-HTML callers fall through to the 403 below in
				// BOTH modes: the knob is about presentation, not about the
				// contract.
				//
				// The redirect is bounded to one hop. firstAuthorizedPage
				// can return a page that itself denies -- the navigation
				// walk and the page render are separate checks -- so a
				// request already carrying denied= renders the 403 instead
				// of redirecting again.
				if outcome != denial.Unauthenticated &&
					hh.pageDenialMode != PageDenialForbid &&
					acceptsHTML(r) &&
					!r.URL.Query().Has("denied") {

					first := hh.firstAuthorizedPage(r.Context(), &l, l.String() == hh.defaultLanguage)
					if first != "" {
						if l.String() != hh.defaultLanguage {
							first = "/" + l.String() + first
						}
						// r.URL.Path, not RequestURI: this is a label, never
						// a redirect target, so it needs no SafeReturnPath
						// collapse -- but it IS caller-influenceable, so any
						// consumer that renders it must treat it as text.
						target := first + "?denied=" + url.QueryEscape(r.URL.Path)
						log.V(2).Info("discovery redirect", "to", first, "denied", r.URL.Path)
						// A cached denial follows the user past the grant
						// change that fixed it.
						w.Header().Set("Cache-Control", "no-store")
						http.Redirect(w, r, target, http.StatusSeeOther)
						return
					}
					log.V(2).Info("no accessible page to discover; rendering 403")
				}
```

**6c.** In `cmd/main.go`, declare the flag beside the proxy timeouts (~line 95 for the var, ~line 128 for the flag):

```go
	var pageDenialMode string
```

```go
	flag.StringVar(&pageDenialMode, "page-denial-mode", string(host.PageDenialDiscover),
		"How the page gate renders a denial to a browser: \"discover\" sends the caller to the "+
			"first page they can reach carrying ?denied=<path>; \"forbid\" renders the 403 error "+
			"page. Non-HTML callers receive 403 in both modes.")
```

And wire it at the `SetProxyTimeouts` call site (~line 334):

```go
		SetPageDenialMode(host.PageDenialMode(pageDenialMode)).
```

**6d.** `chart/values.yaml` — add beside the `proxy:` block:

```yaml
# How the page gate renders a denial to a browser. "discover" sends the
# caller to the first page they can reach, carrying ?denied=<path>;
# "forbid" renders the 403 error page. Non-HTML callers receive 403 in
# both modes -- this knob is about presentation, not about the contract.
pageDenialMode: discover
```

**6e.** `chart/templates/deployment.yaml` — add after the `proxy` block:

```yaml
            {{- with .Values.pageDenialMode }}
            - --page-denial-mode={{ . }}
            {{- end }}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestPageGate -v`
Expected: PASS.

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && make test && make lint`
Expected: PASS, `0 issues`. `make lint` also lints the Helm chart.

Verify the chart renders the flag in both settings:

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
helm template t chart/ | grep -- --page-denial-mode
helm template t chart/ --set pageDenialMode=forbid | grep -- --page-denial-mode
```
Expected: `- --page-denial-mode=discover` then `- --page-denial-mode=forbid`.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/types.go internal/host/page.go internal/host/page_denial_test.go internal/host/page_test.go cmd/main.go chart/values.yaml chart/templates/deployment.yaml
git commit -m "feat(host): add --page-denial-mode with an explained, bounded discovery redirect"
```

---

### Task 7: Tell the caller why the sniffer stayed silent

**Files:**
- Modify: `internal/host/feedback.go:254-257`
- Test: `internal/host/feedback_authgate_test.go` (extend)

**Interfaces:**
- Consumes: the `unwrap` allow-list from Task 2 (which already exempts `X-KDex-Sniffer-Suppressed`).
- Produces: nothing new.

The sniffer's 404 is **correct and stays**: the path genuinely does not exist, which is why the sniffer was reached at all. The contract governs denials, never absences, so promoting this to 403 would break the rule in the other direction. What was missing is the reason — recorded only at `V(1)`, where no caller can see it. A response header answers the question the skill documents people asking ("I expected a 303, got 404") without misreporting the status.

- [ ] **Step 1: Write the failing test**

Add a subtest to `TestHostHandler_DesignMiddleware_SnifferAuthGate` in `internal/host/feedback_authgate_test.go`, immediately after the existing *"denies logged-in user without functions:create entitlement"* case and reusing its exact fixture:

```go
	// The 404 is truthful -- the path does not exist, which is why the
	// sniffer was reached at all. But suppression was visible only at V(1),
	// which is why "I expected a 303, got 404" is a documented question.
	// Name the missing entitlement in a header so curl -i answers it,
	// without relabelling an absence as a denial.
	t.Run("names the missing entitlement in a response header", func(t *testing.T) {
		ac := &snifferGateChecker{allow: false}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		ctx = auth.SetAuthContext(ctx, auth.AuthContext{"sub": "alice"})
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"the path really does not exist; the contract governs denials, not absences")
		assert.Equal(t, "functions:create", w.Header().Get("X-KDex-Sniffer-Suppressed"))
	})

	// An anonymous caller is never told which entitlement they lack: they
	// presented no credential, so the header would advertise the gate rather
	// than explain a decision about them.
	t.Run("says nothing to an anonymous caller", func(t *testing.T) {
		ac := &snifferGateChecker{allow: true}
		hh, ctx := newSnifferTestHandler(t, ac)

		req := httptest.NewRequest("GET", "/v2/sniffer", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		hh.DesignMiddleware(nextOK).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Empty(t, w.Header().Get("X-KDex-Sniffer-Suppressed"))
	})
```

The anonymous case matters: `canGenerateSniffer` returns false for an anonymous caller *before* `CheckAccess` runs (the existing test asserts `ac.resource` stays empty), so the header must be set only where a subject was actually evaluated. Guard it accordingly in Step 3.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestSnifferSuppression -v`
Expected: FAIL with `X-KDex-Sniffer-Suppressed = ""`.

- [ ] **Step 3: Write minimal implementation**

In `internal/host/feedback.go`:

```go
		if invokeSniffer && !hh.canGenerateSniffer(r.Context()) {
			log.V(1).Info("sniffer suppressed: caller lacks functions:create entitlement",
				"path", r.URL.Path)
			// The 404 that follows is truthful -- the path does not exist,
			// which is why the sniffer was reached. But suppression was
			// previously visible only at V(1), which is why "I expected a
			// 303, got 404" is a documented question. Name the missing
			// entitlement in a header so curl -i answers it, without
			// relabelling an absence as a denial. unwrap exempts this
			// header from its wipe.
			//
			// Only for a caller whose subject was actually evaluated.
			// canGenerateSniffer refuses an anonymous caller before
			// CheckAccess runs, and naming the entitlement there would
			// advertise the gate rather than explain a decision about them.
			if _, authenticated := auth.GetAuthContext(r.Context()); authenticated {
				w.Header().Set("X-KDex-Sniffer-Suppressed", "functions:create")
			}
			invokeSniffer = false
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/rotty/projects/kdex/workspace/kdex-host-manager && go test ./internal/host/ -run TestSniffer -v`
Expected: PASS.

Then the full gate, from the workspace root:

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager && make test
cd /home/rotty/projects/kdex/workspace && make lint
```
Expected: PASS, `0 issues`.

- [ ] **Step 5: Commit**

```bash
cd /home/rotty/projects/kdex/workspace/kdex-host-manager
git add internal/host/feedback.go internal/host/feedback_authgate_test.go
git commit -m "feat(host): name the missing entitlement when sniffer generation is suppressed"
```

---

## After the tasks

Not part of any task, and not to be done without asking:

- **Release.** host-manager only — no `kdex-crds` change, so no `./updateCrdUsage.sh` and no nexus-manager release. This is a behaviour change to an observable HTTP contract, so it warrants a **minor** bump, not a patch.
- **Verify artifacts rather than inferring from green CI** — `docker manifest inspect` the image and `helm show chart` the chart under `ghcr.io/kdex-tech/charts/host-manager`.
- **Two follow-up issues to file, not fix here.** Both gates treat an authorization check that *errored* as a denial: `internal/host/proxy.go` falls into the contract branch and `internal/host/page.go:42` returns 404. Neither is a denial — an errored check is a server fault, and 500 is arguably the honest answer. The spec deferred this for the proxy; the page gate has the identical arm and the identical argument. File one issue covering both rather than letting either drift into this change.
- **Live confirmation** once deployed: the three probes from the spec's Problem section should return 401 (bearer-only function), 401 + challenge (oauth2 function), and — with `Accept: text/html` — a 401 that *still* carries the challenge.

# Auth Event Hooks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a KDexHost react to auth lifecycle events (login, logout, login-failed, session-refresh) by POSTing to Secret-configured, HMAC-signed HTTP endpoints — advisory (async) or, for login/logout only, enforcing (sync).

**Architecture:** Mirror the existing `httpLookup` backend: a Kubernetes Secret (`kdex.dev/secret-type: http-event-hook`) discovered in the controller yields an `httpEventHook` HTTP client that POSTs an HMAC-signed JSON envelope. An `EventDispatcher` owns the parsed hooks and exposes typed emission methods; it is injected into the `Exchanger` (which owns every emission frame) via `NewExchanger`. Login success is gated pre-mint (enforcing) and notified post-mint (advisory); logout runs a sync barrier that never refuses; login-failed and session-refresh are async only.

**Tech Stack:** Go 1.26.0, `net/http`, `crypto/hmac`+`sha256`, `github.com/golang-jwt/jwt/v5`, `k8s.io/api/core/v1`, controller-runtime, gomega + `net/http/httptest` for tests.

**Spec:** `docs/superpowers/specs/2026-09-11-auth-event-hooks-design.md`

## Global Constraints

- Go version pinned to **1.26.0**; do not change `go.mod`.
- **host-manager only** — no kdex-crds change, no nexus-manager change, no CRD field, no 3-actor release.
- HMAC contract is fixed: `X-K-CNAS-Event-Timestamp: <unix-millis>` and `X-K-CNAS-Event-Signature: hex(hmac-sha256(shared-secret, timestamp + "." + body))`. Reuse the existing package-level `computeSignature` (`internal/auth/lookup_http.go:200-206`) and `minSharedSecretBytes` (`= 32`, `lookup_http.go:24`) — do NOT redefine them.
- Enforcing mode is honored ONLY for `login` and `logout`. For `login-failed`/`session-refresh`, dispatch is always async regardless of the Secret's `mode`.
- Enforcing-login failure default is **fail-closed** (deny); enforcing-logout is a barrier that **never refuses** logout (effectively fail-open).
- Default timeout is **2000 ms** (`defaultEventHookTimeout = 2 * time.Second`).
- Every async call must run on a `context.Background()`-derived context with its own timeout — never the request context — so sending the HTTP response (which cancels the request context) cannot abort an in-flight hook call.
- A host with no `http-event-hook` Secret must behave byte-identically to today: a `nil` `*EventDispatcher` is valid and every method is a no-op (`GateLogin` returns `nil`).
- Follow existing patterns: mirror `lookup_http.go` for the client and `lookup_http_test.go` for tests. Use `gomega` (`. "github.com/onsi/gomega"`) and `logf "sigs.k8s.io/controller-runtime/pkg/log"` as the rest of the package does.

---

## File Structure

- **Create** `internal/auth/event_hook.go` — `EventType`/`HookMode`/`FailureMode` constants, `EventPayload`, `eventHookResponse`, `httpEventHook` + `NewHTTPEventHook` (Secret parse/validate) + `call`. (Task 1)
- **Create** `internal/auth/event_hook_test.go` — client + parsing tests. (Task 1)
- **Create** `internal/auth/event_dispatcher.go` — `EventDispatcher` + `GateLogin`/`NotifyLoginSuccess`/`NotifyLoginFailed`/`Logout`/`NotifySessionRefresh`. (Task 2)
- **Create** `internal/auth/event_dispatcher_test.go` — dispatcher sync/async/failure-mode/multi-hook tests. (Task 2)
- **Modify** `internal/controller/kdexinternalhost_controller.go:~547-580` — discover `http-event-hook` Secrets, build the dispatcher, pass to `NewExchanger`. (Task 3)
- **Modify** `internal/auth/exchange.go` — add `eventDispatcher *EventDispatcher` field (`~44-91`), extend `NewExchanger` (`:221`), add `EmitLogout` helper; emit in `LoginLocal` (`:848-977`), `ExchangeToken` (`:519`), the refresh-grant path, and expose logout emission. (Tasks 3-7)
- **Modify** `internal/host/login.go:128-210` (`LogoutPost`) — call `hh.authExchanger.EmitLogout(...)`. (Task 6)
- **Modify** `docs/` / host-manager README — document the `http-event-hook` Secret. (Task 8)

---

### Task 1: `httpEventHook` client + Secret parsing

**Files:**
- Create: `internal/auth/event_hook.go`
- Test: `internal/auth/event_hook_test.go`

**Interfaces:**
- Consumes: package-level `computeSignature([]byte, string, []byte) string` and `minSharedSecretBytes` from `lookup_http.go`.
- Produces:
  - `type EventType string` with `EventLogin`/`EventLogout`/`EventLoginFailed`/`EventSessionRefresh`
  - `type HookMode string` with `ModeAdvisory`/`ModeEnforcing`
  - `type FailureMode string` with `FailOpen`/`FailClosed` (and `""` = unset)
  - `type EventPayload struct{...}` (fields below)
  - `HTTPEventHookSecretType = "http-event-hook"`
  - `func NewHTTPEventHook(secret corev1.Secret) (*httpEventHook, error)`
  - `func (h *httpEventHook) call(ctx context.Context, payload EventPayload) (ok bool, reason string, err error)`
  - `httpEventHook` fields (unexported, read by the dispatcher in Task 2, same package): `name string`, `events map[EventType]bool`, `mode HookMode`, `failureMode FailureMode`, `timeout time.Duration`.

- [ ] **Step 1: Write the failing test** (`internal/auth/event_hook_test.go`)

```go
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func makeEventHookSecret(name, url string, data map[string]string) corev1.Secret {
	d := map[string][]byte{
		"url":           []byte(url),
		"shared-secret": []byte(strings.Repeat("k", 32)),
	}
	for k, v := range data {
		d[k] = []byte(v)
	}
	return corev1.Secret{
		ObjectMeta: metaObjectMeta(name), // helper: see note below
		Data:       d,
	}
}

func TestNewHTTPEventHook_ParsesAndValidates(t *testing.T) {
	g := NewWithT(t)

	h, err := NewHTTPEventHook(makeEventHookSecret("h1", "https://x.example",
		map[string]string{"events": "login,logout", "mode": "enforcing", "timeout-ms": "1500", "failure-mode": "fail-open"}))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(h.events[EventLogin]).To(BeTrue())
	g.Expect(h.events[EventLogout]).To(BeTrue())
	g.Expect(h.mode).To(Equal(ModeEnforcing))
	g.Expect(h.failureMode).To(Equal(FailOpen))
	g.Expect(h.timeout.Milliseconds()).To(Equal(int64(1500)))
	g.Expect(h.name).To(Equal("h1"))
}

func TestNewHTTPEventHook_Rejects(t *testing.T) {
	g := NewWithT(t)

	// missing url
	_, err := NewHTTPEventHook(corev1.Secret{ObjectMeta: metaObjectMeta("h"), Data: map[string][]byte{"shared-secret": []byte(strings.Repeat("k", 32)), "events": []byte("login")}})
	g.Expect(err).To(MatchError(ContainSubstring("url")))

	// short shared-secret
	_, err = NewHTTPEventHook(corev1.Secret{ObjectMeta: metaObjectMeta("h"), Data: map[string][]byte{"url": []byte("https://x"), "shared-secret": []byte("short"), "events": []byte("login")}})
	g.Expect(err).To(MatchError(ContainSubstring("shared-secret")))

	// empty events
	_, err = NewHTTPEventHook(makeEventHookSecret("h", "https://x", map[string]string{"events": ""}))
	g.Expect(err).To(MatchError(ContainSubstring("events")))

	// unknown event token
	_, err = NewHTTPEventHook(makeEventHookSecret("h", "https://x", map[string]string{"events": "login,bogus"}))
	g.Expect(err).To(MatchError(ContainSubstring("bogus")))
}

func TestHTTPEventHook_Call_SignsAndSendsEnvelope(t *testing.T) {
	g := NewWithT(t)

	var gotSig, gotTs string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-K-CNAS-Event-Signature")
		gotTs = r.Header.Get("X-K-CNAS-Event-Timestamp")
		gotBody, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(eventHookResponse{OK: true})
	}))
	defer srv.Close()

	h, err := NewHTTPEventHook(makeEventHookSecret("h", srv.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	g.Expect(err).ToNot(HaveOccurred())

	ok, _, err := h.call(context.Background(), EventPayload{Event: EventLogin, Subject: "alice"})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeTrue())

	// signature must verify against the shared secret over ts + "." + body
	mac := hmac.New(sha256.New, []byte(strings.Repeat("k", 32)))
	mac.Write([]byte(gotTs))
	mac.Write([]byte("."))
	mac.Write(gotBody)
	g.Expect(gotSig).To(Equal(hex.EncodeToString(mac.Sum(nil))))

	var env EventPayload
	g.Expect(json.Unmarshal(gotBody, &env)).To(Succeed())
	g.Expect(env.Event).To(Equal(EventLogin))
	g.Expect(env.Subject).To(Equal("alice"))
}

func TestHTTPEventHook_Call_OKFalseAndErrors(t *testing.T) {
	g := NewWithT(t)

	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(eventHookResponse{OK: false, Reason: "blocked"})
	}))
	defer deny.Close()
	h, _ := NewHTTPEventHook(makeEventHookSecret("h", deny.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	ok, reason, err := h.call(context.Background(), EventPayload{Event: EventLogin})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ok).To(BeFalse())
	g.Expect(reason).To(Equal("blocked"))

	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer boom.Close()
	h2, _ := NewHTTPEventHook(makeEventHookSecret("h", boom.URL, map[string]string{"events": "login", "mode": "enforcing"}))
	_, _, err = h2.call(context.Background(), EventPayload{Event: EventLogin})
	g.Expect(err).To(HaveOccurred())
}
```

> Note: `metaObjectMeta(name)` is a tiny local helper — add it to the test file:
> ```go
> import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
> func metaObjectMeta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Name: name} }
> ```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run 'HTTPEventHook|NewHTTPEventHook' -v`
Expected: FAIL — `undefined: NewHTTPEventHook` / `EventPayload` / `eventHookResponse`.

- [ ] **Step 3: Write minimal implementation** (`internal/auth/event_hook.go`)

```go
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	HTTPEventHookSecretType = "http-event-hook"
	defaultEventHookTimeout = 2 * time.Second
)

type EventType string

const (
	EventLogin          EventType = "login"
	EventLogout         EventType = "logout"
	EventLoginFailed    EventType = "login-failed"
	EventSessionRefresh EventType = "session-refresh"
)

// enforceableEvents are the only events for which mode=enforcing is honored.
var enforceableEvents = map[EventType]bool{EventLogin: true, EventLogout: true}

func knownEvent(e EventType) bool {
	switch e {
	case EventLogin, EventLogout, EventLoginFailed, EventSessionRefresh:
		return true
	}
	return false
}

type HookMode string

const (
	ModeAdvisory  HookMode = "advisory"
	ModeEnforcing HookMode = "enforcing"
)

type FailureMode string

const (
	FailOpen   FailureMode = "fail-open"
	FailClosed FailureMode = "fail-closed"
)

// EventPayload is the JSON envelope POSTed to a hook. Field presence varies by
// event (see the design spec); omitempty keeps absent context out of the body.
type EventPayload struct {
	Event        EventType      `json:"event"`
	Timestamp    int64          `json:"timestamp"`
	Host         string         `json:"host"`
	Subject      string         `json:"subject"`
	AuthMethod   string         `json:"auth_method,omitempty"`
	ClientID     string         `json:"client_id,omitempty"`
	Scope        string         `json:"scope,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Entitlements []string       `json:"entitlements,omitempty"`
	SessionID    string         `json:"session_id,omitempty"`
	Reason       string         `json:"reason,omitempty"`
}

type eventHookResponse struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

type httpEventHook struct {
	name         string
	url          string
	sharedSecret []byte
	events       map[EventType]bool
	mode         HookMode
	failureMode  FailureMode // "" = unset -> per-event default resolved in the dispatcher
	timeout      time.Duration
	client       *http.Client
}

func NewHTTPEventHook(secret corev1.Secret) (*httpEventHook, error) {
	url := string(secret.Data["url"])
	if url == "" {
		return nil, errors.New("http-event-hook Secret missing required 'url' data field")
	}

	sharedSecret := secret.Data["shared-secret"]
	if len(sharedSecret) < minSharedSecretBytes {
		return nil, fmt.Errorf("http-event-hook Secret 'shared-secret' must be at least %d bytes (got %d)",
			minSharedSecretBytes, len(sharedSecret))
	}

	events := map[EventType]bool{}
	for _, tok := range strings.Split(string(secret.Data["events"]), ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		et := EventType(tok)
		if !knownEvent(et) {
			return nil, fmt.Errorf("http-event-hook Secret 'events' has unknown event %q", tok)
		}
		events[et] = true
	}
	if len(events) == 0 {
		return nil, errors.New("http-event-hook Secret 'events' must list at least one event")
	}

	mode := ModeAdvisory
	if raw := string(secret.Data["mode"]); raw != "" {
		switch HookMode(raw) {
		case ModeAdvisory, ModeEnforcing:
			mode = HookMode(raw)
		default:
			return nil, fmt.Errorf("http-event-hook Secret 'mode' must be advisory or enforcing (got %q)", raw)
		}
	}

	var failureMode FailureMode
	if raw := string(secret.Data["failure-mode"]); raw != "" {
		switch FailureMode(raw) {
		case FailOpen, FailClosed:
			failureMode = FailureMode(raw)
		default:
			return nil, fmt.Errorf("http-event-hook Secret 'failure-mode' must be fail-open or fail-closed (got %q)", raw)
		}
	}

	timeout := defaultEventHookTimeout
	if raw := string(secret.Data["timeout-ms"]); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("http-event-hook Secret 'timeout-ms' is not a valid integer: %w", err)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	return &httpEventHook{
		name:         secret.Name,
		url:          url,
		sharedSecret: sharedSecret,
		events:       events,
		mode:         mode,
		failureMode:  failureMode,
		timeout:      timeout,
		client:       &http.Client{Timeout: timeout},
	}, nil
}

// enforcingFor reports whether this hook enforces (sync-gates) the given event.
// Only login/logout are enforceable; everything else is always advisory.
func (h *httpEventHook) enforcingFor(e EventType) bool {
	return h.mode == ModeEnforcing && enforceableEvents[e]
}

// call POSTs the HMAC-signed envelope and returns the (ok, reason) response.
// A transport/status/decode failure returns a non-nil err; a clean ok=false is
// err==nil with ok==false.
func (h *httpEventHook) call(ctx context.Context, payload EventPayload) (bool, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: marshal: %w", err)
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := computeSignature(h.sharedSecret, ts, body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-K-CNAS-Event-Timestamp", ts)
	req.Header.Set("X-K-CNAS-Event-Signature", sig)

	resp, err := h.client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("httpEventHook: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("httpEventHook: server returned status %d", resp.StatusCode)
	}

	var parsed eventHookResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return false, "", fmt.Errorf("httpEventHook: decode response: %w", err)
	}
	return parsed.OK, parsed.Reason, nil
}

// sortHooksByName gives enforcing evaluation a deterministic order.
func sortHooksByName(hooks []*httpEventHook) {
	sort.Slice(hooks, func(i, j int) bool { return hooks[i].name < hooks[j].name })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run 'HTTPEventHook|NewHTTPEventHook' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/event_hook.go internal/auth/event_hook_test.go
git commit -m "feat(auth): http-event-hook client + Secret parsing"
```

---

### Task 2: `EventDispatcher` (sync/async, failure modes, multi-hook)

**Files:**
- Create: `internal/auth/event_dispatcher.go`
- Test: `internal/auth/event_dispatcher_test.go`

**Interfaces:**
- Consumes: `httpEventHook`, `EventPayload`, `EventType`, `FailOpen`/`FailClosed`, `sortHooksByName`, `enforceableEvents` (Task 1).
- Produces:
  - `func NewEventDispatcher(host string, hooks []*httpEventHook, log logr.Logger) *EventDispatcher`
  - `func (d *EventDispatcher) GateLogin(ctx context.Context, p EventPayload) error` — nil-safe; runs enforcing-login hooks sequentially in name order, short-circuits on first deny; returns a non-nil error on deny or fail-closed transport error. Returns nil when `d` is nil or no enforcing-login hooks exist.
  - `func (d *EventDispatcher) NotifyLoginSuccess(ctx context.Context, p EventPayload)` — async advisory-login hooks.
  - `func (d *EventDispatcher) NotifyLoginFailed(ctx context.Context, p EventPayload)` — async, all login-failed hooks.
  - `func (d *EventDispatcher) Logout(ctx context.Context, p EventPayload)` — enforcing-logout barriers (sync, never refuse) then advisory-logout async.
  - `func (d *EventDispatcher) NotifySessionRefresh(ctx context.Context, p EventPayload)` — async, all session-refresh hooks.
  - Sentinel: `var ErrLoginHookDenied = errors.New("login denied by event hook")`.

- [ ] **Step 1: Write the failing test** (`internal/auth/event_dispatcher_test.go`)

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

func hookTo(t *testing.T, name, url, events, mode string, extra map[string]string) *httpEventHook {
	t.Helper()
	d := map[string]string{"events": events, "mode": mode}
	for k, v := range extra {
		d[k] = v
	}
	h, err := NewHTTPEventHook(makeEventHookSecret(name, url, d))
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	return h
}

func TestGateLogin_NilDispatcherAllows(t *testing.T) {
	g := NewWithT(t)
	var d *EventDispatcher
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestGateLogin_DenyShortCircuitsInNameOrder(t *testing.T) {
	g := NewWithT(t)
	var bHit atomic.Bool
	// "a" denies; "b" must never be called (name order, short-circuit).
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"nope"}`))
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		bHit.Store(true)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer b.Close()

	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "b", b.URL, "login", "enforcing", nil),
		hookTo(t, "a", a.URL, "login", "enforcing", nil),
	}, logr.Discard())

	err := d.GateLogin(context.Background(), EventPayload{Event: EventLogin, Subject: "x"})
	g.Expect(err).To(MatchError(ContainSubstring("nope")))
	g.Expect(bHit.Load()).To(BeFalse())
}

func TestGateLogin_TimeoutFailClosedByDefault(t *testing.T) {
	g := NewWithT(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "login", "enforcing", map[string]string{"timeout-ms": "10"}),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(HaveOccurred())
}

func TestGateLogin_TimeoutFailOpenWhenConfigured(t *testing.T) {
	g := NewWithT(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "login", "enforcing", map[string]string{"timeout-ms": "10", "failure-mode": "fail-open"}),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestGateLogin_IgnoresAdvisoryHooks(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Bool
	adv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Store(true)
		_, _ = w.Write([]byte(`{"ok":false,"reason":"should not gate"}`))
	}))
	defer adv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", adv.URL, "login", "advisory", nil),
	}, logr.Discard())
	// advisory login hook must not gate; GateLogin sees no enforcing hooks.
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
}

func TestNotify_AsyncFireAndForget(t *testing.T) {
	g := NewWithT(t)
	var count atomic.Int32
	done := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "login-failed", "advisory", nil),
		hookTo(t, "b", srv.URL, "login-failed", "advisory", nil),
	}, logr.Discard())

	d.NotifyLoginFailed(context.Background(), EventPayload{Event: EventLoginFailed, Reason: "bad"})
	for i := 0; i < 2; i++ {
		g.Eventually(done, "2s").Should(Receive())
	}
	g.Expect(count.Load()).To(Equal(int32(2)))
}

func TestLogout_BarrierNeverRefuses(t *testing.T) {
	g := NewWithT(t)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":false,"reason":"try to refuse"}`)) // must be ignored
	}))
	defer slow.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", slow.URL, "logout", "enforcing", map[string]string{"timeout-ms": "5"}),
	}, logr.Discard())
	// Logout returns nothing and never blocks the caller from logging out.
	d.Logout(context.Background(), EventPayload{Event: EventLogout, Subject: "x"})
}

func TestGateLogin_MultipleEnforcingAllPass(t *testing.T) {
	g := NewWithT(t)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ok.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", ok.URL, "login", "enforcing", nil),
		hookTo(t, "b", ok.URL, "login", "enforcing", nil),
	}, logr.Discard())
	g.Expect(d.GateLogin(context.Background(), EventPayload{Event: EventLogin})).To(Succeed())
	_ = strings.TrimSpace // keep imports stable if edited
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run 'GateLogin|Notify|Logout_Barrier' -v`
Expected: FAIL — `undefined: NewEventDispatcher`.

- [ ] **Step 3: Write minimal implementation** (`internal/auth/event_dispatcher.go`)

```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
)

// ErrLoginHookDenied is returned by GateLogin when an enforcing login hook
// denies the login (ok=false, or a fail-closed transport failure).
var ErrLoginHookDenied = errors.New("login denied by event hook")

// EventDispatcher owns the parsed hooks for one host and emits lifecycle events.
// A nil *EventDispatcher is valid: every method is a no-op (GateLogin allows).
type EventDispatcher struct {
	host  string
	hooks []*httpEventHook // sorted by name
	log   logr.Logger
}

func NewEventDispatcher(host string, hooks []*httpEventHook, log logr.Logger) *EventDispatcher {
	sortHooksByName(hooks)
	return &EventDispatcher{host: host, hooks: hooks, log: log}
}

// bgTimeout derives a background context bounded by the hook's own timeout, so
// neither the request's cancellation nor a slow hook can hang or abort work.
func bgTimeout(h *httpEventHook) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), h.timeout)
}

func (d *EventDispatcher) selecting(e EventType, enforcing bool) []*httpEventHook {
	var out []*httpEventHook
	for _, h := range d.hooks {
		if !h.events[e] {
			continue
		}
		if enforcing != h.enforcingFor(e) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// GateLogin runs the enforcing login hooks in name order and denies on the first
// ok=false (or, per failure-mode, a transport error). Nil-safe.
func (d *EventDispatcher) GateLogin(ctx context.Context, p EventPayload) error {
	if d == nil {
		return nil
	}
	p.Host = d.host
	p.Timestamp = time.Now().UnixMilli()
	for _, h := range d.selecting(EventLogin, true) {
		cctx, cancel := bgTimeout(h)
		ok, reason, err := h.call(cctx, p)
		cancel()
		if err != nil {
			// login default is fail-closed; only an explicit fail-open allows.
			if h.failureMode == FailOpen {
				d.log.Error(err, "enforcing login hook errored; failing open", "hook", h.name)
				continue
			}
			d.log.Error(err, "enforcing login hook errored; failing closed", "hook", h.name)
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, "hook unavailable")
		}
		if !ok {
			if reason == "" {
				reason = "denied"
			}
			return fmt.Errorf("%w: %s", ErrLoginHookDenied, reason)
		}
	}
	return nil
}

func (d *EventDispatcher) fireAsync(p EventPayload, hooks []*httpEventHook) {
	for _, h := range hooks {
		h := h
		go func() {
			cctx, cancel := bgTimeout(h)
			defer cancel()
			if _, _, err := h.call(cctx, p); err != nil {
				d.log.Error(err, "async event hook failed", "hook", h.name, "event", string(p.Event))
			}
		}()
	}
}

func (d *EventDispatcher) NotifyLoginSuccess(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	d.fireAsync(p, d.selecting(EventLogin, false))
}

func (d *EventDispatcher) NotifyLoginFailed(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	// login-failed is async-only, so both advisory and (ignored) enforcing hooks
	// that subscribe to it fire async: select every hook subscribed to the event.
	var all []*httpEventHook
	for _, h := range d.hooks {
		if h.events[EventLoginFailed] {
			all = append(all, h)
		}
	}
	d.fireAsync(p, all)
}

func (d *EventDispatcher) NotifySessionRefresh(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	var all []*httpEventHook
	for _, h := range d.hooks {
		if h.events[EventSessionRefresh] {
			all = append(all, h)
		}
	}
	d.fireAsync(p, all)
}

// Logout runs enforcing-logout hooks as sequential barriers (blocking up to each
// hook's timeout) but NEVER refuses the logout, then fires advisory-logout hooks
// async. Nil-safe.
func (d *EventDispatcher) Logout(ctx context.Context, p EventPayload) {
	if d == nil {
		return
	}
	p.Host, p.Timestamp = d.host, time.Now().UnixMilli()
	for _, h := range d.selecting(EventLogout, true) {
		cctx, cancel := bgTimeout(h)
		if _, _, err := h.call(cctx, p); err != nil {
			d.log.Error(err, "enforcing logout barrier failed; proceeding with logout", "hook", h.name)
		}
		cancel()
	}
	d.fireAsync(p, d.selecting(EventLogout, false))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/auth/ -run 'GateLogin|Notify|Logout_Barrier' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/event_dispatcher.go internal/auth/event_dispatcher_test.go
git commit -m "feat(auth): EventDispatcher (sync gate, async notify, logout barrier)"
```

---

### Task 3: Wire the dispatcher (controller discovery + Exchanger injection)

**Files:**
- Modify: `internal/auth/exchange.go` (struct `~44-91`, `NewExchanger` `:221`)
- Modify: `internal/controller/kdexinternalhost_controller.go` (`~547-580`)
- Test: `internal/auth/exchange_eventhook_test.go` (new — constructor wiring)

**Interfaces:**
- Consumes: `NewEventDispatcher`, `NewHTTPEventHook`, `httpEventHook`, `HTTPEventHookSecretType` (Tasks 1-2).
- Produces:
  - `Exchanger.eventDispatcher *EventDispatcher` (unexported field)
  - `NewExchanger(ctx, config, cacheManager, sp, dispatcher *EventDispatcher)` — new trailing parameter.
  - `func (e *Exchanger) EmitLogout(ctx context.Context, refreshTokenID, idToken string)` (implemented in Task 6; declared here so wiring compiles — start as a call into `d.Logout` with subject "" and fill in Task 6).

- [ ] **Step 1: Write the failing test** (`internal/auth/exchange_eventhook_test.go`)

```go
package auth

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

// NewExchanger must accept and retain an EventDispatcher (nil is allowed).
func TestNewExchanger_AcceptsEventDispatcher(t *testing.T) {
	g := NewWithT(t)
	d := NewEventDispatcher("h", nil, logr.Discard())
	ex, err := NewExchanger(context.Background(), Config{}, nil, nil, d)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ex).ToNot(BeNil())
	g.Expect(ex.eventDispatcher).To(Equal(d))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestNewExchanger_AcceptsEventDispatcher -v`
Expected: FAIL — `too many arguments in call to NewExchanger` / `ex.eventDispatcher undefined`.

- [ ] **Step 3: Write minimal implementation**

In `internal/auth/exchange.go`, add the field to the `Exchanger` struct (after `sp InternalIdentityProvider`, `~:90`):

```go
	sp              InternalIdentityProvider
	eventDispatcher *EventDispatcher
```

Extend `NewExchanger` (`:221`) — add the trailing parameter and set the field on the returned `*Exchanger` (find the `&Exchanger{...}` literal in the constructor and add `eventDispatcher: dispatcher,`):

```go
func NewExchanger(
	ctx context.Context,
	config Config,
	cacheManager cache.Manager, // keep the existing parameter type/name
	sp InternalIdentityProvider,
	dispatcher *EventDispatcher,
) (*Exchanger, error) {
	// ... existing body ...
	// in the &Exchanger{ ... } literal add:
	//     eventDispatcher: dispatcher,
}
```

> Confirm the exact existing parameter names/types of `NewExchanger` at `exchange.go:221` and the field names in the `&Exchanger{...}` literal; add the new param last and the field assignment alongside `sp`.

Add a stub `EmitLogout` (filled in Task 6) so the package compiles:

```go
// EmitLogout dispatches the logout event. Subject/claims are recovered in Task 6.
func (e *Exchanger) EmitLogout(ctx context.Context, refreshTokenID, idToken string) {
	if e == nil {
		return
	}
	e.eventDispatcher.Logout(ctx, EventPayload{Event: EventLogout})
}
```

In `internal/controller/kdexinternalhost_controller.go`, after the `httpLookupSecret` block (`~:557`) and before `NewRoleProvider`, discover event-hook Secrets and build the dispatcher; pass it as the new last arg to `NewExchanger` (`~:576`):

```go
	var eventHooks []*auth.httpEventHook // NOTE: httpEventHook is unexported; expose a slice type or a builder — see step note
	for _, s := range secrets.FindAll(func(s corev1.Secret) bool {
		return s.Annotations["kdex.dev/secret-type"] == auth.HTTPEventHookSecretType &&
			s.Annotations["kdex.dev/active-key"] == "true"
	}) {
		h, err := auth.NewHTTPEventHook(s)
		if err != nil {
			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}
		eventHooks = append(eventHooks, h)
	}
	eventDispatcher := auth.NewEventDispatcher(internalHost.Name, eventHooks, logf.FromContext(ctx))

	// ... NewRoleProvider unchanged ...

	authExchanger, err := auth.NewExchanger(ctx, *authConfig, r.HostHandler.GetCacheManager(), rp, eventDispatcher)
```

> **Two adjustments to confirm while implementing:**
> 1. `httpEventHook` is unexported, so the controller (a different package) cannot name `[]*auth.httpEventHook`. Add an exported constructor-collector in package `auth` instead: `func NewEventDispatcherFromSecrets(host string, secrets []corev1.Secret, log logr.Logger) (*EventDispatcher, error)` that filters by annotation, calls `NewHTTPEventHook`, and returns the dispatcher (or the first parse error). Call THAT from the controller and drop the `[]*auth.httpEventHook` local. Add a unit test for it in `event_dispatcher_test.go`.
> 2. Confirm `secrets` exposes a multi-match helper; if only `Find` (single) exists (see `kdexinternalhost_controller.go:547`), iterate `secrets` directly or add a `FindAll`. Prefer moving the whole loop into `NewEventDispatcherFromSecrets` so the controller just passes the `secrets` collection.

Revised exported API (implement this shape):

```go
// in event_dispatcher.go
func NewEventDispatcherFromSecrets(host string, secrets []corev1.Secret, log logr.Logger) (*EventDispatcher, error) {
	var hooks []*httpEventHook
	for _, s := range secrets {
		if s.Annotations["kdex.dev/secret-type"] != HTTPEventHookSecretType ||
			s.Annotations["kdex.dev/active-key"] != "true" {
			continue
		}
		h, err := NewHTTPEventHook(s)
		if err != nil {
			return nil, err
		}
		hooks = append(hooks, h)
	}
	return NewEventDispatcher(host, hooks, log), nil
}
```

Then the controller is just:

```go
	eventDispatcher, err := auth.NewEventDispatcherFromSecrets(internalHost.Name, secrets.Items(), logf.FromContext(ctx))
	if err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}
```

> Confirm how to get a `[]corev1.Secret` slice from the `secrets` collection (`.Items()` or the underlying field) at `kdexinternalhost_controller.go:543`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run 'TestNewExchanger_AcceptsEventDispatcher|NewEventDispatcherFromSecrets' -v && go build ./...`
Expected: PASS + build clean (controller compiles with the new call).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/exchange.go internal/auth/event_dispatcher.go internal/auth/event_dispatcher_test.go internal/auth/exchange_eventhook_test.go internal/controller/kdexinternalhost_controller.go
git commit -m "feat(auth): inject EventDispatcher into Exchanger + controller discovery"
```

---

### Task 4: Emit login events from `LoginLocal`

**Files:**
- Modify: `internal/auth/exchange.go` — `LoginLocal` (`:848-977`)
- Test: `internal/auth/exchange_login_events_test.go` (new)

**Interfaces:**
- Consumes: `Exchanger.eventDispatcher`, `GateLogin`, `NotifyLoginSuccess`, `NotifyLoginFailed`, `EventPayload`, `EventLogin`, `EventLoginFailed` (Tasks 1-3).
- Produces: no new exported symbols; behavior only.

Payload builder — add near `LoginLocal` (extracts roles/entitlements/claims from the `signingContext jwt.MapClaims`):

```go
func loginPayload(event EventType, signingContext jwt.MapClaims, subject, clientID, scope, authMethod string) EventPayload {
	p := EventPayload{
		Event:      event,
		Subject:    subject,
		ClientID:   clientID,
		Scope:      scope,
		AuthMethod: authMethod,
		Claims:     map[string]any{},
	}
	for k, v := range signingContext {
		switch k {
		case "roles":
			p.Roles = toStringSlice(v)
		case "entitlements":
			p.Entitlements = toStringSlice(v)
		default:
			p.Claims[k] = v
		}
	}
	return p
}

// toStringSlice coerces a claim value ([]any after JSON, []string in-process).
func toStringSlice(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
```

Emission points inside `LoginLocal`:
- **Credential-failure path** (`:878`, the `return TokenSet{}, err` after `FindInternal`): before returning, fire `NotifyLoginFailed` with subject=`username`, reason=`err.Error()`.
- **Gate** — after `grantedScopeStr` is computed (`:938`) and BEFORE `SignScoped` (`:940`): call `GateLogin`; on error emit `NotifyLoginFailed` and return a login failure.
- **Success** — after the refresh-token block (`:974`), before `return ts, nil` (`:976`): `NotifyLoginSuccess`.

Concrete inserts:

```go
// at the credential-failure return (~:878), replace `return TokenSet{}, err` with:
	e.eventDispatcher.NotifyLoginFailed(ctx, EventPayload{
		Event: EventLoginFailed, Subject: username, AuthMethod: string(authMethod), Reason: err.Error(),
	})
	return TokenSet{}, err
```

```go
// after grantedScopeStr (~:938), before SignScoped (~:940):
	if gerr := e.eventDispatcher.GateLogin(ctx, loginPayload(EventLogin, signingContext, username, clientID, grantedScopeStr, string(authMethod))); gerr != nil {
		e.eventDispatcher.NotifyLoginFailed(ctx, EventPayload{
			Event: EventLoginFailed, Subject: username, AuthMethod: string(authMethod), Reason: gerr.Error(),
		})
		return failed("%w: %v", ErrAccessDenied, gerr) // confirm the right client-facing sentinel (see note)
	}
```

```go
// just before `return ts, nil` (~:976):
	e.eventDispatcher.NotifyLoginSuccess(ctx, loginPayload(EventLogin, signingContext, username, clientID, grantedScopeStr, string(authMethod)))
	return ts, nil
```

> **Confirm the deny sentinel:** the design says an enforcing deny is a client-visible refusal, not a 500. Check the sentinels in `exchange.go`/`oautherr.go` (e.g. `ErrAccessDenied`/`ErrInvalidGrant`) and use the one that maps to a 4xx `access_denied`/`invalid_grant`, NOT `ErrServerError`. Mirror how `failed(...)` composes errors here.

- [ ] **Step 1: Write the failing test** (`internal/auth/exchange_login_events_test.go`)

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

// buildTestExchanger wires an Exchanger with a stub identity provider that
// returns a fixed signingContext, and the given dispatcher. Reuse the package's
// existing test helpers for Config/Signer (see exchange_*_test.go) — this sketch
// names the moving parts the test needs.
func TestLoginLocal_EnforcingDenyBlocksLogin(t *testing.T) {
	g := NewWithT(t)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"risk"}`))
	}))
	defer deny.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", deny.URL, "login", "enforcing", nil),
	}, logr.Discard())

	ex := newLoginTestExchanger(t, d) // helper: Config+Signer+stub sp resolving sub=alice
	_, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).To(MatchError(ContainSubstring("risk")))
}

func TestLoginLocal_AdvisoryFiresSuccess(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Int32
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "login", "advisory", nil),
	}, logr.Discard())

	ex := newLoginTestExchanger(t, d)
	_, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(done, "2s").Should(Receive())
	g.Expect(hit.Load()).To(Equal(int32(1)))
	_ = time.Now
}
```

> Implement `newLoginTestExchanger(t, d)` by copying the Config/Signer/stub-`sp` setup from an existing `LoginLocal` test (search `exchange_*_test.go` for tests calling `LoginLocal` and reuse their fixtures); the only addition is passing `d` as the dispatcher.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run 'LoginLocal_Enforcing|LoginLocal_Advisory' -v`
Expected: FAIL (deny not enforced / success not emitted) before the inserts.

- [ ] **Step 3: Write minimal implementation** — apply the three inserts + `loginPayload`/`toStringSlice` above.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run 'LoginLocal' -v`
Expected: PASS (new + existing LoginLocal tests).

- [ ] **Step 5: Commit**

```bash
git add internal/auth/exchange.go internal/auth/exchange_login_events_test.go
git commit -m "feat(auth): emit login gate/success/failed events from LoginLocal"
```

---

### Task 5: Emit login events from the OIDC path (`ExchangeToken`)

**Files:**
- Modify: `internal/auth/exchange.go` — `ExchangeToken` (`:519`)
- Test: `internal/auth/exchange_oidc_events_test.go` (new)

**Interfaces:**
- Consumes: same dispatcher methods + `loginPayload` (Task 4).

- [ ] **Step 1: Write the failing test**

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

func TestExchangeToken_EnforcingDenyBlocksOIDCLogin(t *testing.T) {
	g := NewWithT(t)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"oidc-risk"}`))
	}))
	defer deny.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", deny.URL, "login", "enforcing", nil),
	}, logr.Discard())

	ex := newOIDCTestExchanger(t, d) // helper mirroring existing ExchangeToken tests
	_, err := ex.ExchangeToken(context.Background(), sampleOIDCExchange(t)) // reuse existing fixture
	g.Expect(err).To(MatchError(ContainSubstring("oidc-risk")))
}
```

> Reuse the existing `ExchangeToken` test fixtures (search `exchange_*_test.go` for `ExchangeToken(` and copy the `OIDCExchange`/verifier/Config setup into `newOIDCTestExchanger`/`sampleOIDCExchange`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestExchangeToken_EnforcingDeny -v`
Expected: FAIL (deny not enforced) before the insert.

- [ ] **Step 3: Write minimal implementation** — in `ExchangeToken` (`:519`), after the local signing context / subject and granted scope are established and BEFORE the local tokens are minted, insert the same gate; emit `NotifyLoginSuccess` just before the successful `return`, and `NotifyLoginFailed` on the pre-mint failure paths. Use `auth_method = "oidc"` (confirm the enum: `AuthMethodOAuth2`/an OIDC value in this frame). Build the payload from the local signing context the same way `LoginLocal` does.

```go
	// after subject + grantedScopeStr known, before minting local tokens:
	if gerr := e.eventDispatcher.GateLogin(ctx, loginPayload(EventLogin, signingContext, subject, clientID, grantedScopeStr, authMethodStr)); gerr != nil {
		e.eventDispatcher.NotifyLoginFailed(ctx, EventPayload{Event: EventLoginFailed, Subject: subject, AuthMethod: authMethodStr, Reason: gerr.Error()})
		return TokenSet{}, fmt.Errorf("%w: %v", ErrAccessDenied, gerr) // same sentinel as Task 4
	}
	// ... mint ...
	// before returning the successful TokenSet:
	e.eventDispatcher.NotifyLoginSuccess(ctx, loginPayload(EventLogin, signingContext, subject, clientID, grantedScopeStr, authMethodStr))
```

> Confirm the actual local variable names in `ExchangeToken` (the signing-context map, subject, clientID, granted-scope string, auth-method) and bind the payload to them; the shape matches `LoginLocal`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run 'ExchangeToken' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/exchange.go internal/auth/exchange_oidc_events_test.go
git commit -m "feat(auth): emit login events from OIDC ExchangeToken path"
```

---

### Task 6: Emit logout event (barrier) from `LogoutPost`

**Files:**
- Modify: `internal/auth/exchange.go` — finish `EmitLogout` (stubbed in Task 3), reuse the refresh-claims decode used by `RevokeRefreshToken` (`:679`).
- Modify: `internal/host/login.go` — `LogoutPost` (`:128-210`), call `EmitLogout`.
- Test: `internal/auth/exchange_logout_events_test.go` (new)

**Interfaces:**
- Consumes: `Exchanger.eventDispatcher.Logout`, the refresh-token cache/claims decode path.
- Produces: `EmitLogout(ctx, refreshTokenID, idToken string)` recovers `subject`/`clientID`/`scope`/`auth_method` best-effort from the refresh token's `RefreshTokenClaims` (`exchange.go:148`) and dispatches an `EventLogout`.

- [ ] **Step 1: Write the failing test**

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

func TestEmitLogout_FiresLogoutEvent(t *testing.T) {
	g := NewWithT(t)
	var gotSubject atomic.Value
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p EventPayload
		_ = decodeJSON(r, &p) // small test helper: json.NewDecoder(r.Body).Decode
		gotSubject.Store(p.Event)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "logout", "advisory", nil),
	}, logr.Discard())

	ex := newLogoutTestExchanger(t, d) // Config+cache; may store a refresh token to decode
	ex.EmitLogout(context.Background(), "", "") // no token -> subject "" still fires
	g.Eventually(done, "2s").Should(Receive())
	g.Expect(gotSubject.Load()).To(Equal(EventLogout))
}
```

> `decodeJSON` and `newLogoutTestExchanger` are small local helpers; the latter can reuse the Config/cache fixtures from existing `RevokeRefreshToken` tests (search `exchange_*_test.go`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestEmitLogout_FiresLogoutEvent -v`
Expected: FAIL (stub `EmitLogout` doesn't set the event / no fixture) — implement, then pass.

- [ ] **Step 3: Write minimal implementation**

Finish `EmitLogout` in `exchange.go` — decode the refresh token's claims best-effort (reuse whatever `RevokeRefreshToken` uses to read the cached `RefreshTokenClaims` by `tokenID`); populate the payload and dispatch:

```go
func (e *Exchanger) EmitLogout(ctx context.Context, refreshTokenID, idToken string) {
	if e == nil {
		return
	}
	p := EventPayload{Event: EventLogout}
	if refreshTokenID != "" {
		if claims, ok := e.lookupRefreshClaims(ctx, refreshTokenID); ok { // reuse RevokeRefreshToken's read
			p.Subject = claims.Subject
			p.ClientID = claims.ClientID
			p.Scope = claims.Scope
			p.AuthMethod = string(claims.AuthMethod)
			p.SessionID = refreshTokenID
		}
	}
	e.eventDispatcher.Logout(ctx, p)
}
```

> Implement `lookupRefreshClaims` (or inline it) by factoring the cache read that `RevokeRefreshToken` (`:679`) already performs to obtain `RefreshTokenClaims`; do not duplicate cache-key logic — call the same helper. If no such helper exists, extract one and have both call it.

In `internal/host/login.go` `LogoutPost`, at the refresh-cookie block (`:146-152`), call `EmitLogout` (barrier) before clearing cookies:

```go
	if hh.authConfig != nil && hh.authExchanger != nil {
		if c, err := r.Cookie("_refresh"); err == nil && c.Value != "" {
			hh.authExchanger.EmitLogout(r.Context(), c.Value, idTokenForLogout) // idToken if already read; else ""
			_ = hh.authExchanger.RevokeRefreshToken(r.Context(), c.Value)
		} else {
			hh.authExchanger.EmitLogout(r.Context(), "", "") // still fire logout with empty subject
		}
	}
```

> Confirm the existing structure at `login.go:146-152`; keep `RevokeRefreshToken` exactly as-is and add the `EmitLogout` call. Fire logout even when there is no `_refresh` cookie (empty subject), per spec. The barrier blocks here up to the hook timeout; that is intended.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ ./internal/host/ -run 'EmitLogout|Logout' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/exchange.go internal/host/login.go internal/auth/exchange_logout_events_test.go
git commit -m "feat(auth): emit logout event (barrier) from LogoutPost"
```

---

### Task 7: Emit `session-refresh` (async) on the refresh-token grant

**Files:**
- Modify: `internal/auth/exchange.go` — the refresh-token grant path (the method that issues a new access token from a refresh token; per the map ~`:560`/`:1454`, reachable via `FindInternalRolesAndEntitlements`).
- Test: `internal/auth/exchange_refresh_events_test.go` (new)

**Interfaces:**
- Consumes: `NotifySessionRefresh`, `EventPayload`, `EventSessionRefresh`.

- [ ] **Step 1: Write the failing test**

```go
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/gomega"
)

func TestRefreshGrant_FiresSessionRefresh(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Int32
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "session-refresh", "advisory", nil),
	}, logr.Discard())

	ex := newRefreshTestExchanger(t, d) // reuse existing refresh-grant fixtures
	_, err := ex.doRefreshGrant(t) // call the actual refresh method with a valid stored refresh token
	g.Expect(err).ToNot(HaveOccurred())
	g.Eventually(done, "2s").Should(Receive())
	g.Expect(hit.Load()).To(Equal(int32(1)))
}
```

> Bind `newRefreshTestExchanger`/`doRefreshGrant` to the real refresh method name and fixtures (search `exchange_*_test.go` for the existing refresh-grant tests and reuse their setup; `doRefreshGrant` is a stand-in for that method).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -run TestRefreshGrant_FiresSessionRefresh -v`
Expected: FAIL before the insert.

- [ ] **Step 3: Write minimal implementation** — in the refresh-grant method, after the new token set is successfully minted and before returning, fire async:

```go
	e.eventDispatcher.NotifySessionRefresh(ctx, EventPayload{
		Event:      EventSessionRefresh,
		Subject:    refreshClaims.Subject,
		ClientID:   refreshClaims.ClientID,
		Scope:      newScopeStr,
		AuthMethod: string(refreshClaims.AuthMethod),
		SessionID:  newRefreshTokenID, // if rotation issues a new id; else the presented one
	})
```

> Bind to the method's actual locals (the decoded `RefreshTokenClaims`, the granted scope string, and the refresh token id). Emit only on success.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/ -run 'Refresh' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/exchange.go internal/auth/exchange_refresh_events_test.go
git commit -m "feat(auth): emit session-refresh event on the refresh grant"
```

---

### Task 8: Docs + full verify + release v0.14.0

**Files:**
- Modify: host-manager README / package docs (document the `http-event-hook` Secret).
- No CRD, no nexus.

- [ ] **Step 1: Document the Secret**

Add a section to the host-manager docs describing the `http-event-hook` Secret: annotations (`kdex.dev/secret-type: http-event-hook`, `kdex.dev/active-key: "true"`), the data keys table from the spec (`url`, `shared-secret`, `events`, `mode`, `timeout-ms`, `failure-mode`), the HMAC header contract (`X-K-CNAS-Event-Timestamp`/`-Signature`), the request envelope, the `{ok, reason}` response (enforcing login only), and the enforcing/advisory + fail-open/closed semantics. Mirror the prose style of the `http-lookup-auth` block in `kdex-crds/api/v1alpha1/kdexhost_types.go:190-245`. (The parallel prose block in kdex-crds is an optional follow-up, kept out of this host-only change.)

- [ ] **Step 2: Full test + lint**

Run: `make test lint`
Expected: exit 0; helm lint + golangci-lint clean.

- [ ] **Step 3: Commit docs**

```bash
git add README.md docs/
git commit -m "docs: document the http-event-hook Secret"
```

- [ ] **Step 4: Push + tag the release**

```bash
git push origin main
git tag -a v0.14.0 -m "v0.14.0"
git push origin v0.14.0
```

- [ ] **Step 5: Verify CI**

Run: `gh run list -R kdex-tech/host-manager -L 3`
Expected: the `v0.14.0` tag run and the `main` run both start and go green (image + Helm chart published).

---

## Self-Review

**Spec coverage:**
- Secret config surface (all keys, validation) → Task 1. ✓
- Advisory/enforcing + fail-open/closed + timeouts → Task 2. ✓
- Events × modes (login/logout enforceable; failed/refresh async-only) → Tasks 1 (enforceability), 2 (dispatch), 4-7 (emission). ✓
- Request contract + HMAC + envelope → Task 1. ✓
- Response contract (enforcing login only) → Tasks 1-2. ✓
- Emission frames (LoginLocal, OIDC ExchangeToken, refresh, logout) → Tasks 4, 5, 7, 6. ✓
- Multiple-hook semantics (async fan-out; enforcing sequential AND by name) → Task 2. ✓
- Logout barrier never refuses + best-effort subject decode → Tasks 2, 6. ✓
- host-only, no CRD/nexus, v0.14.0 → Task 8. ✓

**Placeholder scan:** Emission tasks (4-7) intentionally include "confirm the exact local variable names" notes because they modify existing functions the executor must read; every insert ships real code, not "add handling here." No TBD/TODO.

**Type consistency:** `EventPayload`, `EventType` values, `httpEventHook`, `EventDispatcher` methods (`GateLogin`/`NotifyLoginSuccess`/`NotifyLoginFailed`/`Logout`/`NotifySessionRefresh`), `NewEventDispatcher`/`NewEventDispatcherFromSecrets`, `ErrLoginHookDenied`, `loginPayload`/`toStringSlice`, and the `NewExchanger` extra param are named identically across tasks.

**Known follow-through for the executor (not placeholders — verifications against existing code):**
1. `NewExchanger`'s exact existing parameter list at `exchange.go:221` (add the dispatcher last).
2. The client-facing deny sentinel (4xx `access_denied`/`invalid_grant`, not `ErrServerError`) in Tasks 4-5.
3. The refresh-claims cache read helper reused by `EmitLogout` (Task 6) and the refresh-grant method name (Task 7).
4. How to obtain `[]corev1.Secret` from the controller's `secrets` collection (Task 3).

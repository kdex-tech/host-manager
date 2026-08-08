# Streaming Deadlines & OAuth Token Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three host-manager defects for v0.5.0 — streaming responses severed at 60s (#167), a token endpoint that cannot signal `invalid_grant` (#168), and refresh rotation that fails every concurrent caller but one (#169).

**Architecture:** #167 adds a `ResponseWriter` wrapper that adjusts the *per-request* write deadline via `http.ResponseController`, plus chart-configurable `server.*` timeouts mirroring the existing `proxy.*` block. #168 introduces a `writeOAuthError` helper and an `ErrServerError` sentinel so RFC 6749 §5.2 codes reach clients without conflating infrastructure failures with dead grants. #169 keeps the atomic single-winner `GetAndDelete` untouched and adds a short-lived cache that *replays the winner's minted result* to concurrent losers.

**Tech Stack:** Go 1.26.0, `net/http` + `httputil.ReverseProxy`, `github.com/stretchr/testify`, Helm chart under `chart/`, internal `cache.Cache` abstraction (in-memory and Valkey backends).

**Spec:** `docs/superpowers/specs/2026-08-08-streaming-deadlines-and-oauth-conformance-design.md`

## Global Constraints

- **Go version is pinned to 1.26.0** (`go.mod`). Do not change it.
- **No CRD changes.** Nothing in this plan touches `kdex-crds`. Do not run `./updateCrdUsage.sh`, and do not add fields to `KDexHost.spec.auth` — the refresh grace window is a binary flag, deliberately, so nexus-manager does not need a paired release.
- **Chart version is derived from the git tag** by `.github/actions/publish-helm-chart` (`refs/tags/vX.Y.Z` → `X.Y.Z`). Do **not** hand-edit `chart/Chart.yaml`'s `version` or `appVersion`; they stay at `0.0.1` in-repo.
- **One Kubernetes resource per YAML file, 2-space YAML indentation** (workspace convention).
- **Use `rg`, not `grep`,** for searching.
- **Run `make lint` and `make test` from inside `kdex-host-manager/`** before each commit that touches Go code. `make test` runs `manifests generate fmt vet setup-envtest` first; `make lint` runs `golangci-lint` plus `helm lint ./chart`.
- **Branch:** all work lands on `feat/streaming-deadlines-oauth-conformance`, already created off `v0.4.28`.
- **Commit inside `kdex-host-manager/`**, never at the workspace root.

---

### Task 1: Configurable inbound server timeouts (#167, part 1)

Makes the four `http.Server` timeouts settable from the chart. Defaults are byte-for-byte today's values, so this task changes no runtime behavior — it only creates the knob that Task 2 needs and that operators need for the `0` escape hatch.

**Files:**
- Modify: `internal/web/server/server.go` (whole file, currently 35 lines)
- Modify: `internal/web/server/server_test.go:18` (the `New` call)
- Modify: `cmd/main.go:92-97` (var block), `cmd/main.go:116-123` (flag block), `cmd/main.go:410` (the `server.New` call)
- Modify: `chart/values.yaml` (after the `proxy:` block, ends line 58)
- Modify: `chart/templates/deployment.yaml:41-51` (the `{{- with .Values.proxy }}` block)
- Test: `internal/web/server/server_test.go`, `chart/render_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `server.Timeouts` struct with fields `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, all `time.Duration`.
  - `server.DefaultTimeouts() Timeouts`.
  - `server.New(address string, hostHandler *host.HostHandler, timeouts Timeouts) *http.Server` — **note the third parameter**; Task 2 modifies this same function.

- [ ] **Step 1: Write the failing tests**

Replace the whole of `internal/web/server/server_test.go` with:

```go
package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultTimeouts pins the fix for kdex-tech/host-manager#49: the
// defaults must have non-zero ReadHeaderTimeout (the cheapest, sharpest
// Slowloris defense) and bounded ReadTimeout/WriteTimeout/IdleTimeout. A
// zero value in any of these fields means "no timeout" in Go's stdlib — a
// single attacker can dribble bytes over a few hundred connections and
// exhaust the pod's goroutines and file descriptors with no traffic-volume
// signal.
//
// #167 made these configurable; this test guards that the DEFAULTS did not
// silently become permissive in the process.
func TestDefaultTimeouts(t *testing.T) {
	d := DefaultTimeouts()

	assert.Greater(t, d.ReadHeaderTimeout, time.Duration(0),
		"ReadHeaderTimeout must be set to close the Slowloris vector (#49)")
	assert.Greater(t, d.ReadTimeout, time.Duration(0),
		"ReadTimeout must bound how long a request body read can dangle")
	assert.Greater(t, d.WriteTimeout, time.Duration(0),
		"WriteTimeout must bound how long a response write can dangle")
	assert.Greater(t, d.IdleTimeout, time.Duration(0),
		"IdleTimeout must bound keepalive idle exposure")

	assert.LessOrEqual(t, d.ReadHeaderTimeout, 30*time.Second,
		"ReadHeaderTimeout should be aggressive (<=30s)")
}

// TestNew_AppliesDefaultTimeouts checks the defaults reach the http.Server.
func TestNew_AppliesDefaultTimeouts(t *testing.T) {
	srv := New(":0", nil, DefaultTimeouts())

	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 60*time.Second, srv.ReadTimeout)
	assert.Equal(t, 60*time.Second, srv.WriteTimeout)
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
}

// TestNew_HonorsExplicitTimeouts checks operator overrides reach the
// http.Server verbatim, including zero, which is stdlib for "no deadline"
// and is the documented escape hatch for #167.
func TestNew_HonorsExplicitTimeouts(t *testing.T) {
	srv := New(":0", nil, Timeouts{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       45 * time.Second,
	})

	assert.Equal(t, 5*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, srv.ReadTimeout)
	assert.Equal(t, time.Duration(0), srv.WriteTimeout,
		"zero must pass through as stdlib 'no deadline', not be replaced by a default")
	assert.Equal(t, 45*time.Second, srv.IdleTimeout)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/web/server/ -run 'TestDefaultTimeouts|TestNew_' -v`
Expected: FAIL to compile — `undefined: DefaultTimeouts`, `undefined: Timeouts`, and `too many arguments in call to New`.

- [ ] **Step 3: Implement `Timeouts`, `DefaultTimeouts` and the new `New` signature**

Replace the whole of `internal/web/server/server.go` with:

```go
package server

import (
	"net/http"
	"time"

	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/web/middleware"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Timeouts bounds exposure on every accepted connection. Zero in any field
// means "no timeout" (the stdlib default) — a single slow client can then
// hold a goroutine + FD indefinitely (Slowloris). See
// kdex-tech/host-manager#49 for why they exist and #167 for why they are
// configurable.
type Timeouts struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// DefaultTimeouts is the conservative pairing shipped since #49. The proxy
// round-trip path already tolerates 60s cold starts via its own
// ResponseHeaderTimeout, so 60s read/write matches it.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func New(address string, hostHandler *host.HostHandler, timeouts Timeouts) *http.Server {
	handler := middleware.WithLogger(
		logf.Log.WithName("server"),
	)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hostHandler.ServeHTTP(w, r)
		}),
	)

	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: timeouts.ReadHeaderTimeout,
		ReadTimeout:       timeouts.ReadTimeout,
		WriteTimeout:      timeouts.WriteTimeout,
		IdleTimeout:       timeouts.IdleTimeout,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/server/ -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Add the flags in `cmd/main.go`**

In the var block (currently `cmd/main.go:92-97`), add four lines after `var proxyIdleConnTimeout time.Duration`:

```go
	var serverReadHeaderTimeout time.Duration
	var serverReadTimeout time.Duration
	var serverWriteTimeout time.Duration
	var serverIdleTimeout time.Duration
```

Immediately after the existing `flag.DurationVar(&proxyIdleConnTimeout, ...)` call (currently ends `cmd/main.go:123`), add:

```go
	srvDefaults := server.DefaultTimeouts()
	flag.DurationVar(&serverReadHeaderTimeout, "server-read-header-timeout", srvDefaults.ReadHeaderTimeout,
		"How long the inbound webserver waits for a request's headers. 0 disables the deadline.")
	flag.DurationVar(&serverReadTimeout, "server-read-timeout", srvDefaults.ReadTimeout,
		"How long the inbound webserver allows for reading a whole request. 0 disables the deadline.")
	flag.DurationVar(&serverWriteTimeout, "server-write-timeout", srvDefaults.WriteTimeout,
		"Connection-level write deadline for the inbound webserver. Streaming responses "+
			"(text/event-stream, and chunked responses that keep making progress) are exempted "+
			"per-request; see kdex-tech/host-manager#167. 0 disables the deadline entirely.")
	flag.DurationVar(&serverIdleTimeout, "server-idle-timeout", srvDefaults.IdleTimeout,
		"How long an idle keep-alive connection to the inbound webserver lingers. 0 disables the deadline.")
```

Change the `server.New` call (currently `cmd/main.go:410`) from:

```go
	srv := server.New(webserverAddr, hostHandler)
```

to:

```go
	srv := server.New(webserverAddr, hostHandler, server.Timeouts{
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	})
```

- [ ] **Step 6: Verify the binary builds and the flags register**

Run: `go build ./... && go run ./cmd --help 2>&1 | rg 'server-(read|write|idle)'`
Expected: build succeeds; four `-server-*` flags are listed with their defaults (`10s`, `1m0s`, `1m0s`, `2m0s`).

- [ ] **Step 7: Write the failing chart render test**

Append to `chart/render_test.go`:

```go
// TestServerTimeoutArgs pins that chart server.* values reach the binary's
// --server-* flags (kdex-tech/host-manager#167). The zero case matters most:
// an operator disabling the write deadline must produce an explicit
// `--server-write-timeout=0`, not an omitted flag that silently restores the
// 60s default.
func TestServerTimeoutArgs(t *testing.T) {
	manifests := renderChart(t,
		"server.readHeaderTimeout=5s",
		"server.readTimeout=30s",
		"server.writeTimeout=0",
		"server.idleTimeout=45s",
	)

	for _, want := range []string{
		"--server-read-header-timeout=5s",
		"--server-read-timeout=30s",
		"--server-write-timeout=0",
		"--server-idle-timeout=45s",
	} {
		if !strings.Contains(manifests, want) {
			t.Errorf("rendered manifests missing %q:\n%s", want, manifests)
		}
	}
}

// TestServerTimeoutArgs_Defaults pins that the shipped defaults render.
func TestServerTimeoutArgs_Defaults(t *testing.T) {
	manifests := renderChart(t)

	for _, want := range []string{
		"--server-read-header-timeout=10s",
		"--server-read-timeout=60s",
		"--server-write-timeout=60s",
		"--server-idle-timeout=120s",
	} {
		if !strings.Contains(manifests, want) {
			t.Errorf("rendered manifests missing default %q:\n%s", want, manifests)
		}
	}
}
```

`renderChart` is already `func renderChart(t *testing.T, sets ...string) string` (`chart/render_test.go:47`), so these calls need no adaptation. It skips the test if `bin/helm` is absent — run `make helm` once if you see a skip.

- [ ] **Step 8: Run the chart test to verify it fails**

Run: `go test ./chart/ -run TestServerTimeoutArgs -v`
Expected: FAIL — the rendered manifests contain no `--server-*` args.

- [ ] **Step 9: Add the chart values**

In `chart/values.yaml`, immediately after the `proxy:` block (which ends with `idleConnTimeout: 90s` on line 58), add:

```yaml

# Inbound webserver timeouts. These bound exposure on every accepted
# connection (kdex-tech/host-manager#49). Streaming responses are exempted
# from writeTimeout per-request — text/event-stream has its deadline cleared
# outright, and a chunked response that keeps making progress has its
# deadline pushed forward on every write — so SSE and MCP streams are no
# longer severed at writeTimeout (#167). Set any value to "0" to disable that
# deadline entirely.
server:
  readHeaderTimeout: 10s
  readTimeout: 60s
  writeTimeout: 60s
  idleTimeout: 120s
```

- [ ] **Step 10: Render the values into args**

In `chart/templates/deployment.yaml`, immediately after the existing
`{{- with .Values.proxy }} ... {{- end }}` block (currently lines 41-51), add:

```yaml
            {{- with .Values.server }}
            - --server-read-header-timeout={{ .readHeaderTimeout }}
            - --server-read-timeout={{ .readTimeout }}
            - --server-write-timeout={{ .writeTimeout }}
            - --server-idle-timeout={{ .idleTimeout }}
            {{- end }}
```

Note the deliberate difference from the `proxy` block above it: **no inner
`{{- with .field }}` guards.** `{{- with 0 }}` is falsy in Helm, so an inner
guard would silently drop `--server-write-timeout=0` — exactly the setting an
operator reaches for. `TestServerTimeoutArgs` fails if this regresses.

- [ ] **Step 11: Run the chart tests to verify they pass**

Run: `go test ./chart/ -v && make lint-chart`
Expected: PASS; `helm lint ./chart` reports no failures.

- [ ] **Step 12: Full verification**

Run: `make lint && make test`
Expected: both succeed.

- [ ] **Step 13: Commit**

```bash
git add internal/web/server/ cmd/main.go chart/values.yaml chart/templates/deployment.yaml chart/render_test.go
git commit -m "feat(server): make inbound webserver timeouts configurable (#167)

Adds server.Timeouts + DefaultTimeouts and threads four --server-* flags
through the chart's new server.* block, mirroring proxy.*. Defaults are
unchanged, so this is behavior-neutral on its own; it creates the knob
that the streaming-deadline fix needs and gives operators the 0 escape
hatch.

The chart block deliberately omits per-field {{- with }} guards: {{- with
0 }} is falsy, which would drop --server-write-timeout=0.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `WithStreamDeadline` middleware (#167, part 2)

The actual fix. `http.Server.WriteTimeout` deadlines the whole connection, so an in-flight `text/event-stream` response dies mid-body at 60s no matter how healthily it flushes. This adjusts the deadline **per request** via `http.ResponseController`.

**Files:**
- Create: `internal/web/middleware/streamdeadline.go`
- Create: `internal/web/middleware/streamdeadline_test.go`
- Modify: `internal/web/server/server.go` (wire the middleware into `New`)
- Test: `internal/web/middleware/streamdeadline_test.go`

**Interfaces:**
- Consumes: `server.Timeouts.WriteTimeout` from Task 1.
- Produces: `middleware.WithStreamDeadline(writeTimeout time.Duration) func(http.Handler) http.Handler` — same shape as the existing `middleware.WithLogger`.

- [ ] **Step 1: Write the failing tests**

Create `internal/web/middleware/streamdeadline_test.go`:

```go
package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWriteTimeout = 200 * time.Millisecond

// serve starts an httptest server whose connection-level WriteTimeout is
// testWriteTimeout and whose handler is wrapped by WithStreamDeadline.
func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(WithStreamDeadline(testWriteTimeout)(h))
	srv.Config.WriteTimeout = testWriteTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestWithStreamDeadline_SSEOutlivesWriteTimeout is the #167 reproduction:
// a text/event-stream response flushing on a healthy cadence must not be
// severed when the connection-level WriteTimeout elapses. The handler runs
// for ~500ms against a 200ms WriteTimeout.
func TestWithStreamDeadline_SSEOutlivesWriteTimeout(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 5; i++ {
			_, _ = fmt.Fprintf(w, ": keepalive %d\n\n", i)
			_ = http.NewResponseController(w).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err,
		"SSE stream was severed mid-body — the per-request write deadline was not cleared (#167)")
	assert.Equal(t, 5, strings.Count(string(body), ": keepalive"),
		"every keep-alive must arrive; got:\n%s", body)
}

// TestWithStreamDeadline_ChunkedProgressOutlivesWriteTimeout covers the
// sliding case: a chunked response with no Content-Length that keeps making
// progress runs unbounded.
func TestWithStreamDeadline_ChunkedProgressOutlivesWriteTimeout(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 5; i++ {
			_, _ = fmt.Fprintf(w, "chunk %d\n", i)
			_ = http.NewResponseController(w).Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err,
		"steadily-progressing chunked response was severed — sliding deadline did not fire (#167)")
	assert.Equal(t, 5, strings.Count(string(body), "chunk "),
		"every chunk must arrive; got:\n%s", body)
}

// TestWithStreamDeadline_ChunkedStallIsStillCut pins the deliberate choice
// of SLIDING rather than CLEARING for chunked responses: a stream that stops
// making progress for longer than writeTimeout is still cut. If this test
// starts passing trivially, the implementation has become "clear the
// deadline for anything chunked", which drops the stall cap.
func TestWithStreamDeadline_ChunkedStallIsStillCut(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "before-stall\n")
		_ = http.NewResponseController(w).Flush()
		time.Sleep(4 * testWriteTimeout)
		_, _ = fmt.Fprint(w, "after-stall\n")
		_ = http.NewResponseController(w).Flush()
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "after-stall",
		"a chunked response that stalls past writeTimeout must still be cut")
}

// TestWithStreamDeadline_FixedLengthStillBounded confirms the middleware
// leaves ordinary responses alone: with a Content-Length set, the
// connection-level WriteTimeout still applies.
func TestWithStreamDeadline_FixedLengthStillBounded(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "24")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "aaaaaaaaaaaa")
		_ = http.NewResponseController(w).Flush()
		time.Sleep(4 * testWriteTimeout)
		_, _ = fmt.Fprint(w, "bbbbbbbbbbbb")
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "bbbbbbbbbbbb",
		"a fixed-Content-Length response must remain bounded by writeTimeout")
}

// TestWithStreamDeadline_Disabled checks the pass-through path: with no
// write deadline to adjust, the middleware must not wrap at all.
func TestWithStreamDeadline_Disabled(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	wrapped := WithStreamDeadline(0)(inner)

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestStreamWriter_InterfaceObligations pins the three wrapper contracts
// from the #167 design. Each omission is a silent functional break:
//   - no Unwrap  -> ResponseController cannot set deadlines, #167 regresses
//   - no Hijack  -> ReverseProxy cannot service Upgrade, WebSockets break
//   - ReadFrom   -> io.Copy bypasses Write, the sliding deadline never fires
func TestStreamWriter_InterfaceObligations(t *testing.T) {
	var w http.ResponseWriter = &streamWriter{ResponseWriter: httptest.NewRecorder()}

	_, ok := w.(interface{ Unwrap() http.ResponseWriter })
	assert.True(t, ok, "Unwrap is required or ResponseController cannot set deadlines (#167)")

	_, ok = w.(http.Flusher)
	assert.True(t, ok, "Flush is required for per-chunk streaming")

	_, ok = w.(http.Hijacker)
	assert.True(t, ok, "Hijack is required or WebSocket proxying through ReverseProxy breaks")

	_, ok = w.(io.ReaderFrom)
	assert.False(t, ok,
		"ReadFrom must NOT be implemented: io.Copy would prefer it, bypass Write, "+
			"and the sliding deadline would never fire")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/web/middleware/ -v`
Expected: FAIL to compile — `undefined: WithStreamDeadline`, `undefined: streamWriter`.

- [ ] **Step 3: Implement the middleware**

Create `internal/web/middleware/streamdeadline.go`:

```go
package middleware

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"time"
)

// WithStreamDeadline adjusts the PER-REQUEST write deadline so a streaming
// response is not severed by the connection-level http.Server.WriteTimeout.
//
// In Go, WriteTimeout deadlines the whole connection rather than a single
// slow write, so an in-flight text/event-stream response is torn down
// mid-body when it elapses — no matter how healthily it is flushing. That is
// kdex-tech/host-manager#167: both production SSE surfaces sat in a
// permanent ~60s reconnect loop.
//
// A writeTimeout of zero or less means the server has no write deadline, so
// there is nothing to adjust and this is a pass-through.
func WithStreamDeadline(writeTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if writeTimeout <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&streamWriter{ResponseWriter: w, writeTimeout: writeTimeout}, r)
		})
	}
}

// streamWriter is the only ResponseWriter wrapper in the serving chain
// (WithLogger passes w through unmodified), so it carries every delegation
// obligation on its own. See the Unwrap/Flush/Hijack comments below, and
// note the deliberate ABSENCE of io.ReaderFrom.
type streamWriter struct {
	http.ResponseWriter

	writeTimeout time.Duration
	sliding      bool
	wroteHeader  bool
}

// Unwrap lets http.ResponseController reach the underlying writer's
// SetWriteDeadline. Without it every deadline call returns
// http.ErrNotSupported and #167 silently regresses.
func (s *streamWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *streamWriter) WriteHeader(code int) {
	s.applyDeadlinePolicyOnce()
	s.ResponseWriter.WriteHeader(code)
}

func (s *streamWriter) Write(p []byte) (int, error) {
	// A handler may Write without an explicit WriteHeader; the stdlib
	// implies 200 on the INNER writer, which would skip our policy.
	s.applyDeadlinePolicyOnce()

	if s.sliding {
		// Push the deadline forward on every write. This removes the
		// total-duration cap (the #167 defect) while keeping a stall cap:
		// a response that goes silent for longer than writeTimeout is
		// still cut.
		_ = http.NewResponseController(s.ResponseWriter).
			SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	return s.ResponseWriter.Write(p)
}

// applyDeadlinePolicyOnce runs exactly once, when the response headers are
// final. The three cases are ordered and first-match-wins: an SSE response
// ALSO has no Content-Length, so the event-stream check must be evaluated
// first or SSE would land in sliding mode and still die on a backend whose
// keep-alive interval exceeds writeTimeout.
func (s *streamWriter) applyDeadlinePolicyOnce() {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true

	h := s.ResponseWriter.Header()

	// 1. Server-Sent Events: clear the deadline outright. The keep-alive
	//    cadence belongs to the backend and may exceed anything we pick.
	if strings.HasPrefix(h.Get("Content-Type"), "text/event-stream") {
		_ = http.NewResponseController(s.ResponseWriter).SetWriteDeadline(time.Time{})
		return
	}

	// 2. Chunked / unknown length: slide the deadline on each write.
	if h.Get("Content-Length") == "" {
		s.sliding = true
		return
	}

	// 3. Fixed-length: leave the connection-level deadline alone.
}

// Flush keeps ReverseProxy's maxLatencyWriter flushing per chunk.
func (s *streamWriter) Flush() {
	_ = http.NewResponseController(s.ResponseWriter).Flush()
}

// Hijack delegates so httputil.ReverseProxy can still service Upgrade
// requests. A wrapper that swallows Hijack breaks WebSocket proxying.
func (s *streamWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/web/middleware/ -v`
Expected: PASS, 7 tests.

If `TestWithStreamDeadline_ChunkedStallIsStillCut` or
`TestWithStreamDeadline_FixedLengthStillBounded` is flaky on a loaded
machine, raise `testWriteTimeout` to `500 * time.Millisecond` and scale the
handler sleeps proportionally. Do **not** weaken the assertions.

- [ ] **Step 5: Wire the middleware into the server**

In `internal/web/server/server.go`, change the handler construction inside
`New` from:

```go
	handler := middleware.WithLogger(
		logf.Log.WithName("server"),
	)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hostHandler.ServeHTTP(w, r)
		}),
	)
```

to:

```go
	handler := middleware.WithLogger(
		logf.Log.WithName("server"),
	)(
		middleware.WithStreamDeadline(timeouts.WriteTimeout)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hostHandler.ServeHTTP(w, r)
			}),
		),
	)
```

`WithStreamDeadline` sits **inside** `WithLogger` so the logger's context
injection happens first and the wrapper is the innermost — and therefore
only — writer wrapper the handler sees.

- [ ] **Step 6: Write the HTTP/2 verification test**

This is the one assumption the design flags as needing proof rather than
trust: `SetWriteDeadline` must be honored on h2 streams, not only h1.

Append to `internal/web/middleware/streamdeadline_test.go`:

```go
// TestWithStreamDeadline_SSEOverHTTP2 proves the per-request deadline is
// honored on HTTP/2 streams too, not just HTTP/1.1. The #167 reproduction
// showed HTTP/2 at the edge, and Go's h2 ResponseWriter implements
// SetWriteDeadline separately from the h1 one — so this is verified, not
// assumed.
//
// If this test fails, DO NOT delete it. It means h2 does not honor the
// per-request deadline, and the fallback is to document
// `server.writeTimeout: 0` as required for h2 SSE deployments. Report that
// before changing anything else.
func TestWithStreamDeadline_SSEOverHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(WithStreamDeadline(testWriteTimeout)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			for i := 0; i < 5; i++ {
				_, _ = fmt.Fprintf(w, ": keepalive %d\n\n", i)
				_ = http.NewResponseController(w).Flush()
				time.Sleep(100 * time.Millisecond)
			}
		}),
	))
	srv.Config.WriteTimeout = testWriteTimeout
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := srv.Client()
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, 2, resp.ProtoMajor, "test must actually exercise HTTP/2")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err,
		"SSE stream severed over HTTP/2 — the h2 ResponseWriter did not honor SetWriteDeadline (#167)")
	assert.Equal(t, 5, strings.Count(string(body), ": keepalive"))
}
```

- [ ] **Step 7: Run the HTTP/2 test**

Run: `go test ./internal/web/middleware/ -run TestWithStreamDeadline_SSEOverHTTP2 -v`
Expected: PASS.

If it FAILS, stop and report — see the test's own comment. Do not proceed to Step 8 with a failing h2 test.

- [ ] **Step 8: Full verification**

Run: `make lint && make test`
Expected: both succeed.

- [ ] **Step 9: Commit**

```bash
git add internal/web/middleware/streamdeadline.go internal/web/middleware/streamdeadline_test.go internal/web/server/server.go
git commit -m "fix(server): stop severing SSE and streaming responses at WriteTimeout (#167)

http.Server.WriteTimeout deadlines the whole connection, so an in-flight
text/event-stream response died mid-body at 60s regardless of how
healthily it flushed. Both production SSE surfaces sat in a permanent
~60s reconnect loop.

WithStreamDeadline adjusts the per-request deadline via
http.ResponseController: cleared outright for text/event-stream, and slid
forward on every write for chunked responses. Sliding rather than
clearing keeps a stall cap for the chunked case — a response that stops
making progress is still cut.

The wrapper delegates Unwrap, Flush and Hijack, and deliberately does not
implement io.ReaderFrom (io.Copy would prefer it and bypass Write).
Verified on both HTTP/1.1 and HTTP/2.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `ErrServerError` sentinel (#168, part 1)

Separates infrastructure failures from grant failures inside the Exchanger, so Task 4 can map the former to `500 server_error` and the latter to `400 invalid_grant`. Without this, a transient cache or signing outage would tell every client to throw away a perfectly good refresh token and re-authorize.

**Files:**
- Modify: `internal/auth/exchange.go` (add the sentinel; wrap it at the infrastructure-failure sites in `RedeemRefreshToken` around lines 681-749 and `RedeemAuthorizationCode` around lines 571-677)
- Create: `internal/auth/exchange_servererror_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `auth.ErrServerError` (`var ErrServerError = errors.New("server error")`), wrapped by every infrastructure-failure return in the two redemption paths and detectable with `errors.Is`.

- [ ] **Step 1: Write the failing test**

Create `internal/auth/exchange_servererror_test.go`:

```go
package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedeemRefreshToken_GrantFailuresAreNotServerErrors pins the #168
// classification boundary. A dead or mismatched grant is the CLIENT's
// problem and maps to 400 invalid_grant; it must never be reported as
// ErrServerError, or a client would be told to retry rather than
// re-authorize.
func TestRedeemRefreshToken_GrantFailuresAreNotServerErrors(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	t.Run("unknown token", func(t *testing.T) {
		_, err := ex.RedeemRefreshToken(ctx, "never-issued", "app")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"an unknown refresh token is a grant failure (400 invalid_grant), not a server error")
	})

	t.Run("client mismatch", func(t *testing.T) {
		tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: AuthMethodLocal,
			ClientID:   "app",
			Subject:    "alice",
			Scope:      "openid",
		})
		require.NoError(t, err)

		_, err = ex.RedeemRefreshToken(ctx, tokenID, "some-other-client")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"a client-id mismatch is a grant failure (400 invalid_grant), not a server error")
	})
}

// TestErrServerError_IsDetectable pins that the sentinel survives wrapping,
// which is the whole mechanism Task 4's handler depends on.
func TestErrServerError_IsDetectable(t *testing.T) {
	wrapped := errors.Join(ErrServerError, errors.New("cache unreachable"))
	assert.True(t, errors.Is(wrapped, ErrServerError))
	assert.False(t, errors.Is(errors.New("refresh token not found or expired"), ErrServerError))
}
```

`newRotationTestExchanger` already exists in `internal/auth/exchange_rotation_race_test.go:41` and is reused here — same package, no import needed.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/auth/ -run 'ServerError' -v`
Expected: FAIL to compile — `undefined: ErrServerError`.

- [ ] **Step 3: Add the sentinel and wrap the infrastructure-failure sites**

In `internal/auth/exchange.go`, add near the top of the file, after the imports:

```go
// ErrServerError marks a failure of OUR infrastructure — a cache read, a
// signing operation, a stored-record unmarshal — as distinct from a failure
// of the client's grant. The token endpoint maps it to RFC 6749 5.2's
// server_error (500) rather than invalid_grant (400), because telling a
// client its credential is dead during a transient outage makes it discard
// a working refresh token and re-authorize for no reason. See
// kdex-tech/host-manager#168.
var ErrServerError = errors.New("server error")
```

Add `"errors"` to the import block if it is not already present.

In `RedeemRefreshToken`, wrap the four infrastructure sites. Change:

```go
	raw, found, _, err := e.refreshTokenCache.GetAndDelete(ctx, tokenID)
	if err != nil {
		return TokenSet{}, fmt.Errorf("failed to read refresh token: %w", err)
	}
```

to:

```go
	raw, found, _, err := e.refreshTokenCache.GetAndDelete(ctx, tokenID)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to read refresh token: %v", ErrServerError, err)
	}
```

Change:

```go
	var claims RefreshTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return TokenSet{}, fmt.Errorf("failed to parse refresh token: %w", err)
	}
```

to:

```go
	var claims RefreshTokenClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		return TokenSet{}, fmt.Errorf("%w: failed to parse refresh token: %v", ErrServerError, err)
	}
```

Change:

```go
	ts, err := e.mintTokensFromSubject(claims.Subject, claims.ClientID, claims.Scope, claims.AuthMethod)
	if err != nil {
		return failed("failed to mint tokens from refresh: %w", err)
	}
```

to:

```go
	ts, err := e.mintTokensFromSubject(claims.Subject, claims.ClientID, claims.Scope, claims.AuthMethod)
	if err != nil {
		return failed("%w: failed to mint tokens from refresh: %v", ErrServerError, err)
	}
```

Change:

```go
	ts.RefreshToken, err = e.createRefreshToken(ctx, RefreshTokenClaims{
		...
	})
	if err != nil {
		return failed("failed to rotate refresh token: %w", err)
	}
```

to the same call with:

```go
	if err != nil {
		return failed("%w: failed to rotate refresh token: %v", ErrServerError, err)
	}
```

Leave the three *grant* rejections in that function untouched — `refresh token expired`, `session absolute timeout reached`, `refresh token was not issued to this client`, and the `refresh token not found or expired` return. Those are `invalid_grant` by definition.

- [ ] **Step 4: Apply the same split in `RedeemAuthorizationCode`**

Exactly three returns in that function are our failures. Change these and nothing else:

`internal/auth/exchange.go:573` — from
```go
		return TokenSet{}, fmt.Errorf("auth not configured")
```
to
```go
		return TokenSet{}, fmt.Errorf("%w: auth not configured", ErrServerError)
```

`internal/auth/exchange.go:593` — from
```go
		return TokenSet{}, fmt.Errorf("failed to unmarshal auth code claims: %w", err)
```
to
```go
		return TokenSet{}, fmt.Errorf("%w: failed to unmarshal auth code claims: %v", ErrServerError, err)
```
(The code decrypted successfully with our own key, so the record is one *we* minted — a malformed one is our bug, not the client's.)

`internal/auth/exchange.go:666` — from
```go
			return failed("failed to check auth code consumption: %w", err)
```
to
```go
			return failed("%w: failed to check auth code consumption: %v", ErrServerError, err)
```

**Leave every other return in that function alone**, including the two that look similar but are not: `failed to parse auth code` (line 579) and `failed to decrypt auth code` (line 588) both describe the *client's* presented code failing to parse or decrypt, which is `invalid_grant`. Likewise all the `failed(...)` rejections — `authorization code expired`, `client_id mismatch`, `redirect_uri mismatch`, `invalid client_id`, the PKCE messages, and `authorization code already consumed or expired`.

Do **not** touch lines 394, 398, 482 or 784. Those `auth not configured` variants are in `LoginClient`, `LoginLocal` and `CreateAuthorizationCode`, which are outside the two redemption paths this task scopes.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -run 'ServerError' -v`
Expected: PASS, 2 tests (3 subtests).

- [ ] **Step 6: Confirm no existing test regressed**

Run: `go test ./internal/auth/ -v`
Expected: PASS. Several existing tests assert on error *strings* — notably
`internal/auth/exchange_failure_subject_test.go`. `%w: failed to read...`
prefixes the message with `server error: `, so any test matching with
`assert.Equal` on a full message needs updating to `assert.Contains`. Update
the assertion, not the message.

- [ ] **Step 7: Full verification**

Run: `make lint && make test`
Expected: both succeed.

- [ ] **Step 8: Commit**

```bash
git add internal/auth/exchange.go internal/auth/exchange_servererror_test.go
git commit -m "refactor(auth): mark infrastructure failures with ErrServerError (#168)

Grant redemption currently returns one undifferentiated error class, so
the token endpoint cannot tell 'your credential is dead' from 'our cache
is down'. Reporting the latter as invalid_grant would make clients
discard working refresh tokens during a transient outage.

Wraps ErrServerError at the cache-read, record-unmarshal, mint and
rotate sites in both redemption paths, leaving every client-input
rejection unwrapped. No behavior change yet; the token endpoint consumes
this next.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: RFC 6749 §5.2 error responses (#168, part 2)

The client-visible fix. `POST /-/token` answers every grant failure with `401` + `text/plain`, so a client keying its re-authorization fallback on `invalid_grant` cannot see it — one observed MCP client retried a dead token 290 times with zero successes.

**Files:**
- Create: `internal/auth/oautherr.go`
- Create: `internal/auth/oautherr_test.go`
- Modify: `internal/auth/oauth2.go:258-398` (every `http.Error` in the token handler, plus the success path's headers)
- Test: `internal/auth/oautherr_test.go`

**Interfaces:**
- Consumes: `auth.ErrServerError` from Task 3.
- Produces: `writeOAuthError(w http.ResponseWriter, status int, code, description string)` — unexported, used only within package `auth`.

- [ ] **Step 1: Write the failing tests**

Create `internal/auth/oautherr_test.go`:

```go
package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteOAuthError_Shape pins the RFC 6749 5.2 response shape: JSON body
// with an `error` code, and no-store caching headers. A text/plain body
// gives a conforming client nothing to parse — that is #168.
func TestWriteOAuthError_Shape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOAuthError(rec, http.StatusBadRequest, "invalid_grant", "refresh token not found or expired")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "refresh token not found or expired", body["error_description"])
}

// TestOAuthErrorForRedemption pins the classification that makes #168 safe:
// an infrastructure failure must become 500 server_error with a GENERIC
// description, never 400 invalid_grant with internals echoed to an
// unauthenticated caller.
func TestOAuthErrorForRedemption(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantDescNot string
	}{
		{
			name:       "dead refresh token is a grant failure",
			err:        errDeadGrantForTest(),
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_grant",
		},
		{
			name:        "infrastructure failure is a server error",
			err:         errServerFailureForTest(),
			wantStatus:  http.StatusInternalServerError,
			wantCode:    "server_error",
			wantDescNot: "cache unreachable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, code, desc := oauthErrorForRedemption(tc.err)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantCode, code)
			if tc.wantDescNot != "" {
				assert.NotContains(t, desc, tc.wantDescNot,
					"server_error must not echo internals to an unauthenticated caller")
			}
		})
	}
}
```

Add these two helpers at the bottom of the same file, and add `"fmt"` to its
import block:

```go
// errDeadGrantForTest is the shape a dead refresh token produces: a plain
// error carrying no ErrServerError.
func errDeadGrantForTest() error {
	return fmt.Errorf("refresh token not found or expired")
}

// errServerFailureForTest is the shape an infrastructure failure produces
// after Task 3's wrapping.
func errServerFailureForTest() error {
	return fmt.Errorf("%w: failed to read refresh token: %v", ErrServerError, "cache unreachable")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -run 'OAuthError' -v`
Expected: FAIL to compile — `undefined: writeOAuthError`, `undefined: oauthErrorForRedemption`.

- [ ] **Step 3: Implement the helper**

Create `internal/auth/oautherr.go`:

```go
package auth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// RFC 6749 5.2 error codes.
const (
	errCodeInvalidRequest       = "invalid_request"
	errCodeInvalidClient        = "invalid_client"
	errCodeInvalidGrant         = "invalid_grant"
	errCodeUnauthorizedClient   = "unauthorized_client"
	errCodeUnsupportedGrantType = "unsupported_grant_type"
	errCodeInvalidScope         = "invalid_scope"
	errCodeServerError          = "server_error"
)

// genericServerErrorDescription is what an unauthenticated caller sees when
// OUR infrastructure fails. The wrapped cause is logged, never returned:
// a signing or cache failure must not have its internals reflected back.
const genericServerErrorDescription = "the authorization server encountered an unexpected condition"

// writeOAuthError emits an RFC 6749 5.2 error response: a JSON body with an
// `error` code, plus the no-store caching headers 5.1 requires of the token
// endpoint. Before kdex-tech/host-manager#168 every failure here was
// text/plain, so a client could not detect invalid_grant and had no
// spec-defined way to learn it should re-authorize.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// oauthErrorForRedemption classifies an error out of a grant-redemption path
// into its 5.2 response. Everything that is not one of OUR failures is
// invalid_grant by definition: 5.2 defines that code as covering invalid,
// expired, revoked, mismatched-client and mismatched-redirect-URI grants,
// which is exactly the remaining set.
func oauthErrorForRedemption(err error) (status int, code, description string) {
	if errors.Is(err, ErrServerError) {
		return http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription
	}
	return http.StatusBadRequest, errCodeInvalidGrant, err.Error()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/auth/ -run 'OAuthError' -v`
Expected: PASS, 2 tests (3 subtests).

- [ ] **Step 5: Write the failing handler tests**

Create `internal/auth/oauth2_tokenerror_test.go`:

```go
package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeOAuthError reads the RFC 6749 5.2 body off a response recorder.
func decodeOAuthError(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
		"5.2 requires the error parameters in an application/json entity body")
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body),
		"body was not JSON: %q", rec.Body.String())
	return body
}

// postToken drives the token handler with form values.
func postToken(t *testing.T, o *OAuth2, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	o.OAuth2TokenHandler(rec, req)
	return rec
}

// newTokenErrorTestHandler builds an OAuth2 handler over the same stub
// Exchanger the rotation tests use, which already registers a public client
// named "app".
func newTokenErrorTestHandler(t *testing.T) *OAuth2 {
	t.Helper()
	ex := newRotationTestExchanger(t)
	return &OAuth2{
		AuthConfig:        &ex.config,
		AuthExchanger:     ex,
		ResourceAudiences: map[string]bool{},
		AccessTokenTTL:    time.Hour,
	}
}

// TestTokenHandler_DeadRefreshTokenIsInvalidGrant is the literal #168
// reproduction: a dead refresh token must produce 400 +
// {"error":"invalid_grant"}, the spec-defined signal telling a client to
// start a fresh authorization flow. Before the fix this was 401 +
// text/plain "Authentication failed", and one MCP client retried the same
// dead token 290 times as a result.
func TestTokenHandler_DeadRefreshTokenIsInvalidGrant(t *testing.T) {
	o := newTokenErrorTestHandler(t)

	rec := postToken(t, o, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"DEADBEEFNOTAREALTOKEN000000"},
		"client_id":     {"app"},
	})

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"5.2 reserves 401 for failed client authentication via the Authorization header")
	assert.Equal(t, "invalid_grant", decodeOAuthError(t, rec)["error"])
}

// TestTokenHandler_ErrorMapping walks the rest of the 5.2 table.
func TestTokenHandler_ErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing refresh_token",
			form:       url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "missing code",
			form:       url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "unknown client_id",
			form:       url.Values{"grant_type": {"refresh_token"}, "client_id": {"no-such-client"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_client",
		},
		{
			name:       "unknown grant_type",
			form:       url.Values{"grant_type": {"telepathy"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "unsupported_grant_type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := postToken(t, newTokenErrorTestHandler(t), tc.form)
			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantCode, decodeOAuthError(t, rec)["error"])
		})
	}
}

// TestTokenHandler_MethodNotAllowed keeps the 405 but gives it the same
// JSON shape, so a client never has to branch on content type.
func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	o := newTokenErrorTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/-/token", nil)
	rec := httptest.NewRecorder()
	o.TokenHandler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "invalid_request", decodeOAuthError(t, rec)["error"])
}

// TestTokenHandler_BasicAuthRejectionIs401WithChallenge pins the ONE case
// where 5.2 does want 401: client authentication attempted through the
// Authorization request header. It then obliges a WWW-Authenticate header.
// No current client takes this path — they are public PKCE clients — but
// the branch must be correct or a future confidential client gets a
// non-conformant response.
func TestTokenHandler_BasicAuthRejectionIs401WithChallenge(t *testing.T) {
	o := newTokenErrorTestHandler(t)
	o.AuthExchanger.config.Clients["confidential"] = AuthClient{
		ClientID:     "confidential",
		ClientSecret: "correct-secret",
	}

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("confidential", "wrong-secret")
	rec := httptest.NewRecorder()
	o.OAuth2TokenHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"5.2 requires 401 when client auth was attempted via the Authorization header")
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"),
		"a 401 from the token endpoint must carry WWW-Authenticate")
	assert.Equal(t, "invalid_client", decodeOAuthError(t, rec)["error"])
}

// TestTokenHandler_NoStoreOnBothPaths pins RFC 6749 5.1's caching
// requirement, which the endpoint omitted entirely before #168. A cached
// token response is a credential leak into any shared cache on the path.
func TestTokenHandler_NoStoreOnBothPaths(t *testing.T) {
	rec := postToken(t, newTokenErrorTestHandler(t), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"DEADBEEFNOTAREALTOKEN000000"},
		"client_id":     {"app"},
	})
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"error responses from the token endpoint must be no-store (5.1)")

	// The success path is exercised end-to-end by minting a live refresh
	// token and redeeming it.
	o := newTokenErrorTestHandler(t)
	tokenID, err := o.AuthExchanger.createRefreshToken(context.Background(), RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	rec = postToken(t, o, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenID},
		"client_id":     {"app"},
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"success responses from the token endpoint must be no-store (5.1)")
}
```

The test file needs `"context"` and `"time"` in its import block for the two
tests above. `newRotationTestExchanger` lives at
`internal/auth/exchange_rotation_race_test.go:41` — same package, no import.

- [ ] **Step 6: Run the handler tests to verify they fail**

Run: `go test ./internal/auth/ -run TestTokenHandler -v`
Expected: FAIL — statuses are `401`, content type is `text/plain`, `decodeOAuthError` fails to unmarshal.

- [ ] **Step 7: Map every failure path in the token handler**

In `internal/auth/oauth2.go`, replace each `http.Error` in the token handler
(the function containing lines 258-398) per this table. Leave the `err = ...`
assignments alone — they feed the deferred log at the top of the function.

| Current line | Current call | Replace with |
|---|---|---|
| 260 | `http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)` | `writeOAuthError(w, http.StatusMethodNotAllowed, errCodeInvalidRequest, "the token endpoint requires POST")` |
| 266 | `http.Error(w, "Failed to parse form", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "malformed request body")` |
| 293 | `http.Error(w, "Invalid client_id", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidClient, "unknown client_id")` |
| 303 | `http.Error(w, "Invalid client_secret", http.StatusBadRequest)` | see Step 8 |
| 315 | `http.Error(w, "Unauthorized grant type", http.StatusUnauthorized)` | `writeOAuthError(w, http.StatusBadRequest, errCodeUnauthorizedClient, "this client is not authorized for that grant_type")` |
| 323 | `http.Error(w, "Unauthorized scope", http.StatusUnauthorized)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidScope, "requested scope is not allowed for this client")` |
| 334 | `http.Error(w, "code is required", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "code is required")` |
| 340 | `http.Error(w, "redirect_uri is required", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "redirect_uri is required")` |
| 347 | `http.Error(w, "client_credentials grant_type is not supported for public clients", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeUnauthorizedClient, "client_credentials is not supported for public clients")` |
| 359 | `http.Error(w, "refresh_token is required", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeInvalidRequest, "refresh_token is required")` |
| 365 | `http.Error(w, "Unsupported grant_type", http.StatusBadRequest)` | `writeOAuthError(w, http.StatusBadRequest, errCodeUnsupportedGrantType, "unsupported grant_type")` |
| 371 | `http.Error(w, "Authentication failed", http.StatusUnauthorized)` | see Step 9 |
| 395 | `http.Error(w, "Failed to encode token response", http.StatusInternalServerError)` | `writeOAuthError(w, http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription)` |

- [ ] **Step 8: Handle the client_secret case, which is the one 401**

At line 303, whether §5.2 wants `400` or `401` depends on **how the
credentials arrived**. The handler already captured that at line 271
(`clientId, clientSecret, _ = r.BasicAuth()`); capture the third return
value so the branch can see it. Change line 271 from:

```go
	clientId, clientSecret, _ = r.BasicAuth()
```

to:

```go
	var usedBasicAuth bool
	clientId, clientSecret, usedBasicAuth = r.BasicAuth()
```

and replace the line-303 `http.Error` with:

```go
			if usedBasicAuth {
				// 5.2: 401 applies only when client authentication was
				// attempted via the Authorization header, and then obliges
				// a WWW-Authenticate challenge.
				w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
				writeOAuthError(w, http.StatusUnauthorized, errCodeInvalidClient, "client authentication failed")
			} else {
				// Public PKCE clients send no Authorization header, so 5.2
				// permits 400 — and we would have no meaningful challenge to
				// put in WWW-Authenticate anyway. This is the path every
				// current client takes.
				writeOAuthError(w, http.StatusBadRequest, errCodeInvalidClient, "client authentication failed")
			}
```

- [ ] **Step 9: Route grant failures through the classifier**

Replace the block at lines 369-373:

```go
	if err != nil {
		err = fmt.Errorf("authentication failed: %w", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
```

with:

```go
	if err != nil {
		status, code, description := oauthErrorForRedemption(err)
		// Keep the full wrapped cause on `err` for the deferred log; only
		// the classified description reaches the client.
		err = fmt.Errorf("token request failed: %w", err)
		writeOAuthError(w, status, code, description)
		return
	}
```

- [ ] **Step 10: Add the no-store headers to the success path**

RFC 6749 §5.1 requires them and they are currently absent. Change lines
392-393 from:

```go
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
```

to:

```go
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
```

- [ ] **Step 11: Run the handler tests to verify they pass**

Run: `go test ./internal/auth/ -run TestTokenHandler -v`
Expected: PASS, 5 tests (with 4 subtests under `TestTokenHandler_ErrorMapping`).

- [ ] **Step 12: Confirm no existing test regressed**

Run: `go test ./internal/auth/ ./internal/host/ -v`
Expected: PASS. Any existing test asserting `401` or a `text/plain` body from
the token endpoint is asserting the **bug**; update it to the new expectation
and note `#168` in the assertion message.

- [ ] **Step 13: Full verification**

Run: `make lint && make test`
Expected: both succeed.

- [ ] **Step 14: Commit**

```bash
git add internal/auth/oautherr.go internal/auth/oautherr_test.go internal/auth/oauth2.go internal/auth/oauth2_tokenerror_test.go
git commit -m "fix(auth): return RFC 6749 5.2 errors from the token endpoint (#168)

POST /-/token reported every grant failure as 401 + text/plain, so a
client keying its re-authorization fallback on invalid_grant could not
see the signal. One MCP client retried a dead refresh token 290 times
with zero successes and never reached initialize.

Maps the whole endpoint onto the 5.2 codes with JSON bodies, and adds
the no-store headers 5.1 requires on both success and error responses.
invalid_client stays 400 for public PKCE clients — 5.2 reserves 401 for
Authorization-header authentication, which then obliges a
WWW-Authenticate challenge, and that branch is now distinguished.

Infrastructure failures classify to 500 server_error with a generic
description rather than invalid_grant, so a transient outage does not
tell clients to discard working credentials.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Refresh-token rotation grace window (#169)

Real clients issue several refresh requests in parallel — the issue documents repeated bursts of 4-5 within 250-600ms — and strict rotation fails all but one. This replays the winner's minted result to the losers instead of rejecting them, so exactly one rotation still happens and #71's single-lineage guarantee is untouched.

**Files:**
- Modify: `internal/auth/config.go` (add `RefreshGraceWindow` to `Config` at ~line 71 and to `ConfigBuilder` at ~line 107; default it in `Build`)
- Modify: `internal/auth/exchange.go` (Exchanger fields ~line 42, cache wiring ~line 113, `RedeemRefreshToken` ~line 681)
- Modify: `internal/controller/kdexinternalhost_controller.go:489-529` (pass the value into the builder)
- Modify: `cmd/main.go` (flag + reconciler field)
- Modify: `internal/controller/kdexinternalhost_controller.go:65-81` (reconciler struct field)
- Modify: `chart/values.yaml`, `chart/templates/deployment.yaml`
- Modify: `internal/auth/exchange_rotation_race_test.go` (rewrite the #71 test, keep a strict-mode variant)
- Create: `internal/auth/exchange_grace_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `auth.Config.RefreshGraceWindow time.Duration`
  - `(*auth.ConfigBuilder).WithRefreshGraceWindow(d time.Duration) *ConfigBuilder`
  - Exchanger internals `refreshGraceCache cache.Cache`, `refreshGraceWindow time.Duration`, and unexported helpers `publishToGrace`, `replayFromGrace`.
  - `RedeemRefreshToken`'s signature is **unchanged**.

- [ ] **Step 1: Rewrite the #71 test and write the new failing tests**

Replace `TestRedeemRefreshToken_ConcurrentRedemptionsHaveSingleWinner` in
`internal/auth/exchange_rotation_race_test.go` (lines 69-118) with these two
tests. Keep everything above line 69 — the stub provider and
`newRotationTestExchanger` — exactly as it is.

```go
// TestRedeemRefreshToken_StrictModeHasSingleWinner preserves the original
// kdex-tech/host-manager#71 assertion. Pre-#71, the Get-then-Delete pattern
// let two concurrent redemptions both pass Get before either reached
// Delete: both minted parallel session lineages, defeating rotation-based
// theft detection. The atomic GetAndDelete produces exactly one winner.
//
// With the #169 grace window DISABLED (0), this is still the observable
// behavior, which is why the grace window is configurable rather than
// unconditional.
func TestRedeemRefreshToken_StrictModeHasSingleWinner(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ex.refreshGraceCache = nil // grace window off
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	const goroutines = 32
	var winners atomic.Int32
	var notFound atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ts, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
			if err == nil && ts.AccessToken != "" {
				winners.Add(1)
				return
			}
			notFound.Add(1)
		}()
	}
	close(start)
	wg.Wait()

	assert.EqualValues(t, 1, winners.Load(),
		"with the grace window off, exactly one of %d concurrent redemptions must succeed (#71)", goroutines)
	assert.EqualValues(t, goroutines-1, notFound.Load(),
		"every loser must be rejected as not-found (atomic GetAndDelete contract)")
}

// TestRedeemRefreshToken_ConcurrentRedemptionsShareOneRotation pins
// kdex-tech/host-manager#169. Real clients fire 4-5 refreshes within a few
// hundred milliseconds; strict rotation failed all but one, and combined
// with #168's missing invalid_grant signal that left clients unrecoverable.
//
// Every concurrent caller must now succeed with the IDENTICAL pair, and
// exactly one rotation must have occurred — that second assertion is what
// keeps #71 intact. Losers replay the winner's result; they mint nothing.
func TestRedeemRefreshToken_ConcurrentRedemptionsShareOneRotation(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	const goroutines = 32
	results := make([]TokenSet, goroutines)
	errs := make([]error, goroutines)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = ex.RedeemRefreshToken(ctx, tokenID, "app")
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d lost the rotation race (#169)", i)
		require.NotEmpty(t, results[i].AccessToken, "caller %d got an empty access token", i)
	}

	// Every caller holds the SAME rotated refresh token -> exactly one
	// rotation happened -> exactly one session lineage exists (#71 holds).
	want := results[0].RefreshToken
	require.NotEmpty(t, want)
	for i, got := range results {
		assert.Equal(t, want, got.RefreshToken,
			"caller %d received a different refresh token; that would mean a second lineage was minted (#71)", i)
	}

	// And that one rotated token is live, while the consumed one is not.
	_, found, _, err := ex.refreshTokenCache.Get(ctx, want)
	require.NoError(t, err)
	assert.True(t, found, "the single rotated refresh token must be live")

	_, found, _, err = ex.refreshTokenCache.Get(ctx, tokenID)
	require.NoError(t, err)
	assert.False(t, found, "the consumed refresh token must be gone")
}
```

Then create `internal/auth/exchange_grace_test.go`:

```go
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshGrace_ExpiresAfterWindow confirms the grace window is a
// WINDOW: once it lapses, a re-presented token is rejected exactly as it is
// today, so rotation's replay protection still holds outside it.
func TestRefreshGrace_ExpiresAfterWindow(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ex.refreshGraceWindow = 50 * time.Millisecond
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	first, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err)

	// Inside the window: replayed.
	replayed, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err, "a re-presentation inside the grace window must be replayed (#169)")
	assert.Equal(t, first.RefreshToken, replayed.RefreshToken)

	// Outside it: rejected.
	time.Sleep(150 * time.Millisecond)
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	assert.Error(t, err,
		"once the grace window lapses, a consumed token must be rejected again")
}

// TestRefreshGrace_RejectedWinnerPublishesNothing pins the accepted
// asymmetry from the design: when the winner's redemption FAILS validation,
// the token is consumed but no grace entry is written, so a concurrent
// loser falls through to not-found rather than replaying a failure. Caching
// a rejection would mean serving a failure from a cache.
func TestRefreshGrace_RejectedWinnerPublishesNothing(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// Wrong client_id: the winner consumes the token and is rejected.
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "some-other-client")
	require.Error(t, err)

	// Nothing was published, so a follow-up sees not-found.
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	assert.Error(t, err, "a rejected redemption must publish no grace entry")
}

// TestRefreshGrace_PollSurvivesSetVisibilityGap covers the sub-race the
// design calls out: a loser can arrive after the winner's GetAndDelete but
// before its Set, an interval that is a network round trip under Valkey.
// The loser polls rather than failing immediately.
func TestRefreshGrace_PollSurvivesSetVisibilityGap(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	// Publish the grace entry only after a delay shorter than the poll
	// ceiling, simulating a winner that is still writing.
	go func() {
		time.Sleep(60 * time.Millisecond)
		ex.publishToGrace(ctx, "in-flight-token", TokenSet{
			AccessToken:  "at",
			RefreshToken: "rt",
			Subject:      "alice",
		})
	}()

	ts, ok := ex.replayFromGrace(ctx, "in-flight-token")
	require.True(t, ok,
		"the loser must poll past the set-visibility gap, not fail on the first miss (#169)")
	assert.Equal(t, "rt", ts.RefreshToken)
}

// TestRefreshGrace_PollGivesUp confirms the poll is bounded: a token that
// was never published must not hang the request for the full ceiling
// forever, and must return not-found.
func TestRefreshGrace_PollGivesUp(t *testing.T) {
	ex := newRotationTestExchanger(t)

	start := time.Now()
	_, ok := ex.replayFromGrace(context.Background(), "never-published")
	elapsed := time.Since(start)

	assert.False(t, ok, "an unpublished token must not replay")
	assert.Less(t, elapsed, time.Second,
		"the poll must be bounded well under a second (10 x 20ms)")
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/ -run 'RefreshGrace|ShareOneRotation|StrictMode' -v`
Expected: FAIL to compile — `ex.refreshGraceCache` and `ex.refreshGraceWindow` are undefined.

- [ ] **Step 3: Add the config field**

In `internal/auth/config.go`, add to the `Config` struct (near
`RefreshTokenTTL` at ~line 71):

```go
	// RefreshGraceWindow keeps a rotated refresh token's RESULT replayable
	// for a short period so concurrent refreshes from one client do not
	// race (RFC 9700 4.14; kdex-tech/host-manager#169). Zero disables it,
	// restoring strict single-winner rotation.
	//
	// Deliberately NOT a KDexHost.spec.auth field: a CRD change would force
	// a paired nexus-manager release. Per-host override goes through
	// KDexHost.spec.helm.hostManager.values instead.
	RefreshGraceWindow time.Duration
```

Add to the `ConfigBuilder` struct (~line 107):

```go
	RefreshGraceWindow time.Duration
```

Add the builder method next to `WithDevMode`:

```go
func (cb *ConfigBuilder) WithRefreshGraceWindow(d time.Duration) *ConfigBuilder {
	cb.RefreshGraceWindow = d
	return cb
}
```

In `Build`, next to where `cfg.RefreshTokenTTL` is set (~line 217), add:

```go
	cfg.RefreshGraceWindow = cb.RefreshGraceWindow
```

- [ ] **Step 4: Wire the cache and the redemption changes**

In `internal/auth/exchange.go`, add to the `Exchanger` struct (next to
`refreshTokenCache` at ~line 42):

```go
	refreshGraceCache  cache.Cache
	refreshGraceWindow time.Duration
```

In `NewExchanger`, inside the `if cacheManager != nil {` block (after the
`refresh-tokens` cache is created at ~line 113-116), add:

```go
		// Grace window for concurrent refresh presentations (#169). Holds
		// the winner's MINTED RESULT keyed by the CONSUMED token id, so
		// losers replay it rather than minting a second lineage.
		if cfg.RefreshGraceWindow > 0 {
			gw := cfg.RefreshGraceWindow
			ex.refreshGraceWindow = gw
			ex.refreshGraceCache = cacheManager.GetCache("refresh-grace", cache.CacheOptions{
				TTL:      &gw,
				Uncycled: true,
			})
		}
```

Add these constants and helpers at the bottom of `exchange.go`:

```go
// graceReplayAttempts and graceReplayInterval bound the poll a losing caller
// does while the winner is still publishing its result. A loser can arrive
// after the winner's GetAndDelete but before its Set, an interval that is
// sub-millisecond in memory but a network round trip under Valkey. Bounded
// at 200ms; the winner either publishes within it or has failed, in which
// case not-found is the correct answer.
const (
	graceReplayAttempts = 10
	graceReplayInterval = 20 * time.Millisecond
)

// publishToGrace makes the winner's result replayable for the window. Called
// only on a SUCCESSFUL rotation: a rejected redemption publishes nothing, so
// its concurrent losers fall through to not-found rather than replaying a
// failure. See kdex-tech/host-manager#169.
func (e *Exchanger) publishToGrace(ctx context.Context, tokenID string, ts TokenSet) {
	if e.refreshGraceCache == nil {
		return
	}
	payload, err := json.Marshal(ts)
	if err != nil {
		return
	}
	_ = e.refreshGraceCache.Set(ctx, tokenID, string(payload), cache.WithTTL(e.refreshGraceWindow))
}

// replayFromGrace returns the winner's result for a token that was already
// rotated inside the grace window. Exactly one rotation still occurred, so
// #71's single-lineage theft-detection guarantee is preserved: losers mint
// nothing, they receive a copy.
func (e *Exchanger) replayFromGrace(ctx context.Context, tokenID string) (TokenSet, bool) {
	if e.refreshGraceCache == nil {
		return TokenSet{}, false
	}
	for attempt := range graceReplayAttempts {
		raw, found, _, err := e.refreshGraceCache.Get(ctx, tokenID)
		if err == nil && found {
			var ts TokenSet
			if json.Unmarshal([]byte(raw), &ts) != nil {
				return TokenSet{}, false
			}
			return ts, true
		}
		if attempt == graceReplayAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return TokenSet{}, false
		case <-time.After(graceReplayInterval):
		}
	}
	return TokenSet{}, false
}
```

In `RedeemRefreshToken`, change the not-found branch from:

```go
	if !found {
		return TokenSet{}, fmt.Errorf("refresh token not found or expired")
	}
```

to:

```go
	if !found {
		// A concurrent caller may have won the rotation microseconds ago.
		// Replay its result rather than failing this one (#169).
		if ts, ok := e.replayFromGrace(ctx, tokenID); ok {
			return ts, nil
		}
		return TokenSet{}, fmt.Errorf("refresh token not found or expired")
	}
```

and change the successful return at the end from:

```go
	return ts, nil
}
```

to:

```go
	e.publishToGrace(ctx, tokenID, ts)

	return ts, nil
}
```

- [ ] **Step 5: Run the auth tests to verify they pass**

Run: `go test ./internal/auth/ -run 'RefreshGrace|ShareOneRotation|StrictMode' -race -v`
Expected: PASS, 6 tests.

The `-race` flag matters here — this is concurrency code and the shared
`results`/`errs` slices in the rewritten test are only safe because each
goroutine writes a distinct index.

- [ ] **Step 6: Thread the flag from `cmd/main.go` to the builder**

Add to the var block in `cmd/main.go`:

```go
	var refreshGraceWindow time.Duration
```

Add the flag next to the `--server-*` flags from Task 1:

```go
	flag.DurationVar(&refreshGraceWindow, "refresh-grace-window", 10*time.Second,
		"How long a rotated refresh token's result stays replayable, so concurrent refreshes "+
			"from one client do not race (RFC 9700 4.14). Exactly one rotation still occurs; "+
			"losers replay the winner's pair. 0 restores strict single-winner rotation.")
```

Add `RefreshGraceWindow: refreshGraceWindow,` to the
`KDexInternalHostReconciler` literal in `cmd/main.go` (the one already
carrying `RequeueDelay: requeueDelay,` — follow that field's pattern exactly).

Add the field to the reconciler struct at
`internal/controller/kdexinternalhost_controller.go:65-81`, alphabetically
among the exported fields:

```go
	RefreshGraceWindow  time.Duration
```

At `internal/controller/kdexinternalhost_controller.go:529`, chain the
builder call onto the existing `.WithDevMode(...)`:

```go
	).WithRefreshGraceWindow(
		r.RefreshGraceWindow,
	)
```

Match the surrounding call's formatting — read lines 489-531 and follow it
rather than reformatting.

- [ ] **Step 7: Add the chart value**

In `chart/values.yaml`, after the `server:` block added in Task 1:

```yaml

# Refresh-token rotation grace window (RFC 9700 4.14,
# kdex-tech/host-manager#169). Real clients fire several refresh requests in
# parallel; with strict rotation only one could win. Within this window a
# concurrent caller replays the winner's pair instead of failing. Exactly one
# rotation still happens, so rotation-based theft detection is unchanged.
# Set to "0" for strict single-winner rotation.
auth:
  refreshGraceWindow: 10s
```

In `chart/templates/deployment.yaml`, after the `server` block from Task 1:

```yaml
            {{- with .Values.auth }}
            - --refresh-grace-window={{ .refreshGraceWindow }}
            {{- end }}
```

Again no inner `{{- with }}` guard, for the same reason as Task 1: `0` must render.

- [ ] **Step 8: Add the chart render test**

Append to `chart/render_test.go`:

```go
// TestRefreshGraceWindowArg pins that the chart value reaches the flag,
// including 0 (kdex-tech/host-manager#169).
func TestRefreshGraceWindowArg(t *testing.T) {
	if got := renderChart(t); !strings.Contains(got, "--refresh-grace-window=10s") {
		t.Errorf("default refresh grace window not rendered:\n%s", got)
	}
	if got := renderChart(t, "auth.refreshGraceWindow=0"); !strings.Contains(got, "--refresh-grace-window=0") {
		t.Errorf("refreshGraceWindow=0 must render explicitly, not be dropped:\n%s", got)
	}
}
```

- [ ] **Step 9: Run the chart test**

Run: `go test ./chart/ -run TestRefreshGraceWindowArg -v && make lint-chart`
Expected: PASS.

- [ ] **Step 10: Full verification**

Run: `make lint && make test`
Expected: both succeed.

- [ ] **Step 11: Commit**

```bash
git add internal/auth/ internal/controller/kdexinternalhost_controller.go cmd/main.go chart/values.yaml chart/templates/deployment.yaml chart/render_test.go
git commit -m "feat(auth): add a refresh-rotation grace window (#169)

Real clients fire 4-5 refresh requests within a few hundred
milliseconds; strict rotation failed all but one, and combined with the
missing invalid_grant signal that left one MCP client permanently
unrecoverable.

Within the grace window a concurrent caller replays the winner's minted
pair rather than being rejected. The atomic GetAndDelete is untouched,
so exactly one rotation and one session lineage still occur and #71's
theft-detection guarantee is preserved verbatim — a thief presenting the
token inside the window gets what the legitimate client already holds,
and presentation after the window is rejected as before.

Configured by --refresh-grace-window / chart auth.refreshGraceWindow;
0 restores strict single-winner rotation, which is how #71's original
assertion survives as a live test.

Deliberately a flag rather than a KDexHost.spec.auth field: a CRD change
would force a paired nexus-manager release.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Release v0.5.0

**Files:**
- No source changes. `chart/Chart.yaml` is **not** edited — CI derives the version from the tag.

**Interfaces:**
- Consumes: Tasks 1-5, all committed on `feat/streaming-deadlines-oauth-conformance`.
- Produces: tag `v0.5.0`, chart `host-manager-0.5.0`, image `ghcr.io/kdex-tech/host-manager:0.5.0`.

- [ ] **Step 1: Full verification from a clean tree**

```bash
git status --porcelain   # must be empty
make lint
make test
```

Expected: clean tree, both targets succeed.

- [ ] **Step 2: Confirm every issue has a test that would fail without its fix**

```bash
go test ./internal/web/middleware/ -run TestWithStreamDeadline -v    # #167
go test ./internal/auth/ -run TestTokenHandler -v                    # #168
go test ./internal/auth/ -run 'ShareOneRotation|RefreshGrace' -race -v  # #169
```

Expected: all PASS. If any of the three has no test, the corresponding task was not completed — stop and report.

- [ ] **Step 3: Merge to main**

```bash
git checkout main
git merge --no-ff feat/streaming-deadlines-oauth-conformance
git push origin main
```

- [ ] **Step 4: Tag and push**

```bash
git tag v0.5.0
git push origin v0.5.0
```

v0.5.0 rather than v0.4.29: #168 changes response status codes on a public endpoint, which is a behavior change and does not belong in a patch bump.

- [ ] **Step 5: Watch CI**

```bash
gh run watch "$(gh run list --workflow=ci.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
```

Expected: green. The tag run publishes the chart via `.github/actions/publish-helm-chart`, which derives both `--version` and `--app-version` from the tag.

- [ ] **Step 6: Verify the published artifacts**

```bash
gh release view v0.5.0 2>/dev/null || echo "no GitHub release (chart+image are the artifacts)"
```

Confirm the chart `host-manager-0.5.0` and image tag `0.5.0` exist in the GHCR package listing before deploying.

- [ ] **Step 7: Report and hand off the deploy**

Post-deploy verification below requires cluster access and a live dev
environment; it is the operator's step, not part of this plan's automation.
Report to the user:

- the tag and CI run URL;
- that `hostDefault.chart.version` in the kcnas-operator config must move to `0.5.0` for dev, be verified, then prod;
- the four post-deploy checks:
  1. `curl -N` the MCP SSE surface through the host — the stream must survive well past 60s with keep-alives at t+60/75/90s (#167).
  2. `curl -i -X POST https://<host>/-/token -d grant_type=refresh_token -d refresh_token=DEADBEEFNOTAREALTOKEN000000 -d client_id=<id>` returns `400` + `application/json` + `{"error":"invalid_grant"}` (#168).
  3. Fire 5 parallel refreshes with the same token — all 5 return `200` with an identical `refresh_token` (#169).
  4. Confirm `codex-mcp-client` reaches `initialize` — the end-to-end signal that #168 and #169 together resolved the deadlock.

---

## Notes for the implementer

**Every identifier in this plan is verified against the source.** The token
endpoint's receiver is `*OAuth2` (`internal/auth/oauth2.go:16`) and its method
is `OAuth2TokenHandler` (line 233); `renderChart` is variadic
(`chart/render_test.go:47`); `newRotationTestExchanger` is at
`internal/auth/exchange_rotation_race_test.go:41`. Line numbers cited
throughout are from `v0.4.28` and shift as you edit — match on the quoted code,
not the line number, once a file has been touched.

**Task order matters in two places.** Task 2 depends on Task 1's `Timeouts`
parameter, and Task 4 depends on Task 3's `ErrServerError`. Tasks 1-2, 3-4,
and 5 are three independent tracks that could otherwise proceed in parallel.

**When an existing test asserts the old behavior, it is asserting the bug.**
Update it to the new expectation and cite the issue number in the assertion
message. Do not weaken a new test to accommodate an old one.

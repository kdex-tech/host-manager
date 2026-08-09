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

const (
	testWriteTimeout = 200 * time.Millisecond
	// testStallTimeout is the SSE window. Deliberately a large multiple of
	// testWriteTimeout so a test can tell the two windows apart: a cadence
	// between them survives on the SSE window and is severed on the
	// chunked one.
	testStallTimeout = 10 * testWriteTimeout // 2s
)

// serve starts an httptest server whose connection-level WriteTimeout is
// testWriteTimeout and whose handler is wrapped by WithStreamDeadline with
// the standard testStallTimeout SSE window.
func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	return serveWithStall(t, testStallTimeout, h)
}

// serveWithStall is serve with an explicit SSE stall window, for the tests
// that are ABOUT that window.
func serveWithStall(t *testing.T, stall time.Duration, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(WithStreamDeadline(testWriteTimeout, stall)(h))
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
		"SSE stream was severed mid-body — the per-request write deadline did not move to the SSE window (#167)")
	assert.Equal(t, 5, strings.Count(string(body), ": keepalive"),
		"every keep-alive must arrive; got:\n%s", body)
}

// TestWithStreamDeadline_SSEStallIsCutAtStreamStallTimeout pins quad-findings
// item 1: SSE is bounded on its OWN window, not exempt from bounding.
//
// The handler proves both halves in one run against a 200ms WriteTimeout and
// a 400ms stall window:
//
//   - "mid-stream" arrives after a 300ms silence. 300ms exceeds
//     writeTimeout, so the response is demonstrably NOT on the chunked
//     window — the SSE window is genuinely separate and larger.
//   - "after-stall" does NOT arrive after a silence far beyond the stall
//     window. Against the previous implementation, which called
//     SetWriteDeadline(time.Time{}) for SSE, this write succeeds and the
//     assertion fails: that code had no bound at all, so a consumer that
//     stopped reading parked the proxy in conn.Write until TCP keepalive
//     (~2h11m), pinning a goroutine, an FD, the upstream connection and
//     ReverseProxy's 32KB buffer.
func TestWithStreamDeadline_SSEStallIsCutAtStreamStallTimeout(t *testing.T) {
	const stall = 2 * testWriteTimeout // 400ms
	srv := serveWithStall(t, stall, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		_, _ = fmt.Fprint(w, ": opened\n\n")
		_ = http.NewResponseController(w).Flush()

		// Longer than writeTimeout, shorter than the stall window.
		time.Sleep(3 * testWriteTimeout / 2)
		_, _ = fmt.Fprint(w, ": mid-stream\n\n")
		_ = http.NewResponseController(w).Flush()

		// Far beyond the stall window.
		time.Sleep(4 * stall)
		_, _ = fmt.Fprint(w, ": after-stall\n\n")
		_ = http.NewResponseController(w).Flush()
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), ": mid-stream",
		"a silence longer than writeTimeout but shorter than streamStallTimeout must survive — "+
			"SSE runs on its own, larger window")
	assert.NotContains(t, string(body), ": after-stall",
		"an SSE stream that stalls past streamStallTimeout must still be cut (quad-findings item 1); "+
			"clearing the deadline outright left a stalled consumer holding the connection for hours")
}

// TestWithStreamDeadline_SSEStallTimeoutZeroClearsDeadline pins the
// documented escape hatch: streamStallTimeout <= 0 restores the earlier
// "clear the deadline for SSE" behavior, for a backend whose legitimate
// silence can exceed any window an operator would pick.
func TestWithStreamDeadline_SSEStallTimeoutZeroClearsDeadline(t *testing.T) {
	srv := serveWithStall(t, 0, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, ": opened\n\n")
		_ = http.NewResponseController(w).Flush()
		time.Sleep(4 * testWriteTimeout)
		_, _ = fmt.Fprint(w, ": after-stall\n\n")
		_ = http.NewResponseController(w).Flush()
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), ": after-stall",
		"streamStallTimeout=0 must clear the SSE deadline outright, matching the documented escape hatch")
}

// TestWithStreamDeadline_EarlyHintsBeforeSSEGetsSSEWindow pins quad-findings
// item 3 (#167 verbatim). httputil.ReverseProxy forwards a backend's 103
// Early Hints by copying the 1xx headers into rw.Header(), calling
// rw.WriteHeader(103), and then CLEARING the header map — the handler below
// reproduces that sequence exactly. Before the 1xx guard,
// applyDeadlinePolicyOnce ran on that first WriteHeader and classified the
// response against headers that carry neither Content-Type nor
// Content-Length, so it landed in CHUNKED mode on the writeTimeout window.
//
// The keep-alive cadence here (300ms) sits deliberately BETWEEN the two
// windows: above writeTimeout (200ms) and far below the stall window (2s).
// So this test discriminates on WHICH window was chosen, not merely on the
// response surviving — on the unfixed code the stream is severed after the
// first event and the count assertion fails.
func TestWithStreamDeadline_EarlyHintsBeforeSSEGetsSSEWindow(t *testing.T) {
	const events = 4
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		// ReverseProxy's Got1xxResponse hook does exactly this: the
		// ResponseWriter does not clear the map for informational
		// responses (RFC 8297), so the proxy must.
		clear(h)

		h.Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < events; i++ {
			_, _ = fmt.Fprintf(w, ": keepalive %d\n\n", i)
			_ = http.NewResponseController(w).Flush()
			time.Sleep(3 * testWriteTimeout / 2)
		}
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err,
		"SSE stream preceded by 103 Early Hints was severed — the policy was decided against the "+
			"1xx headers and the response got the chunked window (quad-findings item 3)")
	assert.Equal(t, events, strings.Count(string(body), ": keepalive"),
		"a cadence between writeTimeout and streamStallTimeout must survive, proving the SSE window "+
			"was chosen despite the preceding 103; got:\n%s", body)
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
//
// It also discriminates the two windows in the other direction: the stall
// here (4x writeTimeout = 800ms) is well inside testStallTimeout (2s), so a
// chunked response that wrongly picked up the SSE window would survive and
// this test would fail.
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

// TestWithStreamDeadline_ChunkedWithoutFlushStaysBounded pins the boundary
// documented in applyDeadlinePolicyOnce and Flush: the sliding deadline is
// only extended by an explicit Flush, not by bytes handed to Write. After
// an initial flush establishes the response (so the client actually
// receives it), a handler that keeps writing — genuinely making progress
// from its own point of view — but never flushes again leaves the deadline
// exactly where that first Flush left it. The response is therefore still
// bounded by that stale deadline, the same as the pre-#167 behavior, even
// though writes kept happening. Not a regression: the one production
// consumer of the sliding path, httputil.ReverseProxy, always flushes for
// a response with no Content-Length (see applyDeadlinePolicyOnce) — but
// the boundary must be asserted here, not assumed.
func TestWithStreamDeadline_ChunkedWithoutFlushStaysBounded(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "before-stall\n")
		_ = http.NewResponseController(w).Flush()

		time.Sleep(4 * testWriteTimeout)

		// Deliberately no Flush after this write: Write alone must not
		// extend the deadline armed by the flush above.
		_, _ = fmt.Fprint(w, "after-stall\n")
	})

	resp, err := http.Get(srv.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "after-stall",
		"a chunked response that writes without flushing again must remain bounded by the last-armed deadline")
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
	wrapped := WithStreamDeadline(0, testStallTimeout)(inner)

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
	srv := httptest.NewUnstartedServer(WithStreamDeadline(testWriteTimeout, testStallTimeout)(
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

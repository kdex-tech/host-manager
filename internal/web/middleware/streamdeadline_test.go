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

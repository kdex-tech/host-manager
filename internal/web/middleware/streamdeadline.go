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
//
// streamStallTimeout is the SEPARATE, much larger window an SSE response
// slides on. SSE is not exempt from bounding — it is bounded on its own
// terms. Clearing the deadline outright (the first #167 implementation)
// left a consumer that stops reading parked in Flush->conn.Write under TCP
// backpressure with nothing to cut it: the request context cancels on
// close, not on a stalled reader, so Linux TCP keepalive reaped it at
// ~2h11m where pre-#167 it died at writeTimeout. Nothing else in the repo
// covers that — ReadTimeout/ReadHeaderTimeout bound the request only,
// IdleTimeout bounds inter-request idle only, and there is no
// ConnState/LimitListener/TimeoutHandler — and each held connection pins a
// goroutine, an FD, the upstream connection and ReverseProxy's 32KB
// buffer. The design's rationale ("the cadence belongs to the backend")
// argues against a CADENCE-SIZED cap, not against any cap: at the 5m
// default a healthy stream runs unbounded at 20x the 15s keep-alive
// cadence of the affected backends, while a stalled one dies in minutes.
// Zero or less restores the cleared-deadline behavior for SSE, which is
// the documented escape hatch for a backend whose legitimate silence can
// exceed any window.
func WithStreamDeadline(writeTimeout, streamStallTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if writeTimeout <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&streamWriter{
				ResponseWriter: w,
				writeTimeout:   writeTimeout,
				stallTimeout:   streamStallTimeout,
			}, r)
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
	stallTimeout time.Duration
	// slideWindow is zero when this response is not in sliding mode, and
	// otherwise the window Flush re-arms: writeTimeout for the chunked
	// case, stallTimeout for the SSE case. Storing the window rather than
	// a bool is what keeps the two paths on their own budgets.
	slideWindow time.Duration
	wroteHeader bool
}

// Unwrap lets http.ResponseController reach the underlying writer's
// SetWriteDeadline. Without it every deadline call returns
// http.ErrNotSupported and #167 silently regresses.
func (s *streamWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *streamWriter) WriteHeader(code int) {
	// A 1xx informational response is NOT the final response head, so the
	// headers accompanying it must not decide this response's policy.
	// httputil.ReverseProxy forwards a backend's `103 Early Hints` by
	// copying the 1xx headers in, calling rw.WriteHeader(103), then
	// CLEARING the header map before the real 200 arrives (its
	// httptrace.Got1xxResponse hook). Without this guard a backend that
	// emits 103 before `200 text/event-stream` had its policy decided
	// against the 1xx headers — no Content-Type, no Content-Length — and
	// landed in the CHUNKED window (writeTimeout) rather than the SSE one
	// (stallTimeout), silently re-severing exactly the streams #167
	// exists to keep alive. See #167 and
	// TestWithStreamDeadline_EarlyHintsBeforeSSEStillGetsSSEWindow, which
	// discriminates on WHICH window was chosen, not merely on survival.
	//
	// 101 Switching Protocols takes this path too: an upgraded connection
	// is governed by Hijack (below), not by any deadline policy we would
	// pick from its headers.
	if code < 200 {
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.applyDeadlinePolicyOnce()
	s.ResponseWriter.WriteHeader(code)
}

func (s *streamWriter) Write(p []byte) (int, error) {
	// A handler may Write without an explicit WriteHeader; the stdlib
	// implies 200 on the INNER writer, which would skip our policy.
	//
	// Deliberately NOT touched here: the deadline. http.response.Write
	// only copies into its internal bufio buffer for small payloads — it
	// does not necessarily touch the socket — so a deadline extension
	// keyed off Write() would arm a fresh window at a time that has
	// nothing to do with when bytes actually left the process. The
	// extension belongs where the real I/O happens: Flush.
	s.applyDeadlinePolicyOnce()
	return s.ResponseWriter.Write(p)
}

// applyDeadlinePolicyOnce runs exactly once, when the response headers are
// final (see WriteHeader's 1xx guard for what "final" excludes). The three
// cases are ordered and first-match-wins: an SSE response ALSO has no
// Content-Length, so the event-stream check must be evaluated first or SSE
// would land on the CHUNKED window and still die on a backend whose
// keep-alive interval exceeds writeTimeout.
func (s *streamWriter) applyDeadlinePolicyOnce() {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true

	h := s.Header()

	// 1. Server-Sent Events: slide on the SEPARATE, much larger
	//    stallTimeout window. The keep-alive cadence belongs to the
	//    backend and may exceed writeTimeout, so the cadence-sized window
	//    is wrong for SSE — but a window still bounds a stalled stream
	//    (see WithStreamDeadline's doc comment for why "no window at all"
	//    was worse than the bug it fixed).
	//
	//    The deadline is armed HERE, not left until the first Flush the
	//    way the chunked case is: until something re-arms it, the
	//    connection-level WriteTimeout is still in force, and an SSE
	//    backend whose FIRST event arrives later than writeTimeout would
	//    be severed before ever reaching Flush.
	if strings.HasPrefix(h.Get("Content-Type"), "text/event-stream") {
		rc := http.NewResponseController(s.ResponseWriter)
		if s.stallTimeout <= 0 {
			// Documented escape hatch: no stall window configured means
			// the pre-existing "clear it outright" behavior.
			_ = rc.SetWriteDeadline(time.Time{})
			return
		}
		s.slideWindow = s.stallTimeout
		_ = rc.SetWriteDeadline(time.Now().Add(s.stallTimeout))
		return
	}

	// 2. Chunked / unknown length: slide the deadline on each write.
	//
	//    "Progress" here means an explicit Flush call, not bytes handed to
	//    Write. A handler that Writes a large body and never calls Flush
	//    still sets slideWindow but the deadline is never extended: the
	//    wrapper only observes Flush (see Flush below), while
	//    http.response's internal bufio buffer auto-flushes to the socket
	//    on its own once it fills, doing real I/O the wrapper never sees.
	//    Such a handler is therefore still bounded by whatever deadline
	//    was last set (typically the server's original connection-level
	//    one) even though it is genuinely making progress. Not a
	//    regression — the pre-#167 behavior was "always bounded" — but it
	//    means the sliding cap only helps handlers that flush. The one
	//    production consumer of this path, httputil.ReverseProxy, always
	//    does: ReverseProxy.flushInterval returns -1 (flush after every
	//    write) whenever ContentLength == -1, which is exactly this case.
	//    See TestWithStreamDeadline_ChunkedWithoutFlushStaysBounded, which
	//    pins this boundary rather than leaving it assumed.
	if h.Get("Content-Length") == "" {
		s.slideWindow = s.writeTimeout
		return
	}

	// 3. Fixed-length: leave the connection-level deadline alone.
}

// Flush keeps ReverseProxy's maxLatencyWriter flushing per chunk, and is
// also where the sliding deadline is extended.
//
// The extension has to live here rather than in Write: Write only copies
// into http.response's internal bufio buffer for small payloads and does
// not necessarily touch the socket, so a deadline set relative to Write's
// call time would always land in the future regardless of how long the
// handler had been silent beforehand — the stale, already-elapsed deadline
// would be overwritten right before the real I/O ever happens, and the
// stall cap (#167's "sliding, not clearing" requirement for chunked
// responses) would never fire. Flush is where bytes actually reach the
// connection, so extending AFTER it succeeds means the deadline armed here
// is what governs the gap before the *next* real flush: if that gap
// exceeds writeTimeout, the runtime's own timer has already marked the
// deadline expired by the time the next Flush is attempted, so it fails
// immediately instead of getting a fresh window.
//
// One deadline, two jobs — a known, accepted trade-off: the same window
// bounds both "how long can the handler stay silent between flushes" AND
// "how long may this flush's own socket write take once TCP backpressure
// makes it block." A flush at T sets the deadline to T+slideWindow; a
// flush that then lands at T+Δ has only slideWindow-Δ left for its own
// write to complete. A cadence that runs right up against the window
// therefore leaves near-zero budget for the write itself, and a slow
// client's ordinary backpressure — not just a genuine stall — can cut the
// response. This is benign at the ~60s chunked / 5m SSE defaults
// (production cadences are far below both), but it means the window is
// implicitly a ceiling on how close together flushes may usefully be, not
// just a stall cap.
//
// slideWindow, not writeTimeout: an SSE response re-arms its own, much
// larger stallTimeout window here (see applyDeadlinePolicyOnce case 1), so
// the two streaming paths never share a budget.
func (s *streamWriter) Flush() {
	s.applyDeadlinePolicyOnce()

	rc := http.NewResponseController(s.ResponseWriter)
	_ = rc.Flush()

	if s.slideWindow > 0 {
		_ = rc.SetWriteDeadline(time.Now().Add(s.slideWindow))
	}
}

// Hijack delegates so httputil.ReverseProxy can still service Upgrade
// requests. A wrapper that swallows Hijack breaks WebSocket proxying.
func (s *streamWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

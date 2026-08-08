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
// final. The three cases are ordered and first-match-wins: an SSE response
// ALSO has no Content-Length, so the event-stream check must be evaluated
// first or SSE would land in sliding mode and still die on a backend whose
// keep-alive interval exceeds writeTimeout.
func (s *streamWriter) applyDeadlinePolicyOnce() {
	if s.wroteHeader {
		return
	}
	s.wroteHeader = true

	h := s.Header()

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
func (s *streamWriter) Flush() {
	s.applyDeadlinePolicyOnce()

	rc := http.NewResponseController(s.ResponseWriter)
	_ = rc.Flush()

	if s.sliding {
		_ = rc.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
}

// Hijack delegates so httputil.ReverseProxy can still service Upgrade
// requests. A wrapper that swallows Hijack breaks WebSocket proxying.
func (s *streamWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

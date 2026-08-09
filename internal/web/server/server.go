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
	// StreamStallTimeout is NOT an http.Server field. It is the separate,
	// much larger sliding window a text/event-stream response runs on, so
	// SSE is bounded on its own terms rather than by WriteTimeout (which
	// is cadence-sized and severed real streams — #167) or by nothing at
	// all (which left a stalled consumer holding the connection until TCP
	// keepalive, ~2h11m). See middleware.WithStreamDeadline.
	StreamStallTimeout time.Duration
}

// DefaultTimeouts is the conservative pairing shipped since #49. The proxy
// round-trip path already tolerates 60s cold starts via its own
// ResponseHeaderTimeout, so 60s read/write matches it.
//
// StreamStallTimeout is 5m: 20x the 15s keep-alive cadence of the SSE
// backends #167 was reported against, so a healthy stream is effectively
// unbounded, while a stalled one is reclaimed in minutes instead of hours.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		ReadHeaderTimeout:  10 * time.Second,
		ReadTimeout:        60 * time.Second,
		WriteTimeout:       60 * time.Second,
		IdleTimeout:        120 * time.Second,
		StreamStallTimeout: 5 * time.Minute,
	}
}

// Normalized returns t with StreamStallTimeout clamped UP to WriteTimeout
// when an operator has configured the stall window below it, and reports
// whether that clamp happened.
//
// StreamStallTimeout is the window a text/event-stream response slides on;
// WriteTimeout is the window every other chunked response slides on. The
// design intent is that the stall window is much larger (5m against 60s by
// default). Setting it lower makes SSE strictly MORE fragile than the
// ordinary chunked responses it exists to protect — the exact inversion of
// what the setting is for. See kdex-tech/host-manager#173.
//
// Clamped rather than rejected, following the --refresh-grace-window
// precedent in internal/auth/exchange.go: this process is the site's serving
// path, and refusing to start over one flag takes the whole host down, which
// is a worse outcome than running with a safe window. The caller reports the
// clamp so an operator whose applied config no longer matches what they wrote
// can see it.
//
// Zero is MEANINGFUL in both fields and is never clamped: a zero
// StreamStallTimeout clears the SSE deadline outright (the documented
// --server-stream-stall-timeout setting), and a zero WriteTimeout disables
// deadlines entirely, leaving no window for SSE to be more fragile than.
func (t Timeouts) Normalized() (Timeouts, bool) {
	if t.WriteTimeout > 0 && t.StreamStallTimeout > 0 && t.StreamStallTimeout < t.WriteTimeout {
		t.StreamStallTimeout = t.WriteTimeout
		return t, true
	}
	return t, false
}

// New builds the inbound webserver and returns it alongside the timeouts it
// actually applied. The second return exists because Normalized may clamp an
// inverted stall window (#173): an operator whose applied configuration no
// longer matches what they wrote must be able to see that in the logs, and
// only the caller has the startup logger.
func New(address string, hostHandler *host.HostHandler, timeouts Timeouts) (*http.Server, Timeouts) {
	timeouts, _ = timeouts.Normalized()

	handler := middleware.WithLogger(
		logf.Log.WithName("server"),
	)(
		middleware.WithStreamDeadline(timeouts.WriteTimeout, timeouts.StreamStallTimeout)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hostHandler.ServeHTTP(w, r)
			}),
		),
	)

	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: timeouts.ReadHeaderTimeout,
		ReadTimeout:       timeouts.ReadTimeout,
		WriteTimeout:      timeouts.WriteTimeout,
		IdleTimeout:       timeouts.IdleTimeout,
	}, timeouts
}

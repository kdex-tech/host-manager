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

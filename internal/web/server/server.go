package server

import (
	"net/http"
	"time"

	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/web/middleware"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func New(address string, hostHandler *host.HostHandler) *http.Server {
	handler := middleware.WithLogger(
		logf.Log.WithName("server"),
	)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hostHandler.ServeHTTP(w, r)
		}),
	)

	return &http.Server{
		Addr:    address,
		Handler: handler,
		// Bound exposure on every accepted connection. Zero (the
		// stdlib default) means "no timeout" — a single slow client
		// can hold a goroutine + FD indefinitely (Slowloris). The
		// proxy round-trip path already tolerates 60s cold starts
		// via its own ResponseHeaderTimeout, so 60s read/write is
		// the conservative pairing. See kdex-tech/host-manager#49.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

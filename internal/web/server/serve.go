package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// Serve runs srv on ln until ctx is done, then drains: it keeps serving for
// drain, so the load balancer and ingress stop routing to this pod before its
// listener closes, and only then shuts down gracefully, giving in-flight
// requests up to shutdownTimeout. The returned channel closes once the server
// has stopped; main must wait on it, or the process exits mid-drain.
//
// Without the drain, SIGTERM closed the listener at once, while the old pod
// was still in the Service's endpoints as seen by Traefik and the load
// balancer, so a rollout answered one or two requests with 502.
func Serve(
	ctx context.Context,
	srv *http.Server,
	ln net.Listener,
	drain, shutdownTimeout time.Duration,
	log logr.Logger,
) <-chan struct{} {
	done := make(chan struct{})
	served := make(chan struct{})

	go func() {
		defer close(served)
		log.Info("starting web server", "address", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error(err, "problem running web server")
		}
	}()

	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-served: // the server failed on its own: nothing to drain
			return
		}
		if drain > 0 {
			log.Info("draining web server before shutdown", "drain", drain.String())
			select {
			case <-time.After(drain):
			case <-served:
				return
			}
		}
		log.Info("shutting down web server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error(err, "problem shutting down web server")
		}
		<-served
	}()

	return done
}

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
)

// StopTimeout is how long a stopping server gives in-flight requests to
// finish before it closes their connections.
const StopTimeout = 5 * time.Second

// Serve runs srv on ln until ctx is done, then drains: it keeps serving for
// drain, so the load balancer and ingress stop routing to this pod before its
// listener closes, and only then stops gracefully, giving in-flight requests
// up to stopTimeout. The returned channel receives exactly one value once the
// server has stopped -- nil for a requested stop, the error for a server that
// failed on its own -- and is then closed. main must wait on it, or the
// process exits mid-drain, and must exit non-zero on an error.
//
// Without the drain, SIGTERM closed the listener at once, while the old pod
// was still in the Service's endpoints as seen by Traefik and the load
// balancer, so a rollout answered one or two requests with 502.
func Serve(
	ctx context.Context,
	srv *http.Server,
	ln net.Listener,
	drain, stopTimeout time.Duration,
	log logr.Logger,
) <-chan error {
	done := make(chan error, 1)
	served := make(chan error, 1)

	go func() {
		log.Info("starting web server", "address", ln.Addr().String())
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
		close(served)
	}()

	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case err := <-served: // failed on its own: nothing to drain
			log.Error(err, "web server stopped unexpectedly")
			done <- err
			return
		}
		// Responses served from here on carry Connection: close, so a proxy
		// does not keep reusing an upstream connection that is about to go.
		srv.SetKeepAlivesEnabled(false)
		if drain > 0 {
			log.Info("draining web server before stopping it", "drain", drain.String())
			select {
			case <-time.After(drain):
			case err := <-served:
				log.Error(err, "web server stopped unexpectedly during the drain")
				done <- err
				return
			}
		}
		log.Info("stopping web server")
		stopCtx, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		if err := srv.Shutdown(stopCtx); err != nil {
			// A connection still busy at the deadline (a long stream) is
			// closed now, not left to the process exit.
			log.Info("web server stop timed out; closing remaining connections", "err", err.Error())
			_ = srv.Close()
		}
		done <- <-served
	}()

	return done
}

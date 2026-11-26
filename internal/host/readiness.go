package host

import (
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// errHostLoading is the readiness failure while the host has not loaded.
var errHostLoading = errors.New("host not loaded yet")

// Loaded reports whether the host has loaded far enough to take traffic: a
// mux is built (so the system routes, /-/translation among them, exist) and
// the host's last reconcile settled Ready or Degraded. Degraded counts
// because a degraded host serves anyway; Progressing and Initializing do not.
func (hh *HostHandler) Loaded() bool {
	hh.mu.RLock()
	mux := hh.Mux
	hh.mu.RUnlock()
	if mux == nil {
		return false
	}
	switch hh.GetStatus() {
	case HostStatusReady, HostStatusDegraded:
		return true
	default:
		return false
	}
}

// ReadinessCheck returns a readiness checker (controller-runtime's
// healthz.Checker shape) that holds a new pod out of its Service until the
// host has loaded, or until timeout has passed since start, whichever comes
// first.
//
// A bare ping let a rolling update move traffic to a pod whose first
// KDexInternalHost reconcile had not built its mux yet, so every route,
// /-/translation included, answered 404 for a minute or two per rollout. A
// gate with no bound is no better: a host that cannot load (one broken
// reference) would keep the old pod serving beside the new one
// indefinitely, with LeaderElection off and both reconciling (#290). The
// bound keeps the old failure mode only for a host that genuinely does not
// load within timeout.
//
// The result latches: once ready, the pod stays ready, so a later Degraded
// or Progressing reconcile never pulls every endpoint out of the Service.
// timeout <= 0 disables the gate (ready at once, the pre-gate behaviour).
func (hh *HostHandler) ReadinessCheck(start time.Time, timeout time.Duration, now func() time.Time) func(*http.Request) error {
	if now == nil {
		now = time.Now
	}
	var ready atomic.Bool
	return func(*http.Request) error {
		if ready.Load() {
			return nil
		}
		if timeout <= 0 || hh.Loaded() {
			ready.Store(true)
			return nil
		}
		if now().Sub(start) >= timeout {
			ready.Store(true)
			hh.log.Info("readiness timeout elapsed before the host loaded; taking traffic anyway",
				"timeout", timeout.String(), "hostStatus", hh.GetStatus())
			return nil
		}
		return errHostLoading
	}
}

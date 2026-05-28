package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNew_TimeoutsConfigured pins the fix for kdex-tech/host-manager#49:
// the http.Server returned by New must have non-zero ReadHeaderTimeout
// (the cheapest, sharpest Slowloris defense) and bounded
// ReadTimeout/WriteTimeout/IdleTimeout. A zero value in any of these
// fields means "no timeout" in Go's stdlib — a single attacker can
// dribble bytes over a few hundred connections and exhaust the pod's
// goroutines and file descriptors with no traffic-volume signal.
func TestNew_TimeoutsConfigured(t *testing.T) {
	srv := New(":0", nil)

	assert.Greater(t, srv.ReadHeaderTimeout, time.Duration(0),
		"ReadHeaderTimeout must be set to close the Slowloris vector (#49)")
	assert.Greater(t, srv.ReadTimeout, time.Duration(0),
		"ReadTimeout must bound how long a request body read can dangle")
	assert.Greater(t, srv.WriteTimeout, time.Duration(0),
		"WriteTimeout must bound how long a response write can dangle")
	assert.Greater(t, srv.IdleTimeout, time.Duration(0),
		"IdleTimeout must bound keepalive idle exposure")

	assert.LessOrEqual(t, srv.ReadHeaderTimeout, 30*time.Second,
		"ReadHeaderTimeout should be aggressive (≤30s)")
}

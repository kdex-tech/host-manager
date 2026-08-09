package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestDefaultTimeouts pins the fix for kdex-tech/host-manager#49: the
// defaults must have non-zero ReadHeaderTimeout (the cheapest, sharpest
// Slowloris defense) and bounded ReadTimeout/WriteTimeout/IdleTimeout. A
// zero value in any of these fields means "no timeout" in Go's stdlib — a
// single attacker can dribble bytes over a few hundred connections and
// exhaust the pod's goroutines and file descriptors with no traffic-volume
// signal.
//
// #167 made these configurable; this test guards that the DEFAULTS did not
// silently become permissive in the process.
func TestDefaultTimeouts(t *testing.T) {
	d := DefaultTimeouts()

	assert.Greater(t, d.ReadHeaderTimeout, time.Duration(0),
		"ReadHeaderTimeout must be set to close the Slowloris vector (#49)")
	assert.Greater(t, d.ReadTimeout, time.Duration(0),
		"ReadTimeout must bound how long a request body read can dangle")
	assert.Greater(t, d.WriteTimeout, time.Duration(0),
		"WriteTimeout must bound how long a response write can dangle")
	assert.Greater(t, d.IdleTimeout, time.Duration(0),
		"IdleTimeout must bound keepalive idle exposure")

	assert.LessOrEqual(t, d.ReadHeaderTimeout, 30*time.Second,
		"ReadHeaderTimeout should be aggressive (<=30s)")

	// Quad-findings item 1: SSE must be bounded on its own window rather
	// than exempt from bounding. A zero default here means the SSE
	// deadline is cleared outright, which is what left a stalled consumer
	// holding a goroutine, an FD and the upstream connection until TCP
	// keepalive (~2h11m).
	assert.Greater(t, d.StreamStallTimeout, time.Duration(0),
		"StreamStallTimeout must bound a stalled SSE stream (#167 / quad-findings item 1)")
	assert.Greater(t, d.StreamStallTimeout, d.WriteTimeout,
		"the SSE stall window must be larger than the chunked window, or SSE is back on a "+
			"cadence-sized deadline and #167 regresses")
}

// TestNew_AppliesDefaultTimeouts checks the defaults reach the http.Server.
func TestNew_AppliesDefaultTimeouts(t *testing.T) {
	srv, _ := New(":0", nil, DefaultTimeouts())

	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 60*time.Second, srv.ReadTimeout)
	assert.Equal(t, 60*time.Second, srv.WriteTimeout)
	assert.Equal(t, 120*time.Second, srv.IdleTimeout)
}

// TestNew_HonorsExplicitTimeouts checks operator overrides reach the
// http.Server verbatim, including zero, which is stdlib for "no deadline"
// and is the documented escape hatch for #167.
func TestNew_HonorsExplicitTimeouts(t *testing.T) {
	srv, _ := New(":0", nil, Timeouts{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       45 * time.Second,
	})

	assert.Equal(t, 5*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, srv.ReadTimeout)
	assert.Equal(t, time.Duration(0), srv.WriteTimeout,
		"zero must pass through as stdlib 'no deadline', not be replaced by a default")
	assert.Equal(t, 45*time.Second, srv.IdleTimeout)
}

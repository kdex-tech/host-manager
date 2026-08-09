package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNormalized_ClampsInvertedStallWindow pins kdex-tech/host-manager#173.
//
// StreamStallTimeout is the window a text/event-stream response slides on;
// WriteTimeout is the window every OTHER chunked response slides on. The
// design intent (#167) is that the stall window is much LARGER — 5m against
// 60s by default. Nothing enforced that relationship, so an operator who set
// the stall window BELOW WriteTimeout made SSE strictly more fragile than the
// ordinary chunked responses the larger window exists to protect: the exact
// inversion of what the setting is for, and silently.
//
// The fix clamps UP rather than refusing to start, following the
// --refresh-grace-window precedent (internal/auth/exchange.go): this process
// is the site's serving path, and refusing to boot over one flag takes the
// whole host down, which is worse than running with a safe window. The clamp
// is reported so an operator whose applied config differs from what they
// wrote can see it.
func TestNormalized_ClampsInvertedStallWindow(t *testing.T) {
	in := Timeouts{WriteTimeout: 60 * time.Second, StreamStallTimeout: 10 * time.Second}

	got, clamped := in.Normalized()

	assert.True(t, clamped,
		"an inverted stall window must report that it was clamped, or the operator cannot see that the applied config differs from what they wrote")
	assert.Equal(t, 60*time.Second, got.StreamStallTimeout,
		"StreamStallTimeout below WriteTimeout must be clamped UP to WriteTimeout so SSE is never more fragile than ordinary chunked responses")
	assert.Equal(t, 60*time.Second, got.WriteTimeout,
		"WriteTimeout is the reference value and must not be altered")
}

// TestNormalized_LeavesValidPairingsAlone covers every configuration that is
// NOT an inversion. The two zero cases are the load-bearing ones: zero is
// MEANINGFUL in both fields, so a naive `stall < write` comparison would
// clamp legitimate configuration.
//
//   - StreamStallTimeout == 0 is the documented "clear the deadline for SSE
//     outright" setting (--server-stream-stall-timeout help text). Clamping it
//     would silently re-bound a stream the operator deliberately unbounded.
//   - WriteTimeout == 0 disables the deadline entirely, and with it all
//     per-request adjustment — middleware.WithStreamDeadline returns a
//     passthrough. There is no window to be more fragile than.
func TestNormalized_LeavesValidPairingsAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   Timeouts
		why  string
	}{
		{
			name: "stall greater than write",
			in:   Timeouts{WriteTimeout: 60 * time.Second, StreamStallTimeout: 5 * time.Minute},
			why:  "the intended pairing",
		},
		{
			name: "stall equal to write",
			in:   Timeouts{WriteTimeout: 60 * time.Second, StreamStallTimeout: 60 * time.Second},
			why:  "equal is not an inversion; SSE is no worse off than chunked",
		},
		{
			name: "stall zero means SSE deadline cleared outright",
			in:   Timeouts{WriteTimeout: 60 * time.Second, StreamStallTimeout: 0},
			why:  "zero is a deliberate, documented setting, not an inversion",
		},
		{
			name: "write zero disables deadlines entirely",
			in:   Timeouts{WriteTimeout: 0, StreamStallTimeout: 10 * time.Second},
			why:  "with no write deadline there is no window for SSE to be more fragile than",
		},
		{
			name: "both zero",
			in:   Timeouts{WriteTimeout: 0, StreamStallTimeout: 0},
			why:  "nothing to compare",
		},
		{
			name: "shipped defaults",
			in:   DefaultTimeouts(),
			why:  "the defaults must never trip the clamp",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, clamped := tc.in.Normalized()

			assert.False(t, clamped, "must not report a clamp: %s", tc.why)
			assert.Equal(t, tc.in, got, "must be returned unchanged: %s", tc.why)
		})
	}
}

// TestNew_AppliesTheClamp is the wiring guard. Normalized() being correct is
// worth nothing if New never calls it — and a clamp that exists but is not
// reached is exactly the "untested but correct" shape that generated three
// separate defects during the v0.5.0 review. New returns the timeouts it
// actually applied so the caller can log them, which is also what makes this
// assertable without standing up a HostHandler.
func TestNew_AppliesTheClamp(t *testing.T) {
	srv, applied := New(":0", nil, Timeouts{
		ReadHeaderTimeout:  5 * time.Second,
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       60 * time.Second,
		IdleTimeout:        45 * time.Second,
		StreamStallTimeout: 10 * time.Second,
	})

	assert.Equal(t, 60*time.Second, applied.StreamStallTimeout,
		"New must apply the #173 clamp, not pass the operator's inverted value straight to the stream-deadline middleware")
	assert.Equal(t, 60*time.Second, srv.WriteTimeout,
		"the http.Server's own WriteTimeout is the reference value and must be untouched by the clamp")
}

// TestNew_ReportsUnclampedTimeoutsVerbatim is the other half: a valid pairing
// must be reported back exactly as given, so a caller logging `applied` never
// tells an operator their config changed when it did not.
func TestNew_ReportsUnclampedTimeoutsVerbatim(t *testing.T) {
	in := DefaultTimeouts()

	_, applied := New(":0", nil, in)

	assert.Equal(t, in, applied, "an unclamped configuration must be reported verbatim")
}

// TestNormalized_PreservesUnrelatedFields guards against the clamp being
// implemented as a partial struct literal, which would silently zero the
// three inbound timeouts #49 exists to keep non-zero.
func TestNormalized_PreservesUnrelatedFields(t *testing.T) {
	in := Timeouts{
		ReadHeaderTimeout:  7 * time.Second,
		ReadTimeout:        11 * time.Second,
		WriteTimeout:       60 * time.Second,
		IdleTimeout:        13 * time.Second,
		StreamStallTimeout: 1 * time.Second,
	}

	got, clamped := in.Normalized()

	assert.True(t, clamped, "precondition: this case must clamp")
	assert.Equal(t, 7*time.Second, got.ReadHeaderTimeout, "ReadHeaderTimeout must survive the clamp (#49)")
	assert.Equal(t, 11*time.Second, got.ReadTimeout, "ReadTimeout must survive the clamp (#49)")
	assert.Equal(t, 13*time.Second, got.IdleTimeout, "IdleTimeout must survive the clamp (#49)")
}

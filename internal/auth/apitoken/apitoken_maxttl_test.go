package apitoken

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KDexHost.spec.auth.apiToken.maxTTL bounds every API token the host mints.
// MintStatelessKey is the one signing point all mint paths share, so it is
// where the bound holds regardless of caller. See kdex-tech/host-manager#238.

func TestMintStatelessKey_RefusesALifetimeAboveMaxTTL(t *testing.T) {
	tm := subjectlessTokenManager(t).WithMaxTTL(time.Hour)

	token, err := tm.MintStatelessKey("aud", "alice", "User", "key-1", "", time.Hour+time.Second)

	require.ErrorIs(t, err, ErrTTLExceedsMax)
	assert.Contains(t, err.Error(), "1h0m0s", "the refusal names the maximum")
	assert.Empty(t, token)
}

func TestMintStatelessKey_MintsAtExactlyMaxTTL(t *testing.T) {
	tm := subjectlessTokenManager(t).WithMaxTTL(time.Hour)

	token, err := tm.MintStatelessKey("aud", "alice", "User", "key-1", "", time.Hour)

	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestMintStatelessKey_UnsetMaxTTLIsUnbounded(t *testing.T) {
	tm := subjectlessTokenManager(t)

	token, err := tm.MintStatelessKey("aud", "alice", "User", "key-1", "", 100*365*24*time.Hour)

	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Zero(t, tm.MaxTTL())
}

func TestCapTTL(t *testing.T) {
	assert.Equal(t, 24*time.Hour, subjectlessTokenManager(t).CapTTL(24*time.Hour), "no maximum leaves the lifetime alone")

	tm := subjectlessTokenManager(t).WithMaxTTL(time.Hour)
	assert.Equal(t, time.Hour, tm.CapTTL(24*time.Hour))
	assert.Equal(t, time.Minute, tm.CapTTL(time.Minute))
	assert.Equal(t, time.Hour, tm.MaxTTL())
}

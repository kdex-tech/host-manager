/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSubjectClaimsTTL_OutlivesRefreshedSession pins kdex-tech/host-manager#137:
// the subject-claims cache is written once at login but a session (and the
// PAT/OAuth tokens derived from it) can be refreshed up to maxSessionAge without
// re-running LoginLocal — and a token minted just before that boundary stays
// valid for its own TTL BEYOND it. So the cache must outlive
// maxSessionAge + refreshTokenTTL, never just maxSessionAge, or vs_entitlements
// vanish mid-session on the refresh path.
func TestSubjectClaimsTTL_OutlivesRefreshedSession(t *testing.T) {
	// Configured durations: TTL must cover the full session plus the refresh
	// window, so it strictly exceeds the maxSessionAge retry boundary.
	got := subjectClaimsTTL(24*time.Hour, 12*time.Hour)
	assert.Equal(t, 36*time.Hour, got)
	assert.Greater(t, got, 24*time.Hour, "TTL must exceed the maxSessionAge retry boundary")

	// Unset durations fall back to the documented defaults (24h / 12h).
	assert.Equal(t, 36*time.Hour, subjectClaimsTTL(0, 0))

	// Even with refreshTokenTTL unset, the TTL must stay above maxSessionAge.
	assert.Greater(t, subjectClaimsTTL(48*time.Hour, 0), 48*time.Hour,
		"TTL must always exceed maxSessionAge, even when refreshTokenTTL is unset")
}

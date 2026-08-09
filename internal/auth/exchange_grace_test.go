/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

// replayFromGrace returns (TokenSet, bool, error) rather than the (TokenSet,
// bool) of the original #169 design sketch: a genuine grace-cache read/parse
// failure is deliberately classified as ErrServerError instead of being
// folded into the same "not found" result a legitimate absence produces, so
// RedeemRefreshToken's caller-facing classification stays accurate (see the
// classification comments on replayFromGrace and RedeemRefreshToken's
// not-found branch in exchange.go). The tests below thread that third value
// through.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefreshGrace_ExpiresAfterWindow confirms the grace window is a
// WINDOW: once it lapses, a re-presented token is rejected exactly as it is
// today, so rotation's replay protection still holds outside it.
func TestRefreshGrace_ExpiresAfterWindow(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ex.refreshGraceWindow = 50 * time.Millisecond
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	first, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err)

	// Inside the window: replayed.
	replayed, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err, "a re-presentation inside the grace window must be replayed (#169)")
	assert.Equal(t, first.RefreshToken, replayed.RefreshToken)

	// Outside it: rejected.
	time.Sleep(150 * time.Millisecond)
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	assert.Error(t, err,
		"once the grace window lapses, a consumed token must be rejected again")
}

// TestRefreshGrace_RejectedWinnerPublishesNothing pins the accepted
// asymmetry from the design: when the winner's redemption FAILS validation,
// the token is consumed but no grace entry is written, so a concurrent
// loser falls through to not-found rather than replaying a failure. Caching
// a rejection would mean serving a failure from a cache.
func TestRefreshGrace_RejectedWinnerPublishesNothing(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// Wrong client_id: the winner consumes the token and is rejected.
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "some-other-client")
	require.Error(t, err)

	// Nothing was published, so a follow-up sees not-found.
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	assert.Error(t, err, "a rejected redemption must publish no grace entry")
}

// TestRefreshGrace_PollSurvivesSetVisibilityGap covers the sub-race the
// design calls out: a loser can arrive after the winner's GetAndDelete but
// before its Set, an interval that is a network round trip under Valkey.
// The loser polls rather than failing immediately.
func TestRefreshGrace_PollSurvivesSetVisibilityGap(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	// Publish the grace entry only after a delay shorter than the poll
	// ceiling, simulating a winner that is still writing.
	go func() {
		time.Sleep(60 * time.Millisecond)
		ex.publishToGrace(ctx, "in-flight-token", TokenSet{
			AccessToken:  "at",
			RefreshToken: "rt",
			Subject:      "alice",
		})
	}()

	ts, ok, err := ex.replayFromGrace(ctx, "in-flight-token")
	require.NoError(t, err)
	require.True(t, ok,
		"the loser must poll past the set-visibility gap, not fail on the first miss (#169)")
	assert.Equal(t, "rt", ts.RefreshToken)
}

// TestRefreshGrace_PollGivesUp confirms the poll is bounded: a token that
// was never published must not hang the request for the full ceiling
// forever, and must return not-found.
func TestRefreshGrace_PollGivesUp(t *testing.T) {
	ex := newRotationTestExchanger(t)

	start := time.Now()
	_, ok, err := ex.replayFromGrace(context.Background(), "never-published")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, ok, "an unpublished token must not replay")
	assert.Less(t, elapsed, time.Second,
		"the poll must be bounded well under a second (10 x 20ms)")
}

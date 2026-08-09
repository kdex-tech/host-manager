/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

// This file diverges from the original #169 task-5 design sketch in three
// ways, all landed in fix round 2 after code review:
//
//  1. replayFromGrace returns (TokenSet, bool, error), not (TokenSet, bool):
//     a genuine grace-cache read/parse failure classifies ErrServerError
//     rather than folding into the same "not found" result a legitimate
//     absence produces.
//  2. replayFromGrace and publishToGrace take a clientID parameter and the
//     stored record now carries it (graceRecord), so a caller presenting a
//     different client_id than the token was issued to is rejected exactly
//     as the strict (non-grace) path rejects it -- CRITICAL finding: the
//     original design let ANY known client_id replay another client's
//     freshly rotated pair.
//  3. The poll only runs its full budget once markGraceInFlight's marker
//     confirms a rotation is actually in progress; an ordinary bogus/expired
//     token (no marker ever published) fails fast instead of paying the
//     full 10-attempt/180ms budget on every miss -- IMPORTANT cost finding.
//
// See the classification and design comments on graceRecord, publishToGrace,
// and replayFromGrace in exchange.go.

import (
	"context"
	"errors"
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
// the token is consumed but no grace RESULT is written, so a concurrent
// loser falls through to not-found rather than replaying a failure. Caching
// a rejection would mean serving a failure from a cache.
//
// It also pins the promptness half of the IMPORTANT cost finding: the
// deferred cleanup in RedeemRefreshToken clears the in-flight marker on
// rejection, so the follow-up below must fail fast, not pay the full poll
// budget.
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

	// Nothing was published, so a follow-up sees not-found -- promptly.
	start := time.Now()
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	elapsed := time.Since(start)
	assert.Error(t, err, "a rejected redemption must publish no grace entry")
	assert.Less(t, elapsed, 100*time.Millisecond,
		"the cleared in-flight marker must let a follow-up fail fast, not pay the full poll budget")
}

// TestRefreshGrace_ReplayRejectsWrongClientAfterRotation pins the CRITICAL
// review finding on kdex-tech/host-manager#169: replayFromGrace must
// enforce the SAME client_id binding the strict (non-grace) path enforces
// via `claims.ClientID != clientID`. Without it, ANY caller presenting a
// known client_id together with the just-consumed token id would receive
// another client's minted access token, ID token, and live rotating
// refresh token -- a bypass of the exact binding strict rotation enforces.
func TestRefreshGrace_ReplayRejectsWrongClientAfterRotation(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// "app" wins the rotation; its result is now published to grace.
	winner, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err)
	require.NotEmpty(t, winner.RefreshToken)

	// A DIFFERENT client_id presenting the same (now-consumed) token id
	// within the window must be rejected, not handed "app"'s tokens.
	_, err = ex.RedeemRefreshToken(ctx, tokenID, "evil")
	require.Error(t, err, "a different client_id replaying the consumed token id must be rejected")
	assert.True(t, errors.Is(err, ErrGrantFailure),
		"the rejection must classify as a grant failure, matching the strict path's client_id mismatch")

	// And "app" itself still holds the one live rotated token.
	replayed, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.NoError(t, err, "the legitimate client must still be able to replay its own result")
	assert.Equal(t, winner.RefreshToken, replayed.RefreshToken)
}

// TestRefreshGrace_CookieSessionClientIDEmptyStillReplays confirms the
// client_id binding introduced by the CRITICAL fix does not break cookie
// sessions. A cookie-bound refresh token is minted with ClientID "" (see
// internal/host/login.go's LoginLocal call) and internal/auth/middleware.go
// always calls RedeemRefreshToken with clientID="" for it -- an empty
// presented client_id must still match an empty recorded one and replay.
func TestRefreshGrace_CookieSessionClientIDEmptyStillReplays(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "", // cookie session: no OAuth client scoping.
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	first, err := ex.RedeemRefreshToken(ctx, tokenID, "")
	require.NoError(t, err)

	replayed, err := ex.RedeemRefreshToken(ctx, tokenID, "")
	require.NoError(t, err, "a cookie session's re-presentation inside the grace window must still replay")
	assert.Equal(t, first.RefreshToken, replayed.RefreshToken)
}

// TestRefreshGrace_PollSurvivesSetVisibilityGap covers the sub-race the
// design calls out: a loser can arrive after the winner's GetAndDelete but
// before its final Set, an interval that is a network round trip under
// Valkey. The in-flight marker is written first (as RedeemRefreshToken does
// at consume time), confirming to the loser's poll that it should commit to
// the full budget rather than failing on the first miss.
func TestRefreshGrace_PollSurvivesSetVisibilityGap(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	ex.markGraceInFlight(ctx, "in-flight-token", "app")

	// Publish the final result only after a delay shorter than the poll
	// ceiling, simulating a winner that is still minting.
	go func() {
		time.Sleep(60 * time.Millisecond)
		ex.publishToGrace(ctx, "in-flight-token", "app", TokenSet{
			AccessToken:  "at",
			RefreshToken: "rt",
			Subject:      "alice",
		})
	}()

	ts, ok, err := ex.replayFromGrace(ctx, "in-flight-token", "app")
	require.NoError(t, err)
	require.True(t, ok,
		"the loser must poll past the set-visibility gap, not fail on the first miss (#169)")
	assert.Equal(t, "rt", ts.RefreshToken)
}

// TestRefreshGrace_NeverPublishedFailsFast pins the IMPORTANT cost finding:
// an ordinary bogus or already-expired token, for which no winner ever
// published so much as the in-flight marker, must fail fast rather than
// paying the full 10-attempt/~180ms poll budget on every miss -- the common
// case, reachable by anyone holding a known client_id.
func TestRefreshGrace_NeverPublishedFailsFast(t *testing.T) {
	ex := newRotationTestExchanger(t)

	start := time.Now()
	_, ok, err := ex.replayFromGrace(context.Background(), "never-published", "app")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, ok, "an unpublished token must not replay")
	assert.Less(t, elapsed, 60*time.Millisecond,
		"nothing was ever published -- not even the in-flight marker -- so the poll must bail out well short of the full ~180ms budget")
}

// TestRefreshGrace_StuckInFlightMarkerGivesUpBounded confirms the poll
// remains bounded even once a rotation is confirmed in progress: if the
// in-flight marker is published but no final result ever follows (e.g. the
// process crashed after marking in-flight and before finishing), the loser
// must not hang forever and must return not-found once the full budget is
// spent.
func TestRefreshGrace_StuckInFlightMarkerGivesUpBounded(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	ex.markGraceInFlight(ctx, "stuck-token", "app")

	start := time.Now()
	_, ok, err := ex.replayFromGrace(ctx, "stuck-token", "app")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, ok, "a marker with no eventual result must not replay")
	assert.Less(t, elapsed, time.Second,
		"the poll must be bounded well under a second (10 x 20ms) even once a rotation is confirmed in progress")
}

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
// Fix round 3 added TestRefreshGrace_PublishSurvivesCanceledRequestContext
// and TestRefreshGrace_PollCancellationIsServerError, the coverage for the
// context.WithoutCancel / ctx.Done() classification half of finding 2, which
// round 2 had landed uncovered.
//
// See the classification and design comments on graceRecord, publishToGrace,
// and replayFromGrace in exchange.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ctxRespectingCache wraps a real cache.Cache and, unlike the in-memory
// backend newRotationTestExchanger otherwise uses (which ignores ctx
// entirely -- see InMemoryCache.Set), fails a Set whose context is already
// canceled, the way a real network round trip to Valkey would
// (client.Do(ctx, cmd) surfaces ctx.Err()). It exists so tests can
// discriminate whether a write path detaches from the caller's context
// (context.WithoutCancel) or not; the in-memory backend alone cannot tell
// the difference.
type ctxRespectingCache struct {
	cache.Cache
}

func (c ctxRespectingCache) Set(ctx context.Context, key string, value string, opts ...cache.SetOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Cache.Set(ctx, key, value, opts...)
}

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
// case, reachable by anyone holding a known client_id. Expected actual is
// ~2 sleeps of graceReplayInterval (~40ms, graceFastBailoutAttempts=3); the
// bound below leaves headroom over that while staying well short of the
// ~180ms full budget a regression back to the old unconditional poll would
// produce.
func TestRefreshGrace_NeverPublishedFailsFast(t *testing.T) {
	ex := newRotationTestExchanger(t)

	start := time.Now()
	_, ok, err := ex.replayFromGrace(context.Background(), "never-published", "app")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, ok, "an unpublished token must not replay")
	assert.Less(t, elapsed, 100*time.Millisecond,
		"nothing was ever published -- not even the in-flight marker -- so the poll must bail out well short of the full ~180ms budget")
}

// TestRefreshGrace_StuckInFlightMarkerGivesUpBounded confirms the poll
// remains bounded even once a rotation is confirmed in progress: if the
// in-flight marker is published but no final result ever follows (e.g. the
// process crashed after marking in-flight and before finishing), the loser
// must not hang forever and must return not-found once the full budget is
// spent. Expected actual is 9 sleeps of graceReplayInterval (~180ms); the
// bound below sits between that and what a doubled poll budget (~360ms)
// would produce, so a regression that widens the budget is caught instead
// of hiding behind a loose 1s ceiling.
func TestRefreshGrace_StuckInFlightMarkerGivesUpBounded(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	ex.markGraceInFlight(ctx, "stuck-token", "app")

	start := time.Now()
	_, ok, err := ex.replayFromGrace(ctx, "stuck-token", "app")
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.False(t, ok, "a marker with no eventual result must not replay")
	assert.Less(t, elapsed, 300*time.Millisecond,
		"the poll must be bounded near the full ~180ms budget (10 x 20ms), not silently doubled or worse")
}

// TestRefreshGrace_PublishSurvivesCanceledRequestContext pins the first
// half of the IMPORTANT finding-2 gap: graceCacheSet must write through
// context.WithoutCancel, so a winner whose OWN request context is canceled
// (client disconnect, deadline) between mint and publish still leaves the
// grace entry behind for concurrent losers -- exactly the #169 scenario a
// request that times out and triggers a retry burst is the canonical
// trigger for.
//
// The in-memory cache InMemoryCache.Set ignores ctx entirely, so it cannot
// tell context.WithoutCancel(ctx) apart from a plain ctx; refreshGraceCache
// is swapped for ctxRespectingCache, which actually fails a Set against an
// already-canceled context the way a real Valkey round trip would. Against
// the pre-fix code (graceCacheSet using the caller's ctx directly instead
// of a detached one), the winner's own canceled context would make every
// grace write -- including markGraceInFlight -- silently fail, so the
// second RedeemRefreshToken call below would find nothing published and
// return an error instead of replaying: this test fails on that code.
func TestRefreshGrace_PublishSurvivesCanceledRequestContext(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ex.refreshGraceCache = ctxRespectingCache{Cache: ex.refreshGraceCache}

	tokenID, err := ex.createRefreshToken(context.Background(), RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// The winner's own request context is canceled up front, standing in
	// for a client that disconnects or hits its deadline somewhere between
	// mint and publish -- by the time markGraceInFlight/publishToGrace run,
	// ctx.Err() is already non-nil either way. The primary refresh-token
	// cache ignores ctx too (same InMemoryCache), so the redemption itself
	// still succeeds; only the grace writes are at risk.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	winner, err := ex.RedeemRefreshToken(canceledCtx, tokenID, "app")
	require.NoError(t, err, "the winner's own redemption must still succeed even though its context is canceled")
	require.NotEmpty(t, winner.RefreshToken)

	// A concurrent loser, on its OWN live context, presents the same
	// (now-consumed) token id. It must still replay the winner's result --
	// proving the publish survived the winner's canceled context.
	replayed, err := ex.RedeemRefreshToken(context.Background(), tokenID, "app")
	require.NoError(t, err,
		"a concurrent loser must still replay the winner's result even though the winner's own request context was canceled (#169 fix round 2)")
	assert.Equal(t, winner.RefreshToken, replayed.RefreshToken)
}

// TestRefreshGrace_PollCancellationIsServerError pins the second half of
// the IMPORTANT finding-2 gap: if a loser's OWN poll is canceled mid-wait
// (its request's context expires while replayFromGrace is sleeping between
// attempts), that is OUR deadline firing, not a fact about the presented
// token, and must classify ErrServerError (500) -- not silently look like
// "not found" and fall through to the client-facing
// "refresh token not found or expired" grant failure, which would tell a
// caller to discard a token that might still be good. Against the pre-fix
// `case <-ctx.Done(): return TokenSet{}, false, nil`, err here is nil and
// this test fails on require.Error.
func TestRefreshGrace_PollCancellationIsServerError(t *testing.T) {
	ex := newRotationTestExchanger(t)

	// Shorter than graceReplayInterval (20ms) so the FIRST poll sleep's
	// select resolves via ctx.Done(), not the timer -- deterministic
	// regardless of graceFastBailoutAttempts, since bailout only fires at
	// attempt index graceFastBailoutAttempts-1 (>= 1), after at least one
	// select has already happened.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, ok, err := ex.replayFromGrace(ctx, "never-published", "app")

	require.Error(t, err, "a poll whose own context is canceled mid-wait must return an error, not silently report not-found")
	assert.False(t, ok)
	assert.True(t, errors.Is(err, ErrServerError),
		"our own deadline firing mid-poll is OUR infrastructure, not a fact about the presented token")
	assert.False(t, errors.Is(err, ErrGrantFailure),
		"must not classify as a grant failure -- that would tell the caller its token is dead when it might still be good")
}

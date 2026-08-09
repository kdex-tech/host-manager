package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

// Refresh-rotation grace window (kdex-tech/host-manager#169).
//
// Rotation is strictly single-use: RedeemRefreshToken consumes the presented
// token with an atomic GetAndDelete, so of N concurrent redemptions of the same
// token exactly one wins. Real clients issue those bursts routinely (4-5 within
// 250-600ms), and pre-#169 every loser failed.
//
// The winner publishes its minted pair here, keyed by the CONSUMED token id, and
// a loser presenting that same id within the window replays it. Exactly one
// rotation and one session lineage still occur, so #71's theft-detection
// guarantee is untouched -- the window makes losers replay a result, it does not
// let them rotate.
//
// Split out of exchange.go (#174): self-contained, with its own cache class and
// its own invariants.

// graceReplayAttempts and graceReplayInterval bound the poll a losing caller
// does while the winner is still publishing its result. A loser can arrive
// after the winner's GetAndDelete but before its Set, an interval that is
// sub-millisecond in memory but a network round trip under Valkey. Bounded at
// 180ms -- 9 sleeps of graceReplayInterval, not 10, because the loop breaks
// before the trailing sleep on its final attempt; the winner either publishes
// within it or has failed, in which case not-found is the correct answer.
//
// graceFastBailoutAttempts bounds a SHORTER leading sub-window used to
// decide whether to poll at all. markGraceInFlight writes a lightweight
// pending marker as a single fast cache op immediately after GetAndDelete
// succeeds -- well before the (comparatively slow) validation/minting work
// -- so if nothing at all (not even that marker) is visible within this
// short sub-window, no winner exists for this token: it is bogus, expired,
// or outside the window, and continuing to poll would only pay Valkey round
// trips and pin a goroutine for a redemption that is never coming. This is
// what makes an ordinary invalid refresh (the common case) cheap again: one
// cache miss plus up to two retries, not the full 10-attempt/180ms budget.
//
// Set to 3 (~40ms: two sleeps of graceReplayInterval), not 2 (~20ms): the
// failure mode of too-tight a bailout IS #169 itself -- a legitimate
// concurrent refresh fast-bailing because the in-flight marker hasn't
// propagated under a loaded Valkey degrades straight back into the
// single-winner-fails-the-rest bug this task exists to fix. It fails
// closed (never a wrong result, only a missed replay), but regressing into
// the original availability bug under exactly the load #169 targets is a
// bad trade for 20ms. Three attempts still gives roughly a 4x reduction
// against the old ~180ms-for-every-miss cost while leaving real headroom
// over Valkey p99 write-visibility latency. See
// kdex-tech/host-manager#169 fix round 2 (cost finding) and round 3
// (bailout-window review).
const (
	graceReplayAttempts      = 10
	graceReplayInterval      = 20 * time.Millisecond
	graceFastBailoutAttempts = 3
)

// graceRecord is what the grace cache actually stores, keyed by the
// CONSUMED token id. ClientID is the client the token was ORIGINALLY issued
// to (claims.ClientID from the record RedeemRefreshToken just consumed),
// carried so replayFromGrace can reject a caller presenting a different
// client_id exactly as the strict `claims.ClientID != clientID` check does
// on the non-grace path -- without it, the grace window would hand a live
// rotating credential to any caller that merely knew the consumed token id.
// See kdex-tech/host-manager#169 (CRITICAL review finding).
//
// Pending marks an in-flight marker written by markGraceInFlight before the
// winner has minted anything: TokenSet is the zero value until
// publishToGrace overwrites the same key with the real result. See
// markGraceInFlight / clearGraceInFlight.
type graceRecord struct {
	ClientID string   `json:"cid"`
	Pending  bool     `json:"pending,omitempty"`
	TokenSet TokenSet `json:"ts"`
}

// graceCacheSet is the shared write path for both the in-flight marker and
// the final result: it always uses a context detached from the caller's own
// (context.WithoutCancel), because both writes matter to OTHER concurrent
// callers, not to whether THIS caller's own request is still live. Without
// this, a winner whose client disconnects or whose deadline fires between
// mint and publish would cancel `ctx`, the Set would fail, nothing would be
// published, and every loser would fall through to not-found -- precisely
// the #169 scenario a request that times out and triggers a retry burst is
// the canonical trigger for. See kdex-tech/host-manager#169 fix round 2
// (IMPORTANT finding).
//
// It RETURNS the write's error rather than swallowing it. The caller that
// publishes the winner's result gates its `published` flag on this, so a
// dropped publish still runs the deferred clearGraceInFlight: an earlier
// revision set `published = true` unconditionally, which meant a single
// failed Set (Valkey blip, OOM, rejected PX) stranded the Pending marker
// with no result behind it for the whole window -- every concurrent loser
// then committed to the full poll budget and returned not-found, and the
// cleanup written for exactly that case was switched off by it. Returning
// nil when no grace cache is configured is correct: nothing to publish is
// not a failure to publish.
func (e *Exchanger) graceCacheSet(ctx context.Context, tokenID string, rec graceRecord) error {
	if e.refreshGraceCache == nil {
		return nil
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return e.refreshGraceCache.Set(context.WithoutCancel(ctx), tokenID, string(payload), cache.WithTTL(e.refreshGraceWindow))
}

// markGraceInFlight publishes the lightweight in-flight marker described on
// graceRecord. Called immediately after the token is consumed and its
// record parses cleanly -- before the validation checks and minting in
// RedeemRefreshToken -- so a concurrent loser's poll can distinguish "a
// rotation for this token is happening right now" from "nothing is
// happening" almost as fast as the winner's own GetAndDelete completed.
//
// Its error is returned for observability only; the marker is a pure
// optimization for concurrent losers (a lost marker costs them a fast
// bailout, never a wrong answer), so no caller gates behavior on it.
func (e *Exchanger) markGraceInFlight(ctx context.Context, tokenID, clientID string) error {
	return e.graceCacheSet(ctx, tokenID, graceRecord{ClientID: clientID, Pending: true})
}

// clearGraceInFlight removes the in-flight marker after a redemption that
// consumed the token but was then rejected (expired, session cap, client_id
// mismatch, or a minting/rotation failure), so a concurrent loser's poll
// sees the marker vanish and stops immediately instead of waiting out the
// full budget for a result that is never coming. It does NOT weaken "a
// rejected redemption publishes nothing": the marker it removes never
// carried a result, only the fact that a (now-rejected) redemption was
// attempted.
func (e *Exchanger) clearGraceInFlight(ctx context.Context, tokenID string) {
	if e.refreshGraceCache == nil {
		return
	}
	_ = e.refreshGraceCache.Delete(context.WithoutCancel(ctx), tokenID)
}

// publishToGrace makes the winner's result replayable for the window,
// overwriting whatever in-flight marker markGraceInFlight left. Called only
// on a SUCCESSFUL rotation: a rejected redemption never reaches this call
// (its deferred cleanup in RedeemRefreshToken clears the marker instead), so
// its concurrent losers fall through to not-found rather than replaying a
// failure. See kdex-tech/host-manager#169.
//
// The error MUST be checked by the caller: a publish that did not land is
// indistinguishable from a rejection as far as losers are concerned, so the
// in-flight marker has to be cleared rather than left stranded.
func (e *Exchanger) publishToGrace(ctx context.Context, tokenID, clientID string, ts TokenSet) error {
	return e.graceCacheSet(ctx, tokenID, graceRecord{ClientID: clientID, TokenSet: ts})
}

// replayFromGrace returns the winner's result for a token that was already
// rotated inside the grace window, for a caller presenting the SAME
// client_id the token was originally issued to. Exactly one rotation still
// occurred, so #71's single-lineage theft-detection guarantee is preserved:
// losers mint nothing, they receive a copy.
//
// A non-nil error is already fully classified:
//   - a client_id mismatch on a live grace record is a grantFailuref, the
//     exact rejection and message the strict (non-grace) path uses for the
//     same case, so a caller cannot use the grace window to bypass client
//     binding (kdex-tech/host-manager#169 CRITICAL review finding).
//   - an unreadable/corrupt grace cache entry, or this poll's own context
//     being canceled (OUR deadline, not a fact about the presented token),
//     is ErrServerError so the token endpoint maps it to 500 server_error
//     rather than telling a caller its refresh token doesn't exist. See
//     kdex-tech/host-manager#168 and #169 fix round 2.
//
// A clean "nothing published" (or "published and rejected", once the
// in-flight marker has been cleared) result is NOT an error:
// (TokenSet{}, false, nil).
func (e *Exchanger) replayFromGrace(ctx context.Context, tokenID, clientID string) (TokenSet, bool, error) {
	if e.refreshGraceCache == nil {
		return TokenSet{}, false, nil
	}
	sawInFlight := false
	for attempt := range graceReplayAttempts {
		raw, found, _, err := e.refreshGraceCache.Get(ctx, tokenID)
		if err != nil {
			return TokenSet{}, false, fmt.Errorf("%w: failed to read refresh-grace entry: %v", ErrServerError, err)
		}
		if found {
			var rec graceRecord
			if json.Unmarshal([]byte(raw), &rec) != nil {
				return TokenSet{}, false, fmt.Errorf("%w: failed to parse refresh-grace entry", ErrServerError)
			}
			if rec.Pending {
				// A rotation is confirmed in progress; keep polling below
				// for the real result within the full budget.
				sawInFlight = true
			} else {
				if rec.ClientID != clientID {
					// Subject attribution, consistent with the identical
					// strict-path rejection (`grantFailed` above, #158):
					// an operator investigating a rejected redemption
					// needs to see WHOSE session it belongs to. The
					// record already carries it on the minted result.
					return TokenSet{Subject: rec.TokenSet.Subject}, false, grantFailuref("refresh token was not issued to this client")
				}
				return rec.TokenSet, true, nil
			}
		} else if sawInFlight {
			// The in-flight marker we previously observed is gone: the
			// winner consumed the token, marked it in-flight, then
			// rejected the redemption and cleared the marker. Stop now
			// rather than burning the remaining poll budget on a result
			// that will never arrive.
			return TokenSet{}, false, nil
		} else if attempt == graceFastBailoutAttempts-1 {
			// Nothing published at all within the fast-bailout window --
			// not even the in-flight marker, which a winner writes
			// immediately. No rotation is happening for this token.
			return TokenSet{}, false, nil
		}
		if attempt == graceReplayAttempts-1 {
			// Skip the trailing sleep: there is no further attempt to wait
			// for. This is what makes the real bound 9 intervals (180ms)
			// rather than 10 (200ms) -- see graceReplayAttempts above.
			break
		}
		select {
		case <-ctx.Done():
			return TokenSet{}, false, fmt.Errorf("%w: refresh-grace replay canceled: %v", ErrServerError, ctx.Err())
		case <-time.After(graceReplayInterval):
		}
	}
	return TokenSet{}, false, nil
}

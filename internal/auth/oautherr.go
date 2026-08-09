package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// The sentinels below moved here from exchange.go (#174). Their only consumers
// are the classifier and writer in this file, which previously cross-referenced
// them in prose across two files. This is a relocation, not a redesign: the
// typed Is hook and the default-closed branch were both reviewed and explicitly
// recommended AGAINST simplifying.

// ErrServerError marks a failure of OUR infrastructure — a cache read, a
// signing operation, a stored-record unmarshal — as distinct from a failure
// of the client's grant. The token endpoint maps it to RFC 6749 5.2's
// server_error (500) rather than invalid_grant (400), because telling a
// client its credential is dead during a transient outage makes it discard
// a working refresh token and re-authorize for no reason. See
// kdex-tech/host-manager#168.
var ErrServerError = errors.New("server error")

// ErrGrantFailure marks a rejection that is genuinely ABOUT the grant the
// caller presented — not found, expired, mismatched, already consumed — and
// is therefore safe to describe back to an unauthenticated caller. Marking is
// an opt-in allowlist: an unmarked error is still treated as a grant failure
// but gets a fixed generic description instead of its own message. Why that
// default points the way it does is documented once, on
// oauthErrorForRedemption.
//
// Errors are classified against this sentinel via errors.Is, but are never
// built by wrapping it with fmt.Errorf("%w: ...", ErrGrantFailure) — doing
// so would put ErrGrantFailure's own "grant failure" text on the wire ahead
// of the actual message (e.g. "grant failure: refresh token not found or
// expired" instead of the exact string #168's reporter is matching on).
// Build grant-failure errors with grantFailuref instead: it classifies
// against this sentinel via the errors.Is opt-in Is(error) bool hook, with
// the message left untouched.
var ErrGrantFailure = errors.New("grant failure")

// grantFailureError carries a client-facing rejection message and classifies
// as ErrGrantFailure without that sentinel's own text ever appearing in
// Error(). See grantFailuref and the ErrGrantFailure doc comment above.
type grantFailureError string

func (e grantFailureError) Error() string { return string(e) }

// Is implements the errors.Is opt-in hook documented on the errors package:
// errors.Is(err, ErrGrantFailure) calls this method with target set to
// ErrGrantFailure, letting a plain string-backed error type classify as the
// sentinel without embedding the sentinel's text.
func (e grantFailureError) Is(target error) bool { return target == ErrGrantFailure }

// grantFailuref builds a grantFailureError, printf-style. Use it (directly,
// or via a function-local grantFailed closure that also attaches the known
// Subject, mirroring the existing failed closures) at rejections that are
// genuinely ABOUT the presented grant.
func grantFailuref(format string, args ...any) error {
	return grantFailureError(fmt.Sprintf(format, args...))
}

const (
	errCodeInvalidRequest       = "invalid_request"
	errCodeInvalidClient        = "invalid_client"
	errCodeInvalidGrant         = "invalid_grant"
	errCodeUnauthorizedClient   = "unauthorized_client"
	errCodeUnsupportedGrantType = "unsupported_grant_type"
	errCodeInvalidScope         = "invalid_scope"
	errCodeServerError          = "server_error"
)

// genericServerErrorDescription is what an unauthenticated caller sees when
// OUR infrastructure fails. The wrapped cause is logged, never returned:
// a signing or cache failure must not have its internals reflected back.
const genericServerErrorDescription = "the authorization server encountered an unexpected condition"

// genericGrantFailureDescription is what an unauthenticated caller sees when a
// redemption fails for a reason carrying neither ErrServerError nor
// ErrGrantFailure. It is the safe default; see oauthErrorForRedemption for why
// the default points this way.
const genericGrantFailureDescription = "the presented grant is invalid"

// writeOAuthError emits an RFC 6749 5.2 error response: a JSON body with an
// `error` code, plus the no-store caching headers 5.1 requires of the token
// endpoint. Before kdex-tech/host-manager#168 every failure here was
// text/plain, so a client could not detect invalid_grant and had no
// spec-defined way to learn it should re-authorize.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// oauthErrorForRedemption classifies an error out of a grant-redemption path
// into its 5.2 response. This is an ALLOWLIST, not a fallthrough. An earlier
// revision of this function treated "not ErrServerError" as sufficient
// license to echo err.Error() to an unauthenticated caller; RedeemRefreshToken
// and RedeemAuthorizationCode both call out to mintTokensFromCode, LoginLocal
// and LoginClient, whose own infrastructure failures were never wrapped and
// reached the caller verbatim — including, on the HTTP identity-lookup path,
// an internal service URL and pod IP. See kdex-tech/host-manager#168.
//
// Only errors explicitly marked ErrGrantFailure get their message echoed —
// those are the rejections that are genuinely ABOUT the presented grant
// (not found, expired, mismatched, already consumed) and are deliberately
// client-facing. ErrServerError still maps to 500 with a fixed description.
// Everything else — including any future error added anywhere in the call
// graph that forgets to mark itself — defaults to 400 invalid_grant with a
// fixed generic description; the real cause is available to the caller only
// via the deferred log, never in the HTTP response.
func oauthErrorForRedemption(err error) (status int, code, description string) {
	switch {
	case errors.Is(err, ErrServerError):
		return http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription
	case errors.Is(err, ErrGrantFailure):
		return http.StatusBadRequest, errCodeInvalidGrant, err.Error()
	default:
		return http.StatusBadRequest, errCodeInvalidGrant, genericGrantFailureDescription
	}
}

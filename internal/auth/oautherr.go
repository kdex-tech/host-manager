package auth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// RFC 6749 5.2 error codes.
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

// genericGrantFailureDescription is what an unauthenticated caller sees when
// a redemption fails for a reason that carries neither ErrServerError nor
// ErrGrantFailure. This is the SAFE DEFAULT that closes kdex-tech/host-
// manager#168's review finding: an earlier revision of this classifier
// treated "not ErrServerError" as license to echo err.Error(), which leaked
// an internal service URL and pod IP out of LoginLocal's HTTP identity
// lookup, and signer/resolver failures out of mintTokensFromCode, on every
// authorization_code redemption. A future error added anywhere in that call
// graph that forgets to mark itself with ErrGrantFailure now discloses
// nothing instead of whatever text it happens to carry.
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

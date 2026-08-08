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
// into its 5.2 response. Everything that is not one of OUR failures is
// invalid_grant by definition: 5.2 defines that code as covering invalid,
// expired, revoked, mismatched-client and mismatched-redirect-URI grants,
// which is exactly the remaining set.
func oauthErrorForRedemption(err error) (status int, code, description string) {
	if errors.Is(err, ErrServerError) {
		return http.StatusInternalServerError, errCodeServerError, genericServerErrorDescription
	}
	return http.StatusBadRequest, errCodeInvalidGrant, err.Error()
}

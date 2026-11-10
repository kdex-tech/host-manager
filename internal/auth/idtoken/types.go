package idtoken

import "net/http"

// HintCookieName is the name, or with a chunk suffix the prefix, of the
// cookies that carry a session's OIDC id token.
const HintCookieName = "oidc_hint"

type IDTokenStore interface {
	Set(w http.ResponseWriter, r *http.Request, rawIDToken string) error
	Get(r *http.Request) (string, error)
}

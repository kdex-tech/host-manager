package idtoken

import "net/http"

const hintName = "oidc_hint"

// HintCookieName is the name, or with a chunk suffix the prefix, of the
// cookies that carry a session's OIDC id token.
const HintCookieName = hintName

type IDTokenStore interface {
	Set(w http.ResponseWriter, r *http.Request, rawIDToken string) error
	Get(r *http.Request) (string, error)
}

package host

import (
	"net/http"
	"strings"
)

// acceptsHTML reports whether the caller can render an HTML response.
//
// It is the single test behind two decisions that must never disagree:
// which denials unwrap re-renders as the error utility page, and whether the
// page gate answers Unauthenticated with a login redirect or a 401. A caller
// that cannot render HTML must never be sent to a login form.
func acceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// Package stubs provides 501 Not Implemented HTTP handlers for routes that
// preview cannot meaningfully serve (auth, login, feedback, OpenAPI
// aggregation). They register under their normal routes so requests don't
// silently 404 — instead, the user gets a clear explanation.
package stubs

import (
	"fmt"
	"net/http"
)

// NotImplemented returns an http.Handler that responds 501 with a body naming
// the feature and pointing the user at the design spec.
func NotImplemented(feature string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, "kdex preview does not serve %s.\nThis endpoint requires a live cluster. See docs/superpowers/specs/2026-05-31-kdex-unified-cli-design.md §6.\n", feature)
	})
}

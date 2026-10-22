package host

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/klauspost/compress/gzhttp"
)

// compressibleHandler marks a mux route whose response is host-manager's own
// render: pages, utility pages (login, announcement), translation, navigation
// and the OpenAPI document. DesignMiddleware negotiates gzip/zstd for these
// routes, and for requests no route matched (the 404 error page). It never
// does so for any other route. See kdex-tech/host-manager#247.
//
// Never mark these:
//   - a function or backend proxy: host-manager does not recode someone
//     else's response;
//   - a rewrite alias (rewriteHandlerFunc): its target may be a KDexFunction
//     streaming text/event-stream, and gzhttp (v1.20.1) has no event-stream
//     exclusion, so it would buffer the stream below its minimum size;
//   - a redirect implementing internalRedirect: followInternalRedirects
//     type-asserts the handler the mux returns, and a wrapper would hide it.
type compressibleHandler struct{ http.Handler }

// compressible marks h for compression by DesignMiddleware.
func compressible(h http.Handler) http.Handler {
	return compressibleHandler{h}
}

// gzipWrap negotiates gzip or zstd from Accept-Encoding with gzhttp's default
// options: a 1024-byte minimum size and its default content-type filter. It
// adds Vary: Accept-Encoding before the wrapped handler runs.
var gzipWrap = gzhttp.GzipHandler

// compressesMatch reports whether DesignMiddleware serves a request through
// gzipWrap, given what the mux matched: a route marked compressible, or no
// route at all (pattern ""), whose response is the error page.
func compressesMatch(h http.Handler, pattern string) bool {
	_, ok := h.(compressibleHandler)
	return ok || pattern == ""
}

// varyHas reports whether the Vary header lists field (case-insensitively).
func varyHas(h http.Header, field string) bool {
	for _, v := range h.Values("Vary") {
		for f := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), field) {
				return true
			}
		}
	}
	return false
}

// acceptEncodingSeed is an ETag discriminator for the codings a request
// accepts, "" when it names none. It is derived from the request header rather
// than from gzhttp's own choice of coding, which is not exposed: two requests
// whose headers differ only cosmetically get distinct ETags, which costs a
// revalidation, never a wrong body.
func acceptEncodingSeed(r *http.Request) string {
	ae := strings.TrimSpace(r.Header.Get("Accept-Encoding"))
	if ae == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ae))
	return "ae-" + hex.EncodeToString(sum[:4])
}

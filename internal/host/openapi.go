package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

func (hh *HostHandler) OpenAPIGet(w http.ResponseWriter, r *http.Request) {
	// The ETag varies with Accept-Encoding: openapiHandler wraps this handler
	// in gzhttp, so the same URL is served in more than one coding, and each
	// coding must have its own ETag (RFC 9110 8.8.3).
	if hh.applyCachingHeadersWithSeed(w, r, nil, hh.reconcileTime, "", acceptEncodingSeed(r)) {
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	query := r.URL.Query()
	spec := hh.GetOpenAPIBuilder().BuildOpenAPI(ko.Host(r), hh.Name, hh.registeredPaths, filterFromQuery(query))

	var jsonBytes []byte
	var err error
	if _, ok := query["pretty"]; ok {
		jsonBytes, err = json.MarshalIndent(spec, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(spec)
	}
	if err != nil {
		http.Error(w, "Failed to marshal OpenAPI spec", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

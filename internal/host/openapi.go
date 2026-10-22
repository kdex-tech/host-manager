package host

import (
	"encoding/json"
	"net/http"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

func (hh *HostHandler) OpenAPIGet(w http.ResponseWriter, r *http.Request) {
	// One RLock for the whole handler, and nothing under it that takes
	// hh.mu again: Go's RWMutex forbids a recursive RLock, so a SetHost
	// writer queued between an outer and an inner RLock wedges the host (the
	// shape of #26, #51 and #82). The builder is therefore read with
	// openAPIBuilderLocked, never GetOpenAPIBuilder. The caching headers run
	// under it too: they read hh.reconcileTime and hh.authConfig, which
	// SetHost rewrites under the write lock.
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	// applyCachingHeadersWithSeed folds Accept-Encoding into the ETag itself,
	// so each coding DesignMiddleware negotiates for this route has its own.
	if hh.applyCachingHeadersWithSeed(w, r, nil, hh.reconcileTime, "", "") {
		return
	}

	query := r.URL.Query()
	spec := hh.openAPIBuilderLocked().BuildOpenAPI(ko.Host(r), hh.Name, hh.registeredPaths, filterFromQuery(query))

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

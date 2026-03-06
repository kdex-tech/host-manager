package host

import (
	"encoding/json"
	"net/http"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

func (hh *HostHandler) OpenAPIGet(w http.ResponseWriter, r *http.Request) {
	if hh.applyCachingHeaders(w, r, nil, hh.reconcileTime) {
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

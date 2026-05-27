package host

import (
	"encoding/json"
	"net/http"
	"sort"

	openapi "github.com/getkin/kin-openapi/openapi3"
)

type schemaEntry struct {
	name   string
	path   string
	schema *openapi.SchemaRef
}

func (hh *HostHandler) SchemaGet(w http.ResponseWriter, r *http.Request) {
	if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
		return
	}

	requested := r.PathValue("path")

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	orderedSchemaArray := []schemaEntry{}
	for path, info := range hh.registeredPaths {
		for name, schema := range info.API.Schemas {
			orderedSchemaArray = append(orderedSchemaArray, schemaEntry{
				name:   name,
				path:   path,
				schema: schema,
			})
		}
	}

	sort.Slice(orderedSchemaArray, func(i, j int) bool {
		if orderedSchemaArray[i].name < orderedSchemaArray[j].name {
			return true
		}
		return orderedSchemaArray[i].path < orderedSchemaArray[j].path
	})

	var foundSchema *openapi.SchemaRef

	// 1. Global lookup by schema name
	for _, schemaEntry := range orderedSchemaArray {
		if schemaEntry.name == requested {
			foundSchema = schemaEntry.schema
			break
		}
	}

	// 2. Namespaced lookup if global failed: /-/schema/{basePath}/{schemaName}
	if foundSchema == nil {
		fullPath := "/" + requested
		var bestMatchPath string
		var bestMatchSchema *openapi.SchemaRef

		for _, schemaEntry := range orderedSchemaArray {
			if fullPath == (schemaEntry.path + "/" + schemaEntry.name) {
				bestMatchPath = schemaEntry.path
				bestMatchSchema = schemaEntry.schema
			}
		}

		if bestMatchPath != "" {
			foundSchema = bestMatchSchema
		}
	}

	if foundSchema == nil {
		http.Error(w, "Schema not found", http.StatusNotFound)
		return
	}

	jsonBytes, err := json.Marshal(foundSchema)
	if err != nil {
		http.Error(w, "Failed to marshal schema", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonBytes)
	if err != nil {
		http.Error(w, "Failed to write schema response", http.StatusInternalServerError)
	}
}

func (hh *HostHandler) SchemaListGet(w http.ResponseWriter, r *http.Request) {
	if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	type schemaListItem struct {
		Name string   `json:"name"`
		URLs []string `json:"urls"`
	}

	type schemaListResponse struct {
		Items []schemaListItem `json:"items"`
	}

	orderedSchemaArray := []schemaEntry{}
	for path, info := range hh.registeredPaths {
		for name, schema := range info.API.Schemas {
			orderedSchemaArray = append(orderedSchemaArray, schemaEntry{
				name:   name,
				path:   path,
				schema: schema,
			})
		}
	}

	sort.Slice(orderedSchemaArray, func(i, j int) bool {
		if orderedSchemaArray[i].name < orderedSchemaArray[j].name {
			return true
		}
		return orderedSchemaArray[i].path < orderedSchemaArray[j].path
	})

	items := make([]schemaListItem, 0, len(orderedSchemaArray))
	globalNamesSeen := make(map[string]bool)
	for _, entry := range orderedSchemaArray {
		urls := []string{}

		// If this is the first time we see this name, it's the one the global lookup hits.
		if !globalNamesSeen[entry.name] {
			urls = append(urls, "/-/schemas/"+entry.name)
			globalNamesSeen[entry.name] = true
		}

		namespacedURL := "/-/schemas" + entry.path + "/" + entry.name
		// Only add namespaced URL if it's different from the global one we just added
		if len(urls) == 0 || namespacedURL != urls[0] {
			urls = append(urls, namespacedURL)
		}

		items = append(items, schemaListItem{
			Name: entry.name,
			URLs: urls,
		})
	}

	response := schemaListResponse{
		Items: items,
	}

	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Failed to marshal schema list", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonBytes)
	if err != nil {
		http.Error(w, "Failed to write schema list response", http.StatusInternalServerError)
	}
}

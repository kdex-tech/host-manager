/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

// ProtectedResourceMetadata is the RFC 9728 OAuth 2.0 Protected Resource
// Metadata document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

const protectedResourcePath = "/.well-known/oauth-protected-resource"

// protectedResourceHandler registers the RFC 9728 well-known endpoints on mux.
func (hh *HostHandler) protectedResourceHandler(mux *http.ServeMux, _ map[string]ko.PathInfo) {
	mux.HandleFunc("GET "+protectedResourcePath, hh.oauthProtectedResourceHandler)
	mux.HandleFunc("GET "+protectedResourcePath+"/{resourcePath...}", hh.oauthProtectedResourceHandler)
}

// oauthProtectedResourceHandler serves the RFC 9728 metadata document for a
// given resource path suffix.
func (hh *HostHandler) oauthProtectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	// PRE-EXISTING and out of scope for the denial contract: this reads
	// hh.functions through oauth2ProtectedResources without holding hh.mu,
	// which that method's doc comment now requires. Tracked separately; the
	// issuerAddress() call below is synchronised because it is the one this
	// branch's new denial paths share.
	resources := hh.oauth2ProtectedResources()
	if len(resources) == 0 {
		http.NotFound(w, r)
		return
	}

	suffix := r.PathValue("resourcePath") // "" for the root (no-suffix) form
	var match *OAuth2Resource
	if suffix == "" {
		// Root form: return the single resource if exactly one exists;
		// otherwise clients must use the path-suffixed form.
		if len(resources) == 1 {
			for _, res := range resources {
				match = &res
			}
		}
	} else {
		basePath := "/" + strings.TrimPrefix(suffix, "/")
		if res, ok := resources[basePath]; ok {
			match = &res
		}
	}
	if match == nil {
		http.NotFound(w, r)
		return
	}

	// Sort a copy of Scopes for stable output (map iteration order is
	// non-deterministic, so scopes may arrive in any order).
	scopes := make([]string, len(match.Scopes))
	copy(scopes, match.Scopes)
	sort.Strings(scopes)

	md := ProtectedResourceMetadata{
		Resource:               match.Resource,
		AuthorizationServers:   []string{hh.issuerAddress()},
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(md)
}

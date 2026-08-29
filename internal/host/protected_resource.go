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

// resourceMetadataURL builds the RFC 9728 metadata URL for a function's
// basePath: the document oauthProtectedResourceHandler serves, and the value
// a WWW-Authenticate challenge's resource_metadata= points at.
//
// One builder, because the two producers -- oauth2ResourceMetadataLocked (the
// snapshot handed to the authentication middleware) and the function proxy's
// gate -- MUST agree byte for byte. If they drifted, the 401 would advertise
// a metadata endpoint the host does not serve, which is the one failure an
// MCP client cannot recover from. This branch's own final commit had to chase
// exactly that drift in this pair.
func resourceMetadataURL(issuer, basePath string) string {
	return issuer + protectedResourcePath + basePath
}

// protectedResourceHandler registers the RFC 9728 well-known endpoints on mux.
func (hh *HostHandler) protectedResourceHandler(mux *http.ServeMux, _ map[string]ko.PathInfo) {
	mux.HandleFunc("GET "+protectedResourcePath, hh.oauthProtectedResourceHandler)
	mux.HandleFunc("GET "+protectedResourcePath+"/{resourcePath...}", hh.oauthProtectedResourceHandler)
}

// oauthProtectedResourceHandler serves the RFC 9728 metadata document for a
// given resource path suffix.
func (hh *HostHandler) oauthProtectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	// ONE snapshot, under ONE lock. Two problems came from splitting it:
	// oauth2ProtectedResources reads hh.functions' slice header against
	// SetHost's write (a genuine race, not a stale-value nit), and -- worse
	// -- `resource` came from the unlocked read while `authorization_servers`
	// came from a separately-locked issuerAddress(), so a reconcile landing
	// between the two emitted a document naming TWO DIFFERENT HOSTS. This is
	// the document every denial.Write resource_metadata= pointer sends an
	// unauthenticated MCP caller to fetch, so an inconsistent one is a
	// discovery dead end.
	//
	// oauth2ProtectedResources returns a fresh map of fresh values (Scopes
	// included), so the snapshot is safe to use after the unlock. The JSON
	// encode below deliberately runs OUTSIDE the lock: it can block on the
	// client's socket, and holding hh.mu across that would let one slow
	// reader starve every reconcile (the shape of #26, #51 and #59).
	hh.mu.RLock()
	resources := hh.oauth2ProtectedResources()
	issuer := hh.issuerAddressLocked()
	hh.mu.RUnlock()

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
		AuthorizationServers:   []string{issuer},
		ScopesSupported:        scopes,
		BearerMethodsSupported: []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(md)
}

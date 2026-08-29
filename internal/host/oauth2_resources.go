/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

// OAuth2Resource describes a KDexFunction basePath that an operation has
// opted into protecting with the built-in "oauth2" security scheme.
type OAuth2Resource struct {
	BasePath string
	Resource string
	Scopes   []string
}

// oauth2ProtectedResources returns the set of oauth2-protected resources for
// this host, keyed by basePath. A function is included when ANY operation
// declares the "oauth2" scheme; Scopes is the de-duplicated union of that
// scheme's scope lists across the function's operations.
//
// Caller must hold hh.mu: it reads hh.functions and (via
// issuerAddressLocked) hh.host and hh.scheme, all rewritten under
// hh.mu.Lock on every reconcile.
func (hh *HostHandler) oauth2ProtectedResources() map[string]OAuth2Resource {
	out := map[string]OAuth2Resource{}
	issuer := hh.issuerAddressLocked()
	if issuer == "" {
		return out
	}
	methods := []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
	for i := range hh.functions {
		fn := &hh.functions[i]
		if fn.Status.State != kdexv1alpha1.KDexFunctionStateReady || fn.Spec.Internal {
			continue
		}
		seen := map[string]bool{}
		var scopes []string
		protected := false
		for _, item := range fn.Spec.API.Paths {
			for _, m := range methods {
				op := item.GetOp(m)
				if op == nil || op.Security == nil {
					continue
				}
				for _, s := range *op.Security {
					sr := kdexv1alpha1.SecurityRequirement(s)
					if list, ok := sr["oauth2"]; ok {
						protected = true
						for _, sc := range list {
							if !seen[sc] {
								seen[sc] = true
								scopes = append(scopes, sc)
							}
						}
					}
				}
			}
		}
		if protected {
			out[fn.Spec.API.BasePath] = OAuth2Resource{
				BasePath: fn.Spec.API.BasePath,
				Resource: issuer + fn.Spec.API.BasePath,
				Scopes:   scopes,
			}
		}
	}
	return out
}

// oauth2ResourceMetadataLocked maps each oauth2-protected basePath to that
// resource's RFC 9728 metadata URL — the same document oauthProtectedResourceHandler
// serves, so the two can never describe different locations.
//
// Handed to auth.Config as a snapshot (#180). The authentication middleware
// wraps the whole mux and cannot resolve a request path to a function, so it
// needs this mapping to name the resource in the 401 challenge it returns for
// an invalid bearer. A snapshot rather than a callback because the middleware
// reads it on every rejected request and must not reach back into HostHandler
// for a lock.
//
// Caller must hold hh.mu: oauth2ProtectedResources reads hh.functions.
func (hh *HostHandler) oauth2ResourceMetadataLocked() map[string]string {
	resources := hh.oauth2ProtectedResources()
	if len(resources) == 0 {
		return nil
	}
	issuer := hh.issuerAddressLocked()
	out := make(map[string]string, len(resources))
	for basePath := range resources {
		out[basePath] = resourceMetadataURL(issuer, basePath)
	}
	return out
}

// oauth2ResourceAudiences returns the set of acceptable RFC 8707 `resource`
// values for this host's oauth2-protected resources. Both the full resource
// URI (issuer + basePath, what clients send as `resource`) and the basePath
// form are included so the token endpoint can recognize either. The OAuth2
// token handler treats a `resource` present in this set as a request to mint
// an audience-bound PASETO PAT as the access_token.
func (hh *HostHandler) oauth2ResourceAudiences() map[string]bool {
	resources := hh.oauth2ProtectedResources()
	out := make(map[string]bool, len(resources)*2)
	for _, r := range resources {
		out[r.Resource] = true
		out[r.BasePath] = true
	}
	return out
}

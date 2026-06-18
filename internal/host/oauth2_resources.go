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
func (hh *HostHandler) oauth2ProtectedResources() map[string]OAuth2Resource {
	out := map[string]OAuth2Resource{}
	issuer := hh.issuerAddress()
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

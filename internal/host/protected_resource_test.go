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
	"net/http/httptest"
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestProtectedResourceMetadataSuffixed(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "dev.knowdrive.ai")
	hh.functions = []kdexv1alpha1.KDexFunction{
		newReadyFunctionWithOAuth2(t, "/api/v1/mcp", []string{"functions:/api/v1/mcp:read"}),
	}
	mux := http.NewServeMux()
	hh.protectedResourceHandler(mux, nil)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/api/v1/mcp", nil)
	req.Host = "dev.knowdrive.ai"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var md ProtectedResourceMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &md); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if md.Resource != "https://dev.knowdrive.ai/api/v1/mcp" {
		t.Fatalf("resource = %q", md.Resource)
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://dev.knowdrive.ai" {
		t.Fatalf("authorization_servers = %v", md.AuthorizationServers)
	}
	if len(md.ScopesSupported) != 1 || md.ScopesSupported[0] != "functions:/api/v1/mcp:read" {
		t.Fatalf("scopes_supported = %v", md.ScopesSupported)
	}
}

func TestProtectedResourceMetadataUnknown404(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "dev.knowdrive.ai")
	mux := http.NewServeMux()
	hh.protectedResourceHandler(mux, nil)
	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/nope", nil)
	req.Host = "dev.knowdrive.ai"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

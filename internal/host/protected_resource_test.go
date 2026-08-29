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
	"net/url"
	"sync"
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

// The handler read hh.functions with no lock and then took hh.mu separately
// for the issuer, so a reconcile landing between the two emitted a document
// whose `resource` named one host and whose `authorization_servers` named
// another. Run under -race: the reader must both stay race-free against
// SetHost's write AND never mix two hosts into one document.
func TestProtectedResourceMetadataIsInternallyConsistentUnderReconcile(t *testing.T) {
	const (
		basePath = "/api/v1/mcp"
		domainA  = "a.example.test"
		domainB  = "b.example.test"
	)

	hh := newTestHostHandlerWithDomain(t, domainA)
	hh.functions = []kdexv1alpha1.KDexFunction{
		newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"}),
	}
	mux := http.NewServeMux()
	hh.protectedResourceHandler(mux, nil)

	// A writer with SetHost's shape: rewrite hh.host and hh.functions under
	// hh.mu.Lock, exactly the fields the handler reads.
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		domains := []string{domainA, domainB}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			hh.mu.Lock()
			hh.host = &kdexv1alpha1.KDexHostSpec{
				Routing: kdexv1alpha1.Routing{Domains: []string{domains[i%2]}},
			}
			hh.functions = []kdexv1alpha1.KDexFunction{
				newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"}),
			}
			hh.mu.Unlock()
		}
	}()

	var readers sync.WaitGroup
	for i := 0; i < 8; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 200; j++ {
				req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource"+basePath, nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				if rr.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rr.Code)
					return
				}
				var md ProtectedResourceMetadata
				if err := json.Unmarshal(rr.Body.Bytes(), &md); err != nil {
					t.Errorf("unmarshal: %v", err)
					return
				}
				if len(md.AuthorizationServers) != 1 {
					t.Errorf("authorization_servers = %v", md.AuthorizationServers)
					return
				}
				if md.Resource != md.AuthorizationServers[0]+basePath {
					t.Errorf("document names two hosts: resource=%q authorization_servers=%v",
						md.Resource, md.AuthorizationServers)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	writer.Wait()
}

// The challenge's resource_metadata= and the snapshot handed to the
// authentication middleware are built by ONE function, so they cannot drift
// apart -- and both must name the path protectedResourceHandler actually
// serves. Assert the built URL round-trips through the live handler.
func TestResourceMetadataURLMatchesTheServedDocument(t *testing.T) {
	const (
		domain   = "dev.knowdrive.ai"
		basePath = "/api/v1/mcp"
	)
	hh := newTestHostHandlerWithDomain(t, domain)
	hh.functions = []kdexv1alpha1.KDexFunction{
		newReadyFunctionWithOAuth2(t, basePath, []string{"functions:" + basePath + ":read"}),
	}

	built := resourceMetadataURL("https://"+domain, basePath)
	if want := "https://" + domain + "/.well-known/oauth-protected-resource" + basePath; built != want {
		t.Fatalf("resourceMetadataURL = %q, want %q", built, want)
	}

	// The middleware snapshot must be the same string.
	hh.mu.RLock()
	snapshot := hh.oauth2ResourceMetadataLocked()
	hh.mu.RUnlock()
	if got := snapshot[basePath]; got != built {
		t.Fatalf("oauth2ResourceMetadataLocked[%q] = %q, want %q", basePath, got, built)
	}

	// And the host must actually serve a document there.
	mux := http.NewServeMux()
	hh.protectedResourceHandler(mux, nil)
	u, err := url.Parse(built)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	req := httptest.NewRequest("GET", u.Path, nil)
	req.Host = domain
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d for %q; the challenge would advertise an endpoint the host does not serve",
			rr.Code, built)
	}
}

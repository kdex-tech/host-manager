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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// newTestHostHandlerWithDomain creates a minimal HostHandler whose issuerAddress()
// returns "https://<domain>".
func newTestHostHandlerWithDomain(_ *testing.T, domain string) *HostHandler {
	return &HostHandler{
		scheme: "https",
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{
				Domains: []string{domain},
			},
		},
	}
}

// newReadyFunctionWithOAuth2 returns a KDexFunction that is Ready and has a
// single POST operation on basePath whose Security contains {"oauth2": scopes}.
func newReadyFunctionWithOAuth2(_ *testing.T, basePath string, scopes []string) kdexv1alpha1.KDexFunction {
	scopeJSON, _ := json.Marshal(scopes)
	raw := []byte(`{"security":[{"oauth2":` + string(scopeJSON) + `}],"responses":{"200":{"description":"ok"}}}`)
	return kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-oauth2", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: basePath,
				Paths: map[string]kdexv1alpha1.PathItem{
					basePath: {Post: &runtime.RawExtension{Raw: raw}},
				},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			State: kdexv1alpha1.KDexFunctionStateReady,
		},
	}
}

// newReadyFunctionBearerOnly returns a KDexFunction that is Ready and has a
// single POST operation on basePath whose Security contains only {"bearer": []}.
func newReadyFunctionBearerOnly(_ *testing.T, basePath string) kdexv1alpha1.KDexFunction {
	raw := []byte(`{"security":[{"bearer":[]}],"responses":{"200":{"description":"ok"}}}`)
	return kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-bearer", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: basePath,
				Paths: map[string]kdexv1alpha1.PathItem{
					basePath: {Post: &runtime.RawExtension{Raw: raw}},
				},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			State: kdexv1alpha1.KDexFunctionStateReady,
		},
	}
}

func TestOAuth2ProtectedResources(t *testing.T) {
	hh := newTestHostHandlerWithDomain(t, "dev.knowdrive.ai")
	hh.functions = []kdexv1alpha1.KDexFunction{
		newReadyFunctionWithOAuth2(t, "/api/v1/mcp", []string{"functions:/api/v1/mcp:read"}),
		newReadyFunctionBearerOnly(t, "/v1/auth"),
	}
	got := hh.oauth2ProtectedResources()
	res, ok := got["/api/v1/mcp"]
	if !ok {
		t.Fatal("expected /api/v1/mcp to be oauth2-protected")
	}
	if res.Resource != "https://dev.knowdrive.ai/api/v1/mcp" {
		t.Fatalf("Resource = %q", res.Resource)
	}
	if len(res.Scopes) != 1 || res.Scopes[0] != "functions:/api/v1/mcp:read" {
		t.Fatalf("Scopes = %v", res.Scopes)
	}
	if _, ok := got["/v1/auth"]; ok {
		t.Fatal("/v1/auth must NOT be oauth2-protected (bearer only)")
	}
}

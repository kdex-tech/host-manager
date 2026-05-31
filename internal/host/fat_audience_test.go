/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// TestFATAudienceFor_KnativeBacked_PreservesFullURL pins the legacy behavior
// for Knative-deployed functions: Status.URL identifies a unique recipient
// (its own Knative Service), so the FAT audience IS Status.URL verbatim.
func TestFATAudienceFor_KnativeBacked_PreservesFullURL(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://fn-xyz.kdex-knative.svc.cluster.local",
		},
	}
	assert.Equal(t,
		"http://fn-xyz.kdex-knative.svc.cluster.local",
		fatAudienceFor(fn),
	)
}

// TestFATAudienceFor_KnativeBacked_PreservesTrailingPath covers the case
// where the Knative URL itself carries a path component (uncommon but
// possible) — still preserved verbatim because the recipient is unique.
func TestFATAudienceFor_KnativeBacked_PreservesTrailingPath(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "https://fn-xyz.kdex-knative.svc.cluster.local/sub/path",
		},
	}
	assert.Equal(t,
		"https://fn-xyz.kdex-knative.svc.cluster.local/sub/path",
		fatAudienceFor(fn),
	)
}

// TestFATAudienceFor_ServiceBacked_StripsPath is the core #98 case:
// multiple sibling KDexFunction CRs proxying to the same backend Service
// must mint FATs with the SAME audience so the backend's single-string
// validator accepts FATs from any of them. The audience is the Service
// origin (scheme + host[:port]), no path.
func TestFATAudienceFor_ServiceBacked_StripsPath(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{
				Type: kdexv1alpha1.FunctionBackendTypeService,
				Service: &kdexv1alpha1.ServiceBackend{
					Name: "knowdb",
					Port: intstr.FromInt(3000),
					Path: "/v1/vector_stores",
				},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://knowdb.dev.svc.cluster.local:3000/v1/vector_stores",
		},
	}
	assert.Equal(t,
		"http://knowdb.dev.svc.cluster.local:3000",
		fatAudienceFor(fn),
	)
}

// TestFATAudienceFor_ServiceBacked_SiblingsAgree confirms the cross-CR
// invariant that #98 cares about: two CRs pointing at the same Service
// with different basePaths/mount-paths produce identical FAT audiences.
func TestFATAudienceFor_ServiceBacked_SiblingsAgree(t *testing.T) {
	vectorStores := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{Type: kdexv1alpha1.FunctionBackendTypeService},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://knowdb.dev.svc.cluster.local:3000/v1/vector_stores",
		},
	}
	files := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{Type: kdexv1alpha1.FunctionBackendTypeService},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://knowdb.dev.svc.cluster.local:3000/v1/files",
		},
	}
	assert.Equal(t, fatAudienceFor(vectorStores), fatAudienceFor(files),
		"sibling service-backed functions must share an audience to be FAT-compatible "+
			"with the same backend audience config (kdex-tech/host-manager#98)")
}

// TestFATAudienceFor_ServiceBacked_RootPath covers the edge case where
// Service.Path is "/" (default) — Status.URL is already path-less aside
// from the lone slash; result is the origin.
func TestFATAudienceFor_ServiceBacked_RootPath(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{Type: kdexv1alpha1.FunctionBackendTypeService},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://svc.ns.svc.cluster.local:8080/",
		},
	}
	assert.Equal(t, "http://svc.ns.svc.cluster.local:8080", fatAudienceFor(fn))
}

// TestFATAudienceFor_ServiceBacked_DropsRawQuery defends against future
// callers that might pass a query string on Status.URL — query has no
// semantic place in an audience identifier, so strip it.
func TestFATAudienceFor_ServiceBacked_DropsRawQuery(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{Type: kdexv1alpha1.FunctionBackendTypeService},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://svc.ns.svc.cluster.local:8080/v1?extra=junk#frag",
		},
	}
	assert.Equal(t, "http://svc.ns.svc.cluster.local:8080", fatAudienceFor(fn))
}

// TestFATAudienceFor_MalformedURL_FallsBackToVerbatim ensures a parse
// failure doesn't crash the proxy build — the audience is whatever was
// in Status.URL, which sign.NewSigner will then reject for being invalid
// (returning a 500 to the caller). Better than panicking.
func TestFATAudienceFor_MalformedURL_FallsBackToVerbatim(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Backend: &kdexv1alpha1.FunctionBackend{Type: kdexv1alpha1.FunctionBackendTypeService},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "://not-a-url",
		},
	}
	assert.Equal(t, "://not-a-url", fatAudienceFor(fn))
}

// TestProxy_FATAudience_ServiceBacked_IsServiceOrigin_NotStatusURL is the
// end-to-end pin for kdex-tech/host-manager#98. Mirrors the test pattern
// from TestProxy_FATDoesNotLeakSensitiveHeaders: stand up a capturing
// upstream, drive an authenticated request through the proxy, decode the
// resulting FAT Authorization header, and assert the `aud` claim is the
// Service origin (NOT Status.URL with the basePath suffix).
func TestProxy_FATAudience_ServiceBacked_IsServiceOrigin_NotStatusURL(t *testing.T) {
	logf.SetLogger(logr.Discard())

	var fatHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fatHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	// Service-backed function. Status.URL points at the upstream test
	// server PLUS a basePath-style suffix — exactly the shape host-manager
	// writes for spec.backend.type=Service (origin + Service.Path).
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-aud", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/api/v1/vector_stores"},
			Backend: &kdexv1alpha1.FunctionBackend{
				Type: kdexv1alpha1.FunctionBackendTypeService,
				Service: &kdexv1alpha1.ServiceBackend{
					Name: "knowdb",
					Port: intstr.FromInt(3000),
					Path: "/v1/vector_stores",
				},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: upstream.URL + "/v1/vector_stores",
		},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv
	cacheManager, _ := cache.NewCacheManager("", "fat-aud-test", nil)
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
		},
	}

	handler := hh.reverseProxyHandler(fn, "https://test-host.example.com")

	authedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "alice",
		"entitlements": []any{"functions:/api/v1/vector_stores:read"},
	})

	req := httptest.NewRequest("GET", "/api/v1/vector_stores", nil).WithContext(authedCtx)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotEmpty(t, fatHeader, "upstream did not receive a FAT")
	require.True(t, strings.HasPrefix(fatHeader, "Bearer "),
		"FAT must arrive as Bearer; got %q", fatHeader)

	parser := jwt.NewParser()
	parsed, _, err := parser.ParseUnverified(strings.TrimPrefix(fatHeader, "Bearer "), jwt.MapClaims{})
	require.NoError(t, err)
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)

	aud := claims["aud"]
	require.NotNil(t, aud, "FAT must carry an aud claim")

	// The aud claim may serialize as either a string (single-aud) or an
	// array (multi-aud). Normalize to a slice of strings for the assertion.
	var auds []string
	switch v := aud.(type) {
	case string:
		auds = []string{v}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				auds = append(auds, s)
			}
		}
	default:
		t.Fatalf("unexpected aud claim type %T: %v", aud, aud)
	}

	// Expected: the service origin without the /v1/vector_stores suffix.
	// httptest.Server URLs are http://127.0.0.1:<port>; the suffix-stripping
	// helper should drop the path component entirely.
	require.Len(t, auds, 1, "FAT should carry exactly one audience")
	assert.Equal(t, upstream.URL, auds[0],
		"FAT audience must be the Service origin (no path), not Status.URL — kdex-tech/host-manager#98")
	assert.NotContains(t, auds[0], "/v1/vector_stores",
		"basePath/Service.Path suffix must be stripped from the FAT audience")
}

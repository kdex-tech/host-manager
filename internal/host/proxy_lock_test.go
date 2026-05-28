/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestReverseProxyHandler_DoesNotPinHostLockDuringUpstream pins the
// fix for kdex-tech/host-manager#59. Pre-fix, the per-request handler
// took hh.mu.RLock() with `defer hh.mu.RUnlock()` and held it across
// the entire upstream proxy.ServeHTTP round-trip. A single slow upstream
// blocked any controller-side SetHost / AddOrUpdate* / Remove* (writer
// acquires hh.mu.Lock), and Go's RWMutex then starved every new reader
// behind the queued writer — silent total host wedge until the slowest
// backend returned (or never).
//
// Post-fix, the handler snapshots hh.authChecker under a tight RLock,
// releases it, and then runs the auth check + proxy.ServeHTTP on the
// snapshot. While the upstream blocks, hh.mu.Lock() must still acquire.
func TestReverseProxyHandler_DoesNotPinHostLockDuringUpstream(t *testing.T) {
	// Upstream that blocks until the test closes `release` — simulates
	// a hung backend / pathological cold start / slowloris response.
	// Register `release` cleanup AFTER `upstream.Close` so LIFO drains
	// the hung handler before httptest tries to wait for it.
	release := make(chan struct{})
	upstreamEntered := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamEntered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	// Same minimum-viable HostHandler shape as the existing proxy_test.go
	// `runProxy` helper — the proxy handler nil-derefs without a key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cm, err := cache.NewCacheManager("", "proxy-lock-test", nil)
	require.NoError(t, err)
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cm,
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{
				ActiveKey: true,
				KeyId:     "test-kid",
				Private:   privateKey,
			},
		},
	}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "slow-fn", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/slow"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: upstream.URL, State: kdexv1alpha1.KDexFunctionStateReady},
	}

	handler := hh.reverseProxyHandler(fn, "https://test-host.example.com")

	// Fire the request in a goroutine — it will block inside
	// proxy.ServeHTTP waiting for the upstream to send a response.
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/slow/anything", nil))

	// Wait until the upstream has actually received the request, so we
	// know the proxy is inside ServeHTTP and (pre-fix) holding the
	// RLock.
	select {
	case <-upstreamEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received the proxied request")
	}

	// Now try to take the writer lock. Pre-fix this blocks until the
	// upstream returns (never, in this test). Post-fix it acquires
	// immediately because the handler released the RLock before
	// proxy.ServeHTTP.
	done := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hh.mu.Lock() blocked behind in-flight proxy round-trip — RLock held across upstream call (#59)")
	}
}

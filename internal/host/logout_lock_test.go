/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestLogoutPost_DoesNotHoldHostLockDuringHookBarrier pins the fix for the
// quad's PERF-1: LogoutPost must NOT hold hh.mu.RLock across the enforcing-logout
// hook barrier (an outbound HTTP call bounded only by the hook timeout). Holding
// the host-wide RWMutex across that I/O lets a slow/hung logout-hook endpoint
// stall a concurrent reconcile's hh.mu.Lock() — and, via RWMutex writer priority,
// every subsequent request that needs the read lock — for up to the hook timeout.
func TestLogoutPost_DoesNotHoldHostLockDuringHookBarrier(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	// An enforcing-logout hook endpoint that blocks until the test releases it,
	// modelling a slow/hung downstream logout hook.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	defer close(release) // ensure the blocked handler is always freed

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "logout-hook",
			Annotations: map[string]string{
				"kdex.dev/secret-type": "http-event-hook",
				"kdex.dev/active-key":  "true",
			},
		},
		Data: map[string][]byte{
			"url":           []byte(srv.URL),
			"shared-secret": []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
			"events":        []byte("logout"),
			"mode":          []byte("enforcing"),
		},
	}
	dispatcher, err := auth.NewEventDispatcherFromSecrets("logout.example", []corev1.Secret{secret}, logr.Discard())
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}

	cm, err := cache.NewCacheManager("", "logout-lock-test", nil)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	ex, err := auth.NewExchanger(context.Background(), auth.Config{}, cm, stubInternalIdentityProvider{}, dispatcher)
	if err != nil {
		t.Fatalf("exchanger: %v", err)
	}

	hh := &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		cacheManager:  cm,
		authConfig:    &auth.Config{CookieName: "auth_token"},
		authExchanger: ex,
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{"logout.example"}},
		},
	}

	// Fire the logout (no refresh cookie -> the barrier still runs with an empty
	// subject). A valid same-origin header passes the CSRF gate.
	req := httptest.NewRequest("POST", "https://logout.example/-/logout", nil)
	req.Header.Set("Origin", "https://logout.example")
	go hh.LogoutPost(httptest.NewRecorder(), req)

	// Wait until the logout is inside the (blocked) hook barrier.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("logout hook was never called")
	}

	// While the barrier is blocked, a reconcile's write lock must still acquire
	// promptly. If LogoutPost holds hh.mu.RLock across the barrier, this blocks.
	locked := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(1 * time.Second):
		t.Fatal("hh.mu.Lock() blocked while a logout hook barrier was in flight — " +
			"LogoutPost holds the host lock across hook I/O (PERF-1); a slow logout hook stalls all host request serving")
	}
}

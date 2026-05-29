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
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestServeHTTP_NoRaceOnAuthConfigDuringSetHost pins the fix for
// kdex-tech/host-manager#88. Pre-fix ServeHTTP snapshotted hh.Mux
// under RLock and released, then dereferenced hh.authConfig and
// hh.authExchanger with no lock. SetHost mutates those fields under
// Lock. Concurrent traffic + reconcile produces an unsynchronized
// read-vs-write that race detector trips on; an unlucky interleaving
// dereferences a half-written interface header and crashes the
// process via uncaught panic.
//
// Same family as #73 (background-render goroutine race) — caught at
// the per-request entry point this time.
func TestServeHTTP_NoRaceOnAuthConfigDuringSetHost(t *testing.T) {
	cm, err := cache.NewCacheManager("", "servehttp-race", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hh := NewHostHandler(nil, "servehttp-race", "default", logr.Discard(), cm)

	// Initial SetHost so hh.Mux is non-nil and ServeHTTP reaches the
	// authConfig.AddAuthentication call site (line 591).
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Concurrent writers — re-SetHost in a loop. Each call mutates
	// hh.authConfig and hh.authExchanger under Lock.
	var stop atomic.Bool
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for !stop.Load() {
			hh.SetHost(
				context.Background(),
				&kdexv1alpha1.KDexHostSpec{DefaultLang: "en"},
				nil, nil, nil, nil, "", nil, nil,
				&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
			)
		}
	}()

	// Concurrent readers — fire ServeHTTP requests against a system
	// path so we reach line 591 even with hh.GetStatus() ==
	// Initializing.
	reqDone := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func() {
			defer func() { _ = recover() }() // panics from unsync reads
			defer func() { reqDone <- struct{}{} }()
			hh.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/-/healthz", nil))
		}()
	}

	for i := 0; i < 50; i++ {
		<-reqDone
	}

	stop.Store(true)
	<-writerDone
}

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
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// blockingSniffer implements the sniffer interface but blocks Analyze
// until `release` is closed, so the test can pin the outer RLock long
// enough to queue a writer between the outer and inner RLock — the
// exact interleaving that produces the recursive-RLock deadlock.
type blockingSniffer struct {
	release chan struct{}
	entered chan struct{}
}

func (b *blockingSniffer) Analyze(*http.Request) (*sniffer.AnalysisResult, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return nil, errors.New("simulated analyze error to drive the serveError branch (#82)")
}

func (b *blockingSniffer) DocsHandler(http.ResponseWriter, *http.Request) {}

// TestDesignMiddleware_NoRecursiveRLockDeadlock pins the fix for
// kdex-tech/host-manager#82. Pre-fix DesignMiddleware took
// hh.mu.RLock() and then called hh.serveError(...) — which also
// hh.mu.RLock()s — while still holding the outer reader. When a
// writer (SetHost / AddOrUpdate*) queued between the outer and inner
// RLock, Go's write-preferring RWMutex blocked the inner RLock; the
// writer couldn't proceed (outer reader held); the request goroutine
// couldn't proceed (inner reader queued). Silent host-wide wedge,
// identical operator-facing symptoms to #26 and #51.
//
// Post-fix the handler snapshots hh.Mux and hh.sniffer under one
// tight RLock, releases it, then runs the dispatch (serveError /
// unwrap) without holding the outer lock. serveError takes its own
// RLock cleanly.
func TestDesignMiddleware_NoRecursiveRLockDeadlock(t *testing.T) {
	cm, err := cache.NewCacheManager("", "design-test", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hh := NewHostHandler(nil, "design-test", "default", logr.Discard(), cm)
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Install ErrorUtilityPage so serveError reaches renderUtilityPage
	// (without this serveError falls through to http.Error without
	// re-acquiring the RLock — and we want to exercise the recursive
	// RLock specifically).
	hh.mu.Lock()
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name:         "err",
		MainTemplate: "<html><body>{{ .ErrorMessage }}</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}
	hh.mu.Unlock()

	bs := &blockingSniffer{
		release: make(chan struct{}),
		entered: make(chan struct{}, 1),
	}
	// Wire the blocking sniffer AND clear authChecker so the sniffer
	// suppression branch at feedback.go:251 doesn't fire (an empty
	// authConfig from SetHost installs a real AuthorizationChecker;
	// without auth context the canGenerateSniffer check fails and
	// invokeSniffer = false, bypassing the Analyze call we need to pin
	// the outer RLock).
	hh.sniffer = bs
	hh.authChecker = nil

	handler := hh.DesignMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Fire the request — DesignMiddleware takes the outer RLock and
	// calls bs.Analyze, which blocks until we release.
	reqDone := make(chan struct{})
	var reqPanic any
	go func() {
		defer func() {
			reqPanic = recover()
			close(reqDone)
		}()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/something/unrouted", nil))
	}()

	// Wait until Analyze has been entered — at this point the
	// goroutine holds hh.mu.RLock().
	select {
	case <-bs.entered:
	case <-time.After(2 * time.Second):
		select {
		case <-reqDone:
			t.Fatalf("request returned before Analyze; reqPanic=%v", reqPanic)
		default:
			t.Fatal("blockingSniffer.Analyze never entered (request goroutine still running)")
		}
	}

	// Queue a writer between the outer RLock (held by the request
	// goroutine) and the inner RLock that serveError will try to take
	// once we release Analyze. Pre-fix this is the trigger interleaving
	// for the deadlock; post-fix the request goroutine has already
	// released its outer RLock before reaching serveError, so the
	// writer acquires cleanly.
	writerAcquired := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(writerAcquired)
	}()

	// Give the writer a moment to actually queue behind the reader.
	time.Sleep(50 * time.Millisecond)

	// Now release Analyze. The handler will hit the error branch and
	// call serveError, which itself takes hh.mu.RLock(). Pre-fix:
	// recursive RLock blocks because the writer is queued. Post-fix:
	// the outer RLock has already been released.
	close(bs.release)

	select {
	case <-writerAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("hh.mu.Lock() blocked because DesignMiddleware held outer RLock across serveError (#82)")
	}

	// Drain the request goroutine so the test exits cleanly.
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("request goroutine never completed")
	}
}

// blockingHeaderWriter blocks its first Header() call until release is
// closed, pinning whatever lock the handler holds at that moment.
type blockingHeaderWriter struct {
	*httptest.ResponseRecorder
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *blockingHeaderWriter) Header() http.Header {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.ResponseRecorder.Header()
}

// TestOpenAPIGet_NoRecursiveRLockDeadlock pins the /-/openapi handler to a
// single RLock. It used to take hh.mu.RLock and then call GetOpenAPIBuilder,
// which takes it again: a writer queued between the two wedged the host (the
// #26/#51/#82 shape). The handler's first Header() call (the caching headers)
// is now under its RLock, so the test pins the lock there, queues a writer,
// and releases: the handler must finish, and the writer must then acquire,
// with no further RLock in between.
func TestOpenAPIGet_NoRecursiveRLockDeadlock(t *testing.T) {
	cm, err := cache.NewCacheManager("", "openapi-lock-test", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hh := NewHostHandler(nil, "openapi-lock-test", "default", logr.Discard(), cm)
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	bw := &blockingHeaderWriter{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		hh.OpenAPIGet(bw, httptest.NewRequest(http.MethodGet, "/-/openapi", nil))
	}()

	select {
	case <-bw.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("OpenAPIGet never reached its first Header() call")
	}

	writerAcquired := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(writerAcquired)
	}()
	// Give the writer a moment to queue behind the handler's RLock.
	time.Sleep(50 * time.Millisecond)
	close(bw.release)

	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("OpenAPIGet blocked on a second hh.mu.RLock behind the queued writer")
	}
	select {
	case <-writerAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("the writer never acquired hh.mu after OpenAPIGet returned")
	}
	if bw.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", bw.Code)
	}
}

// openAPIBuilderLocked is for a caller already holding hh.mu, so it must
// never take the lock: under the write lock, a lock attempt would block.
func TestOpenAPIBuilderLocked_TakesNoLock(t *testing.T) {
	cm, err := cache.NewCacheManager("", "openapi-locked-test", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hh := NewHostHandler(nil, "openapi-locked-test", "default", logr.Discard(), cm)

	done := make(chan struct{})
	go func() {
		defer close(done)
		hh.mu.Lock()
		defer hh.mu.Unlock()
		if hh.openAPIBuilderLocked() != &hh.openapiBuilder {
			t.Error("openAPIBuilderLocked must return the host's builder")
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("openAPIBuilderLocked took hh.mu")
	}
}

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestBackgroundRender_NoRaceWithSetHost pins the fix for
// kdex-tech/host-manager#73. Pre-fix, the "stale cache hit → background
// migration" goroutines in renderUtilityPage / pageHandlerFunc /
// navigationGet outlived the parent request and accessed mutating
// hh.* state (hh.host, hh.themeAssets, hh.scripts, hh.packageReferences,
// hh.importmap, hh.reconcileTime, hh.authConfig) without any lock.
// Concurrent SetHost writes raced the goroutine's reads — race
// detector trips immediately; in production an unlucky interleaving
// crashes the process via uncaught panic in a detached goroutine
// (net/http's per-request recover doesn't see it).
//
// Post-fix, each background goroutine takes hh.mu.RLock + defer
// RUnlock at its top, so SetHost briefly queues behind the render but
// the read state is consistent.
func TestBackgroundRender_NoRaceWithSetHost(t *testing.T) {
	cm, err := cache.NewCacheManager("", "bgrender-test", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "bgrender-test", "default", logr.Discard(), cm)

	// SetHost wires up everything renderUtilityPage's goroutine reads.
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "A"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Install an Error utility-page handler with a minimal template so
	// renderUtilityPage has a valid handler to dispatch to.
	hh.mu.Lock()
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name:         "err",
		MainTemplate: "<html><body>{{ .Title }}</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}
	hh.mu.Unlock()

	// Pre-populate a STALE cache entry: Set under gen=g1, then Cycle
	// to g2 so the entry is in a non-current generation. Get then
	// returns ok=true, isCurrent=false — the stale-hit branch fires
	// and the background goroutine spawns.
	require.NoError(t, cm.Cycle("g1", false))
	uc := cm.GetCache("utility", cache.CacheOptions{})
	ph := hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType]
	cacheKey := ph.CacheKey(language.English)
	require.NoError(t, uc.Set(context.Background(), cacheKey, "stale-rendered-content"))
	require.NoError(t, cm.Cycle("g2", false))

	// Run the scenario across multiple trials — race detection on a
	// single iteration is timing-sensitive (the bg goroutine and the
	// SetHost can both start and finish before they overlap on a memory
	// access). The more trials, the more likely the race detector
	// surfaces the unsynchronised read.
	for trial := 0; trial < 50; trial++ {
		// Re-stage the stale entry — every SetHost calls cm.Cycle which
		// flushes non-current generations.
		require.NoError(t, cm.Cycle("g-trial-a", false))
		require.NoError(t, uc.Set(context.Background(), cacheKey, "stale-rendered-content"))
		require.NoError(t, cm.Cycle("g-trial-b", false))

		// Trigger the stale-hit goroutine on the main thread. Call
		// renderUtilityPage directly with EMPTY extraTemplateData so
		// the cache-Get branch fires (serveError passes ErrorCode/Msg,
		// which skips the cache branch entirely).
		func() {
			defer func() { _ = recover() }()
			hh.mu.RLock()
			_ = hh.renderUtilityPage(kdexv1alpha1.ErrorUtilityPageType, language.English, nil, &hh.Translations)
			hh.mu.RUnlock()
		}()

		// ...then immediately race a SetHost against the in-flight
		// background render. The goroutine reads hh.host /
		// hh.themeAssets / hh.scripts / hh.importmap; SetHost writes
		// all of them under hh.mu.Lock. Pre-fix the goroutine holds
		// no lock and the race detector fires.
		brandName := "B"
		if trial%2 == 0 {
			brandName = "C"
		}
		var written atomic.Bool
		go func() {
			hh.SetHost(
				context.Background(),
				&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: brandName},
				nil, nil, nil, nil, "", nil, nil,
				&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
			)
			written.Store(true)
		}()

		// Wait for SetHost AND any spawned background renders to drain
		// before moving to the next trial.
		for !written.Load() {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

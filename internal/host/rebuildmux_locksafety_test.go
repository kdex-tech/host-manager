/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package host

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"kdex.dev/crds/api/v1alpha1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// panickingAuthChecker satisfies the authChecker interface but panics inside
// ParseRequirements. Used to verify that a panic in the read-phase of
// RebuildMux doesn't leak the RLock and deadlock subsequent reconciles.
type panickingAuthChecker struct{}

func (p *panickingAuthChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (p *panickingAuthChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return false, nil
}

func (p *panickingAuthChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (p *panickingAuthChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	panic("simulated ParseRequirements panic (kdex-tech/host-manager#26)")
}

func (p *panickingAuthChecker) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return false, nil
}

// TestRebuildMux_NoOrphanLockOnPanic regression-tests kdex-tech/host-manager#26.
// Pre-fix, RebuildMux acquired hh.mu.RLock() without a deferred RUnlock; a
// panic inside ParseRequirements (called under the RLock) was caught by the
// controller-runtime panic handler but orphaned the reader on hh.mu. Every
// subsequent acquire of hh.mu blocked forever, silently wedging all
// kdex-* reconcilers (pod stayed Ready because the HTTP probe is independent
// of the workqueue).
//
// Post-fix, both lock acquisitions in RebuildMux are deferred, so a panic at
// any point releases the lock instead of leaking it.
func TestRebuildMux_NoOrphanLockOnPanic(t *testing.T) {
	log := logr.Discard()
	cacheManager, _ := cache.NewCacheManager("", "test-host", nil)
	hh := NewHostHandler(nil, "test-host", "default", log, cacheManager)

	// One page is enough to enter the page-requirements loop (where
	// ParseRequirements is called).
	hh.Pages.Set(page.PageHandler{
		Name:         "page-home",
		MainTemplate: "<html><body>home</body></html>",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Home",
			Paths: kdexv1alpha1.Paths{BasePath: "/"},
			Security: &[]v1alpha1.SecurityRequirement{
				{"bearer": []string{"pages"}},
			},
		},
	})

	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "KDex"},
		nil, nil, nil, nil, "", nil, nil,
		&auth.Exchanger{}, &auth.Config{}, "http", nil, time.Now(),
	)

	// Wire in the panicking authChecker AFTER SetHost so SetHost doesn't
	// overwrite it.
	hh.authChecker = &panickingAuthChecker{}

	// Trigger RebuildMux and recover the panic, simulating
	// controller-runtime's deferred panic handler.
	func() {
		defer func() {
			_ = recover()
		}()
		hh.RebuildMux()
	}()

	// Try to acquire the write lock with a short timeout. Pre-fix this
	// blocked forever (the orphan RLock from RebuildMux was never released).
	// Post-fix the deferred unlocks release the lock before the panic
	// escapes the function.
	acquired := make(chan struct{})
	go func() {
		hh.mu.Lock()
		defer hh.mu.Unlock()
		close(acquired)
	}()

	select {
	case <-acquired:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("hh.mu.Lock() timed out after RebuildMux panic — RLock leaked (kdex-tech/host-manager#26)")
	}

	// Also verify a fresh RebuildMux call doesn't itself deadlock (the
	// in-flight pieces don't leave behind state that breaks subsequent
	// rebuilds).
	hh.authChecker = nil
	rebuildDone := make(chan struct{})
	go func() {
		hh.RebuildMux()
		close(rebuildDone)
	}()
	select {
	case <-rebuildDone:
	case <-time.After(2 * time.Second):
		t.Fatal("subsequent RebuildMux timed out after panic-recovery")
	}

	assert.True(t, true, "lock acquired and subsequent rebuild completed")
}

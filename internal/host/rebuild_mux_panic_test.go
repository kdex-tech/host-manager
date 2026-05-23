package host

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	G "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// panickingAuthChecker forces ParseRequirements to panic on every call,
// simulating the corrupted-slice-header case observed in
// kdex-tech/host-manager#26.
type panickingAuthChecker struct{}

func (panickingAuthChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}
func (panickingAuthChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return false, nil
}
func (panickingAuthChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}
func (panickingAuthChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	panic("simulated ParseRequirements panic")
}
func (panickingAuthChecker) VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error) {
	return false, nil
}

// TestRebuildMux_PanicReleasesLocks pins the fix for
// kdex-tech/host-manager#26: a panic inside the read phase of RebuildMux
// (here: authChecker.ParseRequirements) must not orphan hh.mu. Before
// the fix, the manually held RLock would leak, every subsequent Lock or
// RLock on hh.mu would block forever, and every kdex-* reconciler would
// go silent until the pod was restarted.
func TestRebuildMux_PanicReleasesLocks(t *testing.T) {
	g := G.NewGomegaWithT(t)

	cacheManager, err := cache.NewCacheManager("", "", nil)
	g.Expect(err).NotTo(G.HaveOccurred())

	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.host = &kdexv1alpha1.KDexHostSpec{}

	// Seed a page with a non-empty BasePath BEFORE installing the
	// panicking checker — PageStore.Set fires RebuildMux via onUpdate,
	// which would otherwise hit the panic before we get to drive it
	// ourselves.
	hh.Pages.Set(page.PageHandler{
		Name: "p",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "P",
			Paths: kdexv1alpha1.Paths{BasePath: "/p"},
		},
	})
	hh.authChecker = panickingAuthChecker{}

	func() {
		defer func() {
			_ = recover() // expected: panic propagates out of RebuildMux
		}()
		hh.RebuildMux()
	}()

	// If the RLock was orphaned, this Lock() would deadlock. Run it in a
	// goroutine and fail fast on timeout instead of hanging the test.
	done := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hh.mu.Lock() blocked after RebuildMux panic — orphan RLock; deadlock would silently wedge all reconcilers")
	}
}

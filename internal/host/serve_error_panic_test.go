package host

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// panickingCacheManager satisfies cache.CacheManager but panics inside
// GetCache, simulating a panic on the render path that serveError takes
// while holding hh.mu.RLock. The class of bug is identical to
// kdex-tech/host-manager#26: any panic between the manual RLock and
// RUnlock orphans the reader, deadlocking every subsequent reconcile.
type panickingCacheManager struct{}

func (panickingCacheManager) Cycle(string, bool) error                            { return nil }
func (panickingCacheManager) GetCache(string, cache.CacheOptions) cache.Cache {
	panic("simulated render-path panic (kdex-tech/host-manager#51)")
}

// TestServeError_PanicReleasesRLock pins the fix for
// kdex-tech/host-manager#51. serveError takes hh.mu.RLock() without a
// deferred RUnlock; any panic during renderUtilityPage (template
// execution, cache backend, anything between the manual RLock and
// RUnlock) leaks the reader on hh.mu. Subsequent hh.mu.Lock() calls by
// the controller (SetHost, AddOrUpdate*) deadlock forever — the pod
// stays Ready (net/http recovers the per-request panic) but every
// reconcile silently wedges.
func TestServeError_PanicReleasesRLock(t *testing.T) {
	cm, err := cache.NewCacheManager("", "", nil)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cm)
	hh.host = &kdexv1alpha1.KDexHostSpec{}

	// Override cacheManager AFTER NewHostHandler / RebuildMux ran, so
	// the constructor doesn't itself trip the panic.
	hh.cacheManager = panickingCacheManager{}

	// serveError must reach renderUtilityPage, which means the
	// ErrorUtilityPageType handler must exist (otherwise
	// renderUtilityPage returns "" before touching cacheManager).
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = page.PageHandler{
		Name: "err",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}

	func() {
		defer func() { _ = recover() }() // expected panic
		hh.serveError(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), 500, "boom")
	}()

	done := make(chan struct{})
	go func() {
		hh.mu.Lock()
		hh.mu.Unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("hh.mu.Lock() blocked after serveError panic — orphan RLock; deadlock would silently wedge all reconcilers (#51)")
	}
}

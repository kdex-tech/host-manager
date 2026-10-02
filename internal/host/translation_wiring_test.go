package host

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	. "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// newWiringTestHostHandler returns a HostHandler with a host set through
// SetHost, so RebuildMux runs its full rebuildMuxSnapshot path.
func newWiringTestHostHandler(t *testing.T) *HostHandler {
	t.Helper()
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	setWiringTestHost(hh)
	return hh
}

// setWiringTestHost is the controller's SetHost call, reduced to what the
// catalog depends on. SetHost always rebuilds the mux.
func setWiringTestHost(hh *HostHandler) {
	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{DefaultLang: "en"}, &kdexv1alpha1.KDexObjectStatus{},
		nil, nil, nil, "", nil, nil, nil, nil, "http", nil, time.Now())
}

// liveRender renders key from the catalog the host is serving (hh.Translations),
// under the read lock the request path takes.
func liveRender(hh *HostHandler, key string) string {
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	return renderKey(&hh.Translations, key)
}

// The order the controller records with SetTranslationOrder (from
// KDexInternalHost.spec.internalTranslationRefs) is the order the live catalog
// is built in: the controller sets it immediately before SetHost, which
// rebuilds, and the last-listed translation wins a shared key.
func TestHostHandler_TranslationOrderDrivesLiveCatalog(t *testing.T) {
	g := NewGomegaWithT(t)
	hh := newWiringTestHostHandler(t)
	hh.AddOrUpdateTranslation("web-a", new(brand("a")))
	hh.AddOrUpdateTranslation("web-b", new(brand("b")))

	hh.SetTranslationOrder([]string{"web-a", "web-b"})
	setWiringTestHost(hh)
	g.Expect(liveRender(hh, "brand")).To(Equal("b"))

	hh.SetTranslationOrder([]string{"web-b", "web-a"})
	setWiringTestHost(hh)
	g.Expect(liveRender(hh, "brand")).To(Equal("a"))

	// RebuildMux on its own (the AddOrUpdate* paths) keeps the recorded order.
	hh.RebuildMux()
	g.Expect(liveRender(hh, "brand")).To(Equal("a"))
}

// A translation value the catalog cannot compile must not stop the host's mux
// from rebuilding: later changes (here, another translation) still go live.
func TestHostHandler_BadTranslationValueDoesNotFreezeRebuild(t *testing.T) {
	g := NewGomegaWithT(t)
	hh := newWiringTestHostHandler(t)

	hh.AddOrUpdateTranslation("web-chart", &kdexv1alpha1.KDexTranslationSpec{Translations: []kdexv1alpha1.Translation{
		{Lang: "en", KeysAndValues: map[string]string{"price": "Price: ${", "cart": "Cart"}},
	}})
	hh.AddOrUpdateTranslation("web-later", new(brand("later")))

	g.Expect(liveRender(hh, "brand")).To(Equal("later"), "a later change must reach the live catalog")
	g.Expect(liveRender(hh, "cart")).To(Equal("Cart"))
	g.Expect(liveRender(hh, "price")).To(Equal("price"))
}

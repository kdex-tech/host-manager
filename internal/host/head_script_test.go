package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	. "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const headScriptImportmap = `{"imports":{"@x/a":"/a.js","@x/b":"/b.js","@x/theme-lib":"/t.js"}}`

func newHeadScriptHost(t *testing.T, hostScopeRefs ...kdexv1alpha1.PackageReference) *HostHandler {
	t.Helper()
	cacheManager, err := cache.NewCacheManager("", "test-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	hh.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{DefaultLang: "en"}, &kdexv1alpha1.KDexObjectStatus{},
		hostScopeRefs, nil, nil, headScriptImportmap, nil, nil, nil, nil, "http", nil, time.Now())
	return hh
}

// headScript renders handler's head under hh.mu.RLock, as every production
// caller of headScriptToHTMLLocked does.
func headScript(hh *HostHandler, handler page.PageHandler) string {
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	return hh.headScriptToHTMLLocked(handler)
}

func pkgRef(name string) kdexv1alpha1.PackageReference {
	return kdexv1alpha1.PackageReference{Name: name, Version: "1.0.0"}
}

func importOf(name string) string {
	pr := pkgRef(name)
	return pr.ToImportStatement()
}

func TestHeadScriptToHTMLLocked_ImportsOnlyHostScopeAndPageRefs(t *testing.T) {
	g := NewGomegaWithT(t)
	hh := newHeadScriptHost(t, pkgRef("@x/theme-lib"))

	out := headScript(hh, page.PageHandler{
		PackageReferences: []kdexv1alpha1.PackageReference{pkgRef("@x/a")},
	})

	g.Expect(out).To(ContainSubstring(importOf("@x/a")))
	g.Expect(out).To(ContainSubstring(importOf("@x/theme-lib")))
	g.Expect(out).NotTo(ContainSubstring(importOf("@x/b")))
	g.Expect(out).To(ContainSubstring(headScriptImportmap))
}

func TestHeadScriptToHTMLLocked_DeterministicOrder(t *testing.T) {
	g := NewGomegaWithT(t)
	hh := newHeadScriptHost(t)
	handler := page.PageHandler{
		PackageReferences: []kdexv1alpha1.PackageReference{pkgRef("@x/z"), pkgRef("@x/a"), pkgRef("@x/m")},
	}

	first := headScript(hh, handler)
	for range 50 {
		g.Expect(headScript(hh, handler)).To(Equal(first))
	}

	a := strings.Index(first, importOf("@x/a"))
	m := strings.Index(first, importOf("@x/m"))
	z := strings.Index(first, importOf("@x/z"))
	g.Expect(a).To(BeNumerically(">=", 0))
	g.Expect(a).To(BeNumerically("<", m))
	g.Expect(m).To(BeNumerically("<", z))
}

func TestHeadScriptToHTMLLocked_ImportmapWithoutImports(t *testing.T) {
	g := NewGomegaWithT(t)

	hh := newHeadScriptHost(t)
	out := headScript(hh, page.PageHandler{})
	g.Expect(out).To(ContainSubstring(headScriptImportmap))
	g.Expect(out).To(ContainSubstring(`<script type="importmap">`))
	g.Expect(out).NotTo(ContainSubstring(`<script type="module">`))

	empty := newHeadScriptHost(t)
	empty.importmap = ""
	g.Expect(headScript(empty, page.PageHandler{})).NotTo(ContainSubstring(`importmap`))
}

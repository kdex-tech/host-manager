package host

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	G "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHostHandler_openapiHandler(t *testing.T) {
	g := G.NewGomegaWithT(t)

	cacheManager, _ := cache.NewCacheManager("", "", nil)
	th := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	th.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		OpenAPI: kdexv1alpha1.OpenAPI{
			TypesToInclude: []kdexv1alpha1.TypeToInclude{
				kdexv1alpha1.TypeBACKEND,
				kdexv1alpha1.TypeFUNCTION,
				kdexv1alpha1.TypePAGE,
				kdexv1alpha1.TypeSYSTEM,
			},
		},
		Routing: kdexv1alpha1.Routing{
			Domains: []string{"test.example.com"},
		},
	}, nil, nil, nil, nil, "", map[string]ko.PathInfo{}, nil, nil, nil, "http", nil, time.Now())

	mux := th.muxWithDefaultsLocked(th.registeredPaths) // registeredPaths is empty, but muxWithDefaultsLocked populates it for defaults

	// We expect defaults to be registered: openapi, sniffer, unimplemented ones
	// Actually we need to call RebuildMux to fully populate everything but we can test defaults.

	// Test OpenAPI endpoint
	req := httptest.NewRequest("GET", "/-/openapi", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	g.Expect(w.Code).To(G.Equal(http.StatusOK))

	var doc openapi3.T
	err := json.Unmarshal(w.Body.Bytes(), &doc)
	g.Expect(err).NotTo(G.HaveOccurred())

	g.Expect(doc.OpenAPI).To(G.Equal("3.0.0"))
	g.Expect(doc.Info.Title).To(G.Equal("KDex Host - test-host"))

	// Check if paths are present
	// We should see /-/openapi and /-/sniffer/docs at least (sniffer if sniffer != nil)
	// th.Sniffer is nil in test-host unless we set it.

	// Check /-/openapi
	pathItem := doc.Paths.Find("/-/openapi")
	g.Expect(pathItem).NotTo(G.BeNil())
	g.Expect(pathItem.Get).NotTo(G.BeNil())
	g.Expect(pathItem.Get.Summary).To(G.Equal("OpenAPI 3.0 Spec"))
}

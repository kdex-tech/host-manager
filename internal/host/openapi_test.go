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
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	G "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
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

// TestLoginHandler_CatchAllClientRouteDocumented verifies the catch-all login
// route appears in the OpenAPI path set (which /-/openapi serializes from), so
// the login client-routing capability is discoverable rather than hidden.
func TestLoginHandler_CatchAllClientRouteDocumented(t *testing.T) {
	hh := &HostHandler{
		log:        logr.Discard(),
		authConfig: &auth.Config{ActivePair: &keys.KeyPair{}},
	}
	registeredPaths := map[string]ko.PathInfo{}
	hh.loginHandler(http.NewServeMux(), registeredPaths)

	info, ok := registeredPaths["/-/login/{path...}"]
	if !ok {
		t.Fatal("catch-all login route must be documented in the OpenAPI path set that /-/openapi serializes from")
	}
	assert.Equal(t, ko.SystemPathType, info.Type)

	item := info.API.Paths["/-/login/{path...}"]
	if item.Get == nil {
		t.Fatal("documented catch-all must expose a GET operation")
	}
	assert.Equal(t, "login-clientroute-get", item.Get.OperationID)

	var hasWildcardPathParam bool
	for _, p := range item.Get.Parameters {
		if p.Value != nil && p.Value.In == "path" && p.Value.Name == "path" {
			hasWildcardPathParam = true
		}
	}
	assert.True(t, hasWildcardPathParam,
		"documented catch-all must expose the wildcard {path...} parameter so the client-routing capability is discoverable")
}

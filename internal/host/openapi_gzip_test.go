package host

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func openapiHost(t *testing.T) *HostHandler {
	t.Helper()
	cm, _ := cache.NewCacheManager("", "", nil)
	th := NewHostHandler(nil, "test-host", "default", logr.Discard(), cm)
	// Enough paths that the document clears gzhttp's minimum size, as every
	// real tenant's does by far.
	paths := map[string]ko.PathInfo{}
	for i := range 40 {
		p := fmt.Sprintf("/api/v1/thing%d", i)
		paths[p] = ko.PathInfo{Type: ko.FunctionPathType, API: ko.OpenAPI{BasePath: p, Paths: map[string]ko.PathItem{
			p: {Description: "A function path long enough to make the generated document worth compressing."},
		}}}
	}
	th.SetHost(context.Background(), &kdexv1alpha1.KDexHostSpec{
		DefaultLang: "en",
		OpenAPI: kdexv1alpha1.OpenAPI{
			TypesToInclude: []kdexv1alpha1.TypeToInclude{kdexv1alpha1.TypeFUNCTION},
		},
		Routing: kdexv1alpha1.Routing{Domains: []string{"test.example.com"}},
	}, nil, nil, nil, nil, "", paths, nil, nil, nil, "https", nil, time.Now())
	return th
}

func getOpenAPI(th *HostHandler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/-/openapi", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	th.Mux.ServeHTTP(w, req)
	return w
}

// /-/openapi is large (hundreds of KB on a real tenant) and was served
// uncompressed. It is now compressed for clients that accept it, and each
// coding gets its own ETag so a cache never answers one with the other.
func TestOpenAPI_GzipForClientsThatAcceptIt(t *testing.T) {
	th := openapiHost(t)

	plain := getOpenAPI(th, nil)
	require.Equal(t, http.StatusOK, plain.Code)
	assert.Empty(t, plain.Header().Get("Content-Encoding"))
	assert.Contains(t, plain.Header().Values("Vary"), "Accept-Encoding")

	gz := getOpenAPI(th, map[string]string{"Accept-Encoding": "gzip"})
	require.Equal(t, http.StatusOK, gz.Code)
	assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
	assert.Contains(t, gz.Header().Values("Vary"), "Accept-Encoding")
	assert.Contains(t, gz.Header().Values("Vary"), "Accept-Language", "the caching helper's Vary is kept")
	assert.Less(t, gz.Body.Len(), plain.Body.Len())

	zr, err := gzip.NewReader(gz.Body)
	require.NoError(t, err)
	raw, err := io.ReadAll(zr)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc), "the gzip body is the same JSON document")
	assert.Contains(t, doc, "openapi")

	assert.NotEqual(t, plain.Header().Get("ETag"), gz.Header().Get("ETag"), "each coding has its own ETag")

	nm := getOpenAPI(th, map[string]string{"Accept-Encoding": "gzip", "If-None-Match": gz.Header().Get("ETag")})
	assert.Equal(t, http.StatusNotModified, nm.Code, "a gzip client revalidates against the gzip ETag")
	assert.Contains(t, nm.Header().Values("Vary"), "Accept-Encoding")

	cross := getOpenAPI(th, map[string]string{"If-None-Match": gz.Header().Get("ETag")})
	assert.Equal(t, http.StatusOK, cross.Code, "the gzip ETag never validates an identity response")
}

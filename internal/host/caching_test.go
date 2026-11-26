package host

import (
	"net/http"
	"testing"

	"github.com/kdex-tech/host-manager/internal/host/ico"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/render"
)

// An applied translation must reach a browser that already holds the old
// strings on its next load: the public response carries no freshness window,
// so every reuse is revalidated, and the old ETag no longer answers 304 (#305).
func TestTranslation_RevalidatesAndSeesAppliedChange(t *testing.T) {
	hh := renderHost(t, nil)
	apply := func(v string) {
		hh.AddOrUpdateTranslation("tr-en", &kdexv1alpha1.KDexTranslationSpec{
			Translations: []kdexv1alpha1.Translation{{Lang: "en", KeysAndValues: map[string]string{"greeting": v}}},
		})
	}
	apply("hello")

	first := compressGet(t, hh, "/-/translation/en", nil)
	require.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, publicCacheControl, first.Header().Get("Cache-Control"))
	assert.False(t, hasCacheDirective(first.Header(), "max-age"), "no freshness window")
	etag := first.Header().Get("ETag")
	require.NotEmpty(t, etag)

	same := compressGet(t, hh, "/-/translation/en", map[string]string{"If-None-Match": etag})
	assert.Equal(t, http.StatusNotModified, same.Code, "unchanged strings revalidate to a 304")

	apply("bonjour")
	after := compressGet(t, hh, "/-/translation/en", map[string]string{"If-None-Match": etag})
	require.Equal(t, http.StatusOK, after.Code, "the old ETag must not validate the new strings")
	assert.Contains(t, after.Body.String(), "bonjour")
	assert.NotEqual(t, etag, after.Header().Get("ETag"))
}

// A public page render carries the same revalidate-every-time policy, and a
// page whose observed state moves no longer answers 304 to its old ETag (#305).
func TestPage_RevalidatesAndSeesAppliedChange(t *testing.T) {
	status := &kdexv1alpha1.KDexObjectStatus{ObservedGeneration: 1, Attributes: map[string]string{}}
	doc := func(label string) page.PageHandler {
		return page.PageHandler{
			Name:         "doc",
			MainTemplate: "<html><body>[[ .Title ]]</body></html>",
			Page:         &kdexv1alpha1.KDexPageSpec{Label: label, Paths: kdexv1alpha1.Paths{BasePath: "/doc"}},
			Status:       status.DeepCopy(),
		}
	}
	hh := renderHost(t, nil, doc("Before"))

	first := compressGet(t, hh, "/doc", nil)
	require.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, publicCacheControl, first.Header().Get("Cache-Control"))
	etag := first.Header().Get("ETag")
	require.NotEmpty(t, etag)
	assert.Equal(t, http.StatusNotModified,
		compressGet(t, hh, "/doc", map[string]string{"If-None-Match": etag}).Code)

	status.ObservedGeneration = 2
	hh.Pages.Set(doc("After"))
	hh.RebuildMux()
	after := compressGet(t, hh, "/doc", map[string]string{"If-None-Match": etag})
	require.Equal(t, http.StatusOK, after.Code, "the old ETag must not validate the new page")
	assert.Contains(t, after.Body.String(), "After")
}

// Every public system route takes its Cache-Control from
// applyCachingHeadersWithSeed, and no inner handler re-adds a freshness
// window: discovery, JWKS and the favicon used to (#305).
func TestPublicSystemRoutes_NoFreshnessWindow(t *testing.T) {
	hh := renderHost(t, nil)
	hh.authConfig.KeyPairs = &keys.KeyPairs{hh.authConfig.ActivePair}
	hh.favicon = ico.NewICO("", render.TemplateData{BrandName: "Kdex"})
	for _, path := range []string{
		"/.well-known/oauth-authorization-server",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/favicon.ico",
		"/-/openapi",
		"/-/translation/en",
		"/doc",
	} {
		rr := compressGet(t, hh, path, nil)
		require.Equal(t, http.StatusOK, rr.Code, path)
		assert.Equal(t, publicCacheControl, rr.Header().Get("Cache-Control"), path)
		assert.NotEmpty(t, rr.Header().Get("ETag"), path)
	}
}

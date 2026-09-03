package host

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	"golang.org/x/text/message/catalog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/render"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestHostHandler_BuildMenuEntries(t *testing.T) {
	tests := []struct {
		name              string
		items             *map[string]page.PageHandler
		isDefaultLanguage bool
		want              *map[string]any
	}{
		{
			name:  "empty",
			items: &map[string]page.PageHandler{},
			want:  nil,
		},
		{
			name:              "simple",
			isDefaultLanguage: true,
			items: &map[string]page.PageHandler{
				"foo": {
					Name: "foo",
					Page: &kdexv1alpha1.KDexPageSpec{
						Label: "Foo",
						Paths: kdexv1alpha1.Paths{
							BasePath: "/foo",
						},
					},
				},
			},
			want: &map[string]any{
				"Foo": render.PageEntry{
					BasePath: "/foo",
					Href:     "/foo",
					Label:    "Foo",
					Name:     "foo",
					Weight:   resource.MustParse("0"),
				},
			},
		},
		{
			name:              "more complex",
			isDefaultLanguage: true,
			items: &map[string]page.PageHandler{
				"foo": {
					Name: "foo",
					Page: &kdexv1alpha1.KDexPageSpec{
						Label: "Foo",
						Paths: kdexv1alpha1.Paths{
							BasePath: "/foo",
						},
						ParentPageRef: &corev1.LocalObjectReference{
							Name: "home",
						},
					},
				},
				"home": {
					Name: "home",
					Page: &kdexv1alpha1.KDexPageSpec{
						Label: "Home",
						Paths: kdexv1alpha1.Paths{
							BasePath: "/home",
						},
					},
				},
				"contact": {
					Name: "contact",
					Page: &kdexv1alpha1.KDexPageSpec{
						Label: "Contact Us",
						NavigationHints: &kdexv1alpha1.NavigationHints{
							Weight: ptr.To(resource.MustParse("100")),
						},
						Paths: kdexv1alpha1.Paths{
							BasePath: "/contact",
						},
					},
				},
			},
			want: &map[string]any{
				"Home": render.PageEntry{
					BasePath: "/home",
					Children: &map[string]any{
						"Foo": render.PageEntry{
							BasePath: "/foo",
							Href:     "/foo",
							Label:    "Foo",
							Name:     "foo",
							Weight:   resource.MustParse("0"),
						},
					},
					Href:   "/home",
					Label:  "Home",
					Name:   "home",
					Weight: resource.MustParse("0"),
				},
				"Contact Us": render.PageEntry{
					BasePath: "/contact",
					Href:     "/contact",
					Label:    "Contact Us",
					Name:     "contact",
					Weight:   resource.MustParse("100"),
				},
			},
		},
		{
			name:              "none default language",
			isDefaultLanguage: false,
			items: &map[string]page.PageHandler{
				"foo": {
					Name: "foo",
					Page: &kdexv1alpha1.KDexPageSpec{
						Label: "Foo",
						Paths: kdexv1alpha1.Paths{
							BasePath: "/foo",
						},
					},
				},
			},
			want: &map[string]any{
				"Foo": render.PageEntry{
					BasePath: "/foo",
					Href:     "/en/foo",
					Label:    "Foo",
					Name:     "foo",
					Weight:   resource.MustParse("0"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cacheManager, _ := cache.NewCacheManager("", "", nil)
			hh := NewHostHandler(fake.NewClientBuilder().Build(), "foo", "foo", logr.Logger{}, cacheManager)
			for _, it := range *tt.items {
				hh.Pages.Set(it)
			}
			tag := language.English
			catalogBuilder := catalog.NewBuilder()
			catalogBuilder.SetString(language.English, "Foo", "Foo Translated")
			got := &render.PageEntry{}

			hh.BuildMenuEntries(ctx, got, &tag, tt.isDefaultLanguage, nil)
			children := got.Children
			assert.Equal(t, tt.want, children)
		})
	}
}

// firstAuthorizedPage picks values[0] after sorting on Weight alone. Its input
// comes from maps.Values (randomized order) and slices.SortFunc is unstable, so
// with every page defaulting to weight 0 the "first" page is whichever one the
// map happened to yield. That is what makes a gated page redirect somewhere
// different on every request. See kdex-tech/host-manager#184.
func TestFirstAuthorizedPage_IsDeterministicWhenWeightsTie(t *testing.T) {
	ctx := context.Background()
	cacheManager, _ := cache.NewCacheManager("", "", nil)
	hh := NewHostHandler(fake.NewClientBuilder().Build(), "foo", "foo", logr.Discard(), cacheManager)

	for _, basePath := range []string{"/terms", "/pricing", "/signup", "/tools/bridge-mac", "/reset-password"} {
		hh.Pages.Set(page.PageHandler{
			Name: basePath,
			Page: &kdexv1alpha1.KDexPageSpec{
				Label: basePath,
				Paths: kdexv1alpha1.Paths{BasePath: basePath},
			},
		})
	}

	tag := language.English
	first := hh.firstAuthorizedPage(ctx, &tag, true)

	for i := 0; i < 200; i++ {
		assert.Equal(t, first, hh.firstAuthorizedPage(ctx, &tag, true),
			"identical requests must resolve to the same page")
	}

	assert.Equal(t, "/pricing", first, "a weight tie must break on BasePath")
}

// registerNavigationForTest builds a mux with only the
// /-/navigation/{navKey}/{l10n}/{basePathMinusLeadingSlash...} route
// registered (mirroring registerPageForTest's pattern in
// enumerated_l10n_test.go, but via navigationHandler directly since
// NavigationGet's page lookup goes through hh.Pages, not the mux), and adds
// a page at basePath so NavigationGet's page lookup succeeds before it
// reaches the language check under test.
func (hh *HostHandler) registerNavigationForTest(t *testing.T, basePath string) *http.ServeMux {
	t.Helper()

	hh.Pages.Set(page.PageHandler{
		Name: "test-page",
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Test Page",
			Paths: kdexv1alpha1.Paths{BasePath: basePath},
		},
		Navigations: map[string]string{"main": "<ul></ul>"},
	})

	mux := http.NewServeMux()
	hh.navigationHandler(mux, map[string]ko.PathInfo{})
	hh.Mux = mux
	return mux
}

// TestNavigationBadLanguageIs400NotServerError is the RED/GREEN pin for task
// 4.1: {l10n} on the navigation-fragment route is a caller-supplied API path
// parameter (unlike page routes, which after this plan's earlier tasks no
// longer parse an arbitrary segment as a language). An unsupported/malformed
// value is a CLIENT error -- kdexhttp.GetLang's failure must map to 400,
// never the 500 an out-of-range server fault would imply.
func TestNavigationBadLanguageIs400NotServerError(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	mux := hh.registerNavigationForTest(t, "/pricing")

	rr := doRequest(t, mux, "GET", "/-/navigation/main/not-a-lang/pricing")

	require.Equal(t, http.StatusBadRequest, rr.Code) // was 500
}

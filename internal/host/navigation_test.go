package host

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	"golang.org/x/text/message/catalog"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
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
							Weight: resource.MustParse("100"),
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

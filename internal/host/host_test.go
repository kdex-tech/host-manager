package host

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	G "github.com/onsi/gomega"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const (
	primaryTemplate = `<!DOCTYPE html>
<html lang="[[ .Language ]]">
	<head>
	[[ .Meta ]]
	[[ .Title ]]
	[[ .Theme ]]
	[[ .HeadScript ]]
	</head>
	<body>
	<header>
		[[ .Header ]]
	</header>
	<nav>
		[[ .Navigation.main ]]
	</nav>
	<main>
		[[ .Content.main ]]
	</main>
	<footer>
		[[ .Footer ]]
	</footer>
	[[ .FootScript ]]
	</body>
</html>`
)

func TestHostHandler_L10nRender(t *testing.T) {
	type THost struct {
		name string
		host kdexv1alpha1.KDexHostSpec
	}

	tests := []struct {
		name              string
		host              THost
		lang              string
		pageHandler       page.PageHandler
		extraTemplateData map[string]any
		translationName   string
		translation       *kdexv1alpha1.KDexTranslationSpec
		want              []string
	}{
		{
			name: "english translation",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						Content: "MAIN",
						Slot:    "main",
					},
				},
				Footer: "FOOTER",
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			lang:            "en",
			translationName: "test-translation",
			translation: &kdexv1alpha1.KDexTranslationSpec{
				Translations: []kdexv1alpha1.Translation{
					{
						Lang: "en",
						KeysAndValues: map[string]string{
							"key": "ENGLISH_TRANSLATION",
						},
					},
					{
						Lang: "fr",
						KeysAndValues: map[string]string{
							"key": "FRENCH_TRANSLATION",
						},
					},
				},
			},
			want: []string{"FOOTER", "ENGLISH_TRANSLATION", "/-/navigation/main/en/", "MAIN", "TITLE"},
		},
		{
			name: "french translation",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						Content: "MAIN",
						Slot:    "main",
					},
				},
				Footer: "FOOTER",
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			lang:            "fr",
			translationName: "test-translation",
			translation: &kdexv1alpha1.KDexTranslationSpec{
				Translations: []kdexv1alpha1.Translation{
					{
						Lang: "en",
						KeysAndValues: map[string]string{
							"key": "ENGLISH_TRANSLATION",
						},
					},
					{
						Lang: "fr",
						KeysAndValues: map[string]string{
							"key": "FRENCH_TRANSLATION",
						},
					},
				},
			},
			want: []string{"FOOTER", "FRENCH_TRANSLATION", "/-/navigation/main/fr/", "MAIN", "TITLE"},
		},
		{
			name: "no translation",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						Content: "MAIN",
						Slot:    "main",
					},
				},
				Footer: "FOOTER",
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			lang: "en",
			want: []string{"FOOTER", "key", "/-/navigation/main/en/", "MAIN", "TITLE"},
		},
		{
			name: "basic web component",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						AppName:           "sample-app",
						AppGeneration:     "1",
						Attributes:        map[string]string{"data-test": "test"},
						CustomElementName: "sample-element",
						Slot:              "main",
					},
				},
				Footer: "FOOTER",
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			lang: "en",
			want: []string{"FOOTER", "key", "/-/navigation/main/en/", `<sample-element data-content-id="main" data-app-name="sample-app" data-app-generation="1" data-test="test"></sample-element>`, "TITLE"},
		},
		{
			name: "extra template data",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						Content: "MAIN",
						Slot:    "main",
					},
				},
				Footer: `FOOTER [[ .Extra.extra ]]`,
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			lang: "en",
			extraTemplateData: map[string]any{
				"extra": "extra data",
			},
			want: []string{"FOOTER extra data", "key", "/-/navigation/main/en/", "MAIN", "TITLE"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := G.NewGomegaWithT(t)

			cacheManager, _ := cache.NewCacheManager("", "", nil)
			th := NewHostHandler(nil, tt.host.name, "default", logr.Discard(), cacheManager)
			th.SetHost(context.Background(), &tt.host.host, nil, nil, nil, nil, "", map[string]ko.PathInfo{}, nil, nil, nil, "http")
			th.AddOrUpdateTranslation(tt.translationName, tt.translation)

			got, gotErr := th.L10nRender(tt.pageHandler, map[string]any{}, language.Make(tt.lang), tt.extraTemplateData, &th.Translations)

			g.Expect(gotErr).NotTo(G.HaveOccurred())

			for _, want := range tt.want {
				g.Expect(got).To(G.ContainSubstring(want))
			}
		})
	}
}

func TestHostHandler_L10nRenders(t *testing.T) {
	type THost struct {
		name string
		host kdexv1alpha1.KDexHostSpec
	}

	tests := []struct {
		name            string
		host            THost
		pageHandler     page.PageHandler
		translationName string
		translation     *kdexv1alpha1.KDexTranslationSpec
		want            map[string][]string
	}{
		{
			name: "translations",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			pageHandler: page.PageHandler{
				Name: "sample-page-binding",
				Page: &kdexv1alpha1.KDexPageSpec{
					Label: "TITLE",
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
				MainTemplate: primaryTemplate,
				Content: map[string]page.PackedContent{
					"main": {
						Content: "MAIN",
						Slot:    "main",
					},
				},
				Footer: "FOOTER",
				Header: `[[ l10n "key" ]]`,
				Navigations: map[string]string{
					"main": "NAV",
				},
			},
			translationName: "test-translation",
			translation: &kdexv1alpha1.KDexTranslationSpec{
				Translations: []kdexv1alpha1.Translation{
					{
						Lang: "en",
						KeysAndValues: map[string]string{
							"key": "ENGLISH_TRANSLATION",
						},
					},
					{
						Lang: "fr",
						KeysAndValues: map[string]string{
							"key": "FRENCH_TRANSLATION",
						},
					},
				},
			},
			want: map[string][]string{
				"en": {
					"FOOTER", "ENGLISH_TRANSLATION", "/-/navigation/main/en/", "MAIN", "TITLE",
				},
				"fr": {
					"FOOTER", "FRENCH_TRANSLATION", "/-/navigation/main/fr/", "MAIN", "TITLE",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := G.NewGomegaWithT(t)

			cacheManager, _ := cache.NewCacheManager("", "", nil)
			th := NewHostHandler(nil, tt.host.name, "default", logr.Discard(), cacheManager)
			th.SetHost(context.Background(), &tt.host.host, nil, nil, nil, nil, "", map[string]ko.PathInfo{}, nil, nil, nil, "http")
			th.AddOrUpdateTranslation(tt.translationName, tt.translation)

			got := th.L10nRenders(tt.pageHandler, map[language.Tag]map[string]any{}, &th.Translations)

			for key, values := range tt.want {
				l10nRender := got[key]
				for _, v := range values {
					g.Expect(l10nRender).To(G.ContainSubstring(v))
				}
			}
		})
	}
}

func TestHostHandler_AddOrUpdateTranslation(t *testing.T) {
	type KeyAndExpected struct {
		key      string
		expected string
	}
	type THost struct {
		name string
		host kdexv1alpha1.KDexHostSpec
	}

	tests := []struct {
		name            string
		host            THost
		translationName string
		translation     *kdexv1alpha1.KDexTranslationSpec
		langTests       map[string]KeyAndExpected
	}{
		{
			name: "add translation",
			host: THost{
				name: "sample-host",
				host: kdexv1alpha1.KDexHostSpec{
					DefaultLang:  "en",
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing: kdexv1alpha1.Routing{
						Domains: []string{"foo.bar"},
					},
				},
			},
			// translationName: "test-translation",
			translation: &kdexv1alpha1.KDexTranslationSpec{
				Translations: []kdexv1alpha1.Translation{
					{
						Lang: "en",
						KeysAndValues: map[string]string{
							"key": "ENGLISH_TRANSLATION",
						},
					},
					{
						Lang: "fr",
						KeysAndValues: map[string]string{
							"key": "FRENCH_TRANSLATION",
						},
					},
					{
						Lang: "fr",
						KeysAndValues: map[string]string{
							"key": "LAST_ONE_WINS",
						},
					},
				},
			},
			langTests: map[string]KeyAndExpected{
				"en": {
					key:      "key",
					expected: "ENGLISH_TRANSLATION",
				},
				"fr": {
					key:      "key",
					expected: "LAST_ONE_WINS",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := G.NewGomegaWithT(t)

			cacheManager, _ := cache.NewCacheManager("", "", nil)
			th := NewHostHandler(nil, tt.host.name, "default", logr.Discard(), cacheManager)
			th.SetHost(context.Background(), &tt.host.host, nil, nil, nil, nil, "", map[string]ko.PathInfo{}, nil, nil, nil, "http")
			th.AddOrUpdateTranslation(tt.translationName, tt.translation)

			for lang, expected := range tt.langTests {
				messagePrinter := message.NewPrinter(
					language.Make(lang),
					message.Catalog(th.Translations.Catalog()),
				)
				g.Expect(
					messagePrinter.Sprintf(expected.key),
				).To(G.Equal(expected.expected))
			}
		})
	}
}

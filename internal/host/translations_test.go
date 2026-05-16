package host

import (
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestNewTranslations_LanguagesDefaultFirst(t *testing.T) {
	// With translations for de + en + fr (alphabetically de < en < fr), the
	// catalog.Builder sorts tags alphabetically by default. If we register
	// defaultLanguage="en" via catalog.Fallback, Languages() must return en
	// first so downstream matcher fallback picks the configured default.
	g := NewGomegaWithT(t)
	tr, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"de": {Translations: []kdexv1alpha1.Translation{
			{Lang: "de", KeysAndValues: map[string]string{"hello": "hallo"}},
		}},
		"fr": {Translations: []kdexv1alpha1.Translation{
			{Lang: "fr", KeysAndValues: map[string]string{"hello": "bonjour"}},
		}},
	})
	g.Expect(err).NotTo(HaveOccurred())

	langs := tr.Languages()
	g.Expect(langs).NotTo(BeEmpty())
	g.Expect(langs[0]).To(Equal(language.Make("en")), "defaultLanguage must be first; got %v", langs)
}

package host

import (
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
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
	}, nil)
	g.Expect(err).NotTo(HaveOccurred())

	langs := tr.Languages()
	g.Expect(langs).NotTo(BeEmpty())
	g.Expect(langs[0]).To(Equal(language.Make("en")), "defaultLanguage must be first; got %v", langs)
}

func brand(value string) kdexv1alpha1.KDexTranslationSpec {
	return kdexv1alpha1.KDexTranslationSpec{Translations: []kdexv1alpha1.Translation{
		{Lang: "en", KeysAndValues: map[string]string{"brand": value}},
	}}
}

func renderKey(tr *Translations, key string) string {
	return message.NewPrinter(language.English, message.Catalog(tr.Catalog())).Sprintf(key)
}

// nexus lists internal translations lowest precedence first; the catalog is
// last-write-wins, so the last listed name must win.
func TestNewTranslations_LastListedWins(t *testing.T) {
	g := NewGomegaWithT(t)
	specs := map[string]kdexv1alpha1.KDexTranslationSpec{
		"web-kdex-default-translation": brand("default"),
		"web-shop":                     brand("self-attached"),
		"web-site":                     brand("host-declared"),
	}

	tr, err := NewTranslations("en", specs, []string{"web-kdex-default-translation", "web-shop", "web-site"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(renderKey(tr, "brand")).To(Equal("host-declared"))

	tr, err = NewTranslations("en", specs, []string{"web-site", "web-shop", "web-kdex-default-translation"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(renderKey(tr, "brand")).To(Equal("default"), "order, not map iteration, decides")
}

// A translation host-manager holds but nexus has not listed (transient, during
// a rollout or before a prune) is written first, so it never overrides a
// listed one; names in the order that host-manager does not hold are ignored.
func TestNewTranslations_UnlistedGoesLowestAndUnknownIsIgnored(t *testing.T) {
	g := NewGomegaWithT(t)
	tr, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"web-stale":  brand("stale"),
		"web-listed": brand("listed"),
	}, []string{"web-not-loaded-yet", "web-listed"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(renderKey(tr, "brand")).To(Equal("listed"))
}

func TestNewTranslations_KeysAreUniqueAndSorted(t *testing.T) {
	g := NewGomegaWithT(t)
	tr, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"a": {Translations: []kdexv1alpha1.Translation{
			{Lang: "en", KeysAndValues: map[string]string{"z": "1", "brand": "a"}},
			{Lang: "fr", KeysAndValues: map[string]string{"z": "1", "brand": "a"}},
		}},
		"b": brand("b"),
	}, []string{"a", "b"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(tr.Keys()).To(Equal([]string{"brand", "z"}))
}

func TestTranslationWriteOrder(t *testing.T) {
	g := NewGomegaWithT(t)
	specs := map[string]kdexv1alpha1.KDexTranslationSpec{"c": {}, "a": {}, "listed-2": {}, "listed-1": {}}
	g.Expect(translationWriteOrder(specs, []string{"listed-1", "ghost", "listed-2", "listed-1"})).
		To(Equal([]string{"a", "c", "listed-1", "listed-2"}))
}

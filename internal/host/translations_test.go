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

// A value the catalog cannot compile (catmsg rejects "Price: ${" and
// "${x(abc)}") must not fail the whole build: one bad value in a chart-shipped
// translation would otherwise freeze the host's mux. The bad value is skipped
// and reported; the good values, in the same and in other translations, build.
func TestNewTranslations_SkipsValueThatDoesNotCompile(t *testing.T) {
	g := NewGomegaWithT(t)
	tr, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"web-shop": {Translations: []kdexv1alpha1.Translation{
			{Lang: "en", KeysAndValues: map[string]string{
				"good":  "Good",
				"price": "Price: ${",
			}},
			{Lang: "fr", KeysAndValues: map[string]string{"macro": "Use ${x(abc)} here"}},
		}},
		"web-site": {Translations: []kdexv1alpha1.Translation{
			{Lang: "en", KeysAndValues: map[string]string{"other": "Other"}},
		}},
	}, []string{"web-shop", "web-site"})
	g.Expect(err).NotTo(HaveOccurred())

	g.Expect(renderKey(tr, "good")).To(Equal("Good"))
	g.Expect(renderKey(tr, "other")).To(Equal("Other"))
	// Absent keys render as the key itself; a skipped value must do the same.
	g.Expect(renderKey(tr, "price")).To(Equal("price"))
	g.Expect(tr.Keys()).To(Equal([]string{"good", "other"}), "a skipped key is not a key")
	g.Expect(tr.Languages()).NotTo(ContainElement(language.French), "a language with only skipped values is not served")

	skipped := tr.Skipped()
	g.Expect(skipped).To(HaveLen(2))
	byKey := map[string]SkippedTranslationValue{}
	for _, s := range skipped {
		byKey[s.Key] = s
	}
	g.Expect(byKey["price"].Translation).To(Equal("web-shop"))
	g.Expect(byKey["price"].Lang).To(Equal("en"))
	g.Expect(byKey["price"].Err).To(MatchError(ContainSubstring("missing '}'")))
	g.Expect(byKey["macro"].Lang).To(Equal("fr"))
	g.Expect(byKey["macro"].Err).To(HaveOccurred())
}

// A skipped higher-precedence value must leave the lower-precedence value in
// place -- the key falls back exactly as if the bad value were absent.
// (catalog.Builder.SetString stores its output even when compilation fails,
// so the value must be compiled before it reaches the live builder.)
func TestNewTranslations_SkippedValueKeepsLowerPrecedenceValue(t *testing.T) {
	g := NewGomegaWithT(t)
	tr, err := NewTranslations("en", map[string]kdexv1alpha1.KDexTranslationSpec{
		"web-kdex-default-translation": brand("default"),
		"web-shop":                     brand("${x(abc)}"),
	}, []string{"web-kdex-default-translation", "web-shop"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(renderKey(tr, "brand")).To(Equal("default"))
	g.Expect(tr.Keys()).To(Equal([]string{"brand"}), "set successfully by another translation, so still a key")
	g.Expect(tr.Skipped()).To(HaveLen(1))
	g.Expect(tr.Skipped()[0].Translation).To(Equal("web-shop"))
}

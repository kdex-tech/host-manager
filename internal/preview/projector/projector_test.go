package projector

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestProjectHost_CopiesSpecVerbatim(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "Test Brand",
			Organization: "Test Org",
			ModulePolicy: kdexv1alpha1.LooseModulePolicy,
			Routing: kdexv1alpha1.Routing{
				Domains: []string{"test.local"},
			},
		},
	}

	got, err := ProjectHost(host, ProjectInput{})
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Name != "h1" || got.Namespace != "ns1" {
		t.Errorf("Name/Namespace: got %s/%s want h1/ns1", got.Name, got.Namespace)
	}
	if got.Spec.KDexHostSpec.BrandName != "Test Brand" {
		t.Errorf("BrandName not copied")
	}
}

func TestProjectHost_SynthesizesUtilityPageRefs(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.LooseModulePolicy,
			Routing:      kdexv1alpha1.Routing{Domains: []string{"x"}},
			UtilityPages: &kdexv1alpha1.UtilityPages{
				LoginRef:        &kdexv1alpha1.KDexObjectReference{Name: "my-login", Kind: "KDexUtilityPage"},
				ErrorRef:        &kdexv1alpha1.KDexObjectReference{Name: "my-error", Kind: "KDexUtilityPage"},
				AnnouncementRef: &kdexv1alpha1.KDexObjectReference{Name: "my-announce", Kind: "KDexUtilityPage"},
			},
		},
	}
	in := ProjectInput{
		UtilityPages: []kdexv1alpha1.KDexUtilityPage{
			{ObjectMeta: metav1.ObjectMeta{Name: "my-login", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.LoginUtilityPageType}},
			{ObjectMeta: metav1.ObjectMeta{Name: "my-error", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.ErrorUtilityPageType}},
			{ObjectMeta: metav1.ObjectMeta{Name: "my-announce", Namespace: "ns1"}, Spec: kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.AnnouncementUtilityPageType}},
		},
	}

	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Spec.LoginRef == nil || got.Spec.LoginRef.Name != "h1-login" {
		t.Errorf("LoginRef: got %+v want LocalObjectReference{Name: h1-login}", got.Spec.LoginRef)
	}
	if got.Spec.ErrorRef == nil || got.Spec.ErrorRef.Name != "h1-error" {
		t.Errorf("ErrorRef: got %+v", got.Spec.ErrorRef)
	}
	if got.Spec.AnnouncementRef == nil || got.Spec.AnnouncementRef.Name != "h1-announcement" {
		t.Errorf("AnnouncementRef: got %+v", got.Spec.AnnouncementRef)
	}
}

func TestProjectHost_SynthesizesTranslationRefs(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.LooseModulePolicy,
			Routing:      kdexv1alpha1.Routing{Domains: []string{"x"}},
			TranslationRefs: []kdexv1alpha1.KDexObjectReference{
				{Name: "tr-en", Kind: "KDexTranslation"},
				{Name: "tr-fr", Kind: "KDexTranslation"},
			},
		},
	}
	in := ProjectInput{
		Translations: []kdexv1alpha1.KDexTranslation{
			{ObjectMeta: metav1.ObjectMeta{Name: "tr-en", Namespace: "ns1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "tr-fr", Namespace: "ns1"}},
		},
	}
	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	want := []corev1.LocalObjectReference{
		{Name: "h1-tr-en"},
		{Name: "h1-tr-fr"},
	}
	if len(got.Spec.InternalTranslationRefs) != len(want) {
		t.Fatalf("InternalTranslationRefs len: got %d want %d", len(got.Spec.InternalTranslationRefs), len(want))
	}
	for i, r := range got.Spec.InternalTranslationRefs {
		if r.Name != want[i].Name {
			t.Errorf("InternalTranslationRefs[%d]: got %q want %q", i, r.Name, want[i].Name)
		}
	}
}

func TestProjectHost_MissingUtilityPageRef_SkipsWithWarning(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexHostSpec{
			BrandName:    "B",
			Organization: "O",
			ModulePolicy: kdexv1alpha1.LooseModulePolicy,
			Routing:      kdexv1alpha1.Routing{Domains: []string{"x"}},
			UtilityPages: &kdexv1alpha1.UtilityPages{
				LoginRef: &kdexv1alpha1.KDexObjectReference{Name: "missing-login", Kind: "KDexUtilityPage"},
			},
		},
	}
	in := ProjectInput{} // no UtilityPages

	got, err := ProjectHost(host, in)
	if err != nil {
		t.Fatalf("ProjectHost: %v", err)
	}
	if got.Spec.LoginRef != nil {
		t.Errorf("LoginRef should be nil when source missing; got %+v", got.Spec.LoginRef)
	}
	if len(got.Warnings) == 0 || !contains(got.Warnings, "missing-login") {
		t.Errorf("expected warning naming missing-login; got: %v", got.Warnings)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s != "" && (s == needle || strings.Contains(s, needle)) {
			return true
		}
	}
	return false
}

func TestProjectUtilityPage_NamesAndHostRef(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
	}
	up := kdexv1alpha1.KDexUtilityPage{
		ObjectMeta: metav1.ObjectMeta{Name: "my-login", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexUtilityPageSpec{
			Type: kdexv1alpha1.LoginUtilityPageType,
		},
	}
	got := ProjectUtilityPage(up, host)
	if got.Name != "h1-login" {
		t.Errorf("Name: got %q want %q (host-lowercase-type, source name discarded)", got.Name, "h1-login")
	}
	if got.Namespace != "ns1" {
		t.Errorf("Namespace: got %q", got.Namespace)
	}
	if got.Spec.HostRef.Name != "h1" {
		t.Errorf("HostRef.Name: got %q", got.Spec.HostRef.Name)
	}
	if got.Spec.Type != kdexv1alpha1.LoginUtilityPageType {
		t.Errorf("Spec.Type not copied")
	}
}

func TestProjectTranslation_NamesAndHostRef(t *testing.T) {
	host := kdexv1alpha1.KDexHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h1", Namespace: "ns1"},
	}
	tr := kdexv1alpha1.KDexTranslation{
		ObjectMeta: metav1.ObjectMeta{Name: "tr-en", Namespace: "ns1"},
		Spec: kdexv1alpha1.KDexTranslationSpec{
			Translations: []kdexv1alpha1.Translation{
				{Lang: "en", KeysAndValues: map[string]string{"hello": "Hello"}},
			},
		},
	}
	got := ProjectTranslation(tr, host)
	if got.Name != "h1-tr-en" {
		t.Errorf("Name: got %q want %q", got.Name, "h1-tr-en")
	}
	if got.Namespace != "ns1" {
		t.Errorf("Namespace: got %q want %q", got.Namespace, "ns1")
	}
	if got.Spec.HostRef.Name != "h1" {
		t.Errorf("HostRef.Name: got %q want h1", got.Spec.HostRef.Name)
	}
	if len(got.Spec.Translations) != 1 || got.Spec.Translations[0].Lang != "en" {
		t.Errorf("Spec.Translations not copied correctly: %+v", got.Spec.Translations)
	}
	if got.Spec.Translations[0].KeysAndValues["hello"] != "Hello" {
		t.Errorf("Spec.Translations[0].KeysAndValues not copied")
	}
}

package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_FlatDir_SingleFilePerCR(t *testing.T) {
	snap, err := Load("testdata/single")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.Themes), 1; got != want {
		t.Errorf("Themes: got %d, want %d", got, want)
	}
	if got, want := len(snap.Pages), 1; got != want {
		t.Errorf("Pages: got %d, want %d", got, want)
	}
}

func TestLoad_MultiDocYaml(t *testing.T) {
	snap, err := Load("testdata")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// testdata/ contains:
	//   multi-doc.yaml  → 1 KDexInternalHost + 1 KDexPage
	//   single/theme.yaml → 1 KDexTheme
	//   single/page.yaml  → 1 KDexPage
	if got, want := len(snap.InternalHosts), 1; got != want {
		t.Errorf("InternalHosts: got %d, want %d", got, want)
	}
	if got, want := len(snap.Themes), 1; got != want {
		t.Errorf("Themes: got %d, want %d", got, want)
	}
	if got, want := len(snap.Pages), 2; got != want {
		t.Errorf("Pages: got %d, want %d", got, want)
	}
}

func TestLoad_RejectsInvalidYAML(t *testing.T) {
	_, err := Load("testdata/does-not-exist")
	if err == nil {
		t.Fatal("expected error for non-existent dir; got nil")
	}
}

func TestLoad_UserFacingHost_ProjectsToInternal(t *testing.T) {
	dir := t.TempDir()
	hostYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  brandName: Test
  organization: Test
  modulePolicy: Loose
  routing:
    domains: [example.local]
`)
	if err := os.WriteFile(filepath.Join(dir, "host.yaml"), hostYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.InternalHosts), 1; got != want {
		t.Errorf("InternalHosts: got %d want %d", got, want)
	}
	if snap.InternalHosts[0].Name != "example" {
		t.Errorf("InternalHost name: got %q want example", snap.InternalHosts[0].Name)
	}
}

func TestLoad_UserFacingHostWithTranslation_ProjectsBoth(t *testing.T) {
	dir := t.TempDir()
	multiYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  brandName: Test
  organization: Test
  modulePolicy: Loose
  routing:
    domains: [example.local]
  translationRefs:
    - name: en
---
apiVersion: kdex.dev/v1alpha1
kind: KDexTranslation
metadata:
  name: en
  namespace: default
spec:
  translations:
    - lang: en
      keysAndValues:
        hello: Hello
`)
	if err := os.WriteFile(filepath.Join(dir, "all.yaml"), multiYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	snap, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := len(snap.InternalHosts), 1; got != want {
		t.Errorf("InternalHosts: got %d want %d", got, want)
	}
	if got, want := len(snap.InternalTranslations), 1; got != want {
		t.Errorf("InternalTranslations: got %d want %d", got, want)
	}
	if snap.InternalTranslations[0].Name != "example-en" {
		t.Errorf("translation name: got %q want example-en", snap.InternalTranslations[0].Name)
	}
}

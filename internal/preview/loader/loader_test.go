package loader

import (
	"os"
	"path/filepath"
	"strings"
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

func TestLoad_RejectsUserFacingHostWithGuidance(t *testing.T) {
	dir := t.TempDir()
	hostYAML := []byte(`apiVersion: kdex.dev/v1alpha1
kind: KDexHost
metadata:
  name: example
  namespace: default
spec:
  routing:
    domains: [example.local]
`)
	if err := os.WriteFile(filepath.Join(dir, "host.yaml"), hostYAML, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for KDexHost (user-facing form); got nil")
	}
	msg := err.Error()
	for _, want := range []string{"KDexHost", "KDexInternalHost", "nexus-manager"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should guide user toward post-reconcile form; missing %q in: %v", want, msg)
		}
	}
}

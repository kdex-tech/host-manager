package loader

import (
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


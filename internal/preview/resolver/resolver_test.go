package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFnOverride_URL(t *testing.T) {
	o, err := ParseFnOverride("svc=http://localhost:9000")
	if err != nil {
		t.Fatalf("ParseFnOverride: %v", err)
	}
	if o.Name != "svc" {
		t.Errorf("Name: got %q want %q", o.Name, "svc")
	}
	if o.Kind != FnOverrideURL {
		t.Errorf("Kind: got %v want %v", o.Kind, FnOverrideURL)
	}
	if o.URL != "http://localhost:9000" {
		t.Errorf("URL: got %q", o.URL)
	}
}

func TestParseFnOverride_Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	o, err := ParseFnOverride("svc=" + dir)
	if err != nil {
		t.Fatalf("ParseFnOverride: %v", err)
	}
	if o.Kind != FnOverrideDir {
		t.Errorf("Kind: got %v want %v", o.Kind, FnOverrideDir)
	}
	if o.Lang != FnLangGo {
		t.Errorf("Lang: got %v want %v", o.Lang, FnLangGo)
	}
	if o.Dir != dir {
		t.Errorf("Dir: got %q want %q", o.Dir, dir)
	}
}

func TestParseFnOverride_DirectoryWithoutKnownLanguage(t *testing.T) {
	dir := t.TempDir() // empty dir — no go.mod, no package.json
	_, err := ParseFnOverride("svc=" + dir)
	if err == nil {
		t.Fatal("expected error for dir with no recognized language manifest; got nil")
	}
}

func TestParseFnOverride_BadInput(t *testing.T) {
	cases := []string{
		"",
		"=",
		"=foo",
		"foo",                       // missing =
		"foo=relative/no/such/path", // not a URL and not an existing dir
	}
	for _, c := range cases {
		if _, err := ParseFnOverride(c); err == nil {
			t.Errorf("ParseFnOverride(%q): expected error; got nil", c)
		}
	}
}

func TestParseMissingAppMode(t *testing.T) {
	for _, in := range []string{"placeholder", "skip", "error"} {
		if _, err := ParseMissingAppMode(in); err != nil {
			t.Errorf("ParseMissingAppMode(%q): %v", in, err)
		}
	}
	if _, err := ParseMissingAppMode("nope"); err == nil {
		t.Errorf("expected error for invalid mode")
	}
}

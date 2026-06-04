# kdex CLI — Phase 2 (Preview MVP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `kdex preview --crs <dir> --fn name=<path|URL>` render a multi-page KDexHost locally with theme/app overrides, supervised local function processes (directory form) or external URLs (URL fallback form), and 501 stubs for out-of-scope routes (auth/login/feedback/openapi). Manual browser refresh on changes; hot reload is Phase 3.

**Architecture:** New `internal/preview/` package tree consumed by `cmd/kdex/cmd/preview.go`. Loader reads CRs from disk; resolver parses CLI flags into typed overrides; supervisor spawns and lifecycles function children; fakeclient seeds host-manager's existing reconcilers behind `client/fake`; synthesizer skips the `KDexInternalHost` / `KDexFunction` reconcilers that don't compose (per spike findings) and directly calls `HostHandler.SetHost(...)` with synthesized route data; stubs replace out-of-scope route handlers with 501; composition root wires everything and serves HTTP.

**Tech Stack:** Go 1.26, cobra, sigs.k8s.io/controller-runtime/pkg/client/fake, sigs.k8s.io/yaml, host-manager's existing `internal/cache`, `internal/host`, `internal/controller`, `internal/web/server`.

**Spec reference:** [2026-05-31-kdex-unified-cli-design.md](../specs/2026-05-31-kdex-unified-cli-design.md), §1 v1 scope, §2 structure, §4 preview deltas, §4.5 function-proxy override, §11 phase 2.

**Spike forward references** (do not re-derive what's already in the spike READMEs):
- [hack/spike-fakeclient/README.md](../../../hack/spike-fakeclient/README.md) — fake-client patterns, reconciler set to run vs. skip, constructor signatures (`cache.NewCacheManager`, `host.NewHostHandler`, `server.New`), the `KDexClusterPageArchetype` default trap, the `[[.Content.main]]` template-field singular gotcha.
- [hack/spike-ogen/README.md](../../../hack/spike-ogen/README.md) — not directly relevant to Phase 2 but documents codegen integration for later.

---

## Phase 2 deliverable

After all tasks complete:

```
./bin/kdex preview \
  --crs internal/preview/testdata/fixtures/basic \
  --fn echo=internal/preview/testdata/fixtures/sample-fn-go \
  --addr :8080
```

- Starts up; spawns the supervised Go function child on an ephemeral port.
- Serves `http://localhost:8080/` returning the composed KDexHost page HTML.
- `http://localhost:8080/api/echo` proxies to the supervised function.
- `http://localhost:8080/-/login` returns `501 Not Implemented — preview does not serve <feature>`.
- Ctrl-C tears down the supervised child within 5 seconds.

---

## Task 2.1: CR loader (flat dir, multi-doc YAML)

Reads CRs from `--crs` directory, decodes into typed objects, returns a snapshot. Kustomize support deferred to Phase 4; this loader only walks `*.yaml`/`*.yml` files and splits multi-doc YAML.

**Files:**
- Create: `internal/preview/loader/loader.go`
- Create: `internal/preview/loader/loader_test.go`
- Create: `internal/preview/loader/testdata/multi-doc.yaml` (test fixture)
- Create: `internal/preview/loader/testdata/single/page.yaml` (test fixture)
- Create: `internal/preview/loader/testdata/single/theme.yaml` (test fixture)

- [ ] **Step 1: Write the failing test**

`internal/preview/loader/loader_test.go`:

```go
package loader

import (
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
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
	// multi-doc.yaml contains a Host + Page in one file
	hostCount := len(snap.InternalHosts)
	pageCount := len(snap.Pages)
	if hostCount == 0 || pageCount == 0 {
		t.Errorf("expected at least one Host and one Page from multi-doc; got hosts=%d pages=%d", hostCount, pageCount)
	}
}

func TestLoad_RejectsInvalidYAML(t *testing.T) {
	_, err := Load("testdata/does-not-exist")
	if err == nil {
		t.Fatal("expected error for non-existent dir; got nil")
	}
}

var _ = kdexv1alpha1.KDexInternalHost{} // keep import live until Snapshot exists
```

- [ ] **Step 2: Write the test fixtures**

`internal/preview/loader/testdata/single/theme.yaml`:
```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexTheme
metadata:
  name: t1
  namespace: default
spec:
  assets:
    - name: style.css
      style: ":root { --x: 1; }"
```

`internal/preview/loader/testdata/single/page.yaml`:
```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexPage
metadata:
  name: home
  namespace: default
spec:
  basePath: /
  themeRef:
    name: t1
  contents:
    - id: main
      name: main
      rawHTML: "<p>hello</p>"
```

`internal/preview/loader/testdata/multi-doc.yaml`:
```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexInternalHost
metadata:
  name: h1
  namespace: default
spec:
  routing:
    domains: [test.local]
    scheme: http
  themeRef:
    name: t1
---
apiVersion: kdex.dev/v1alpha1
kind: KDexPage
metadata:
  name: home
  namespace: default
spec:
  basePath: /
  themeRef:
    name: t1
  contents:
    - id: main
      name: main
      rawHTML: "<p>multi-doc</p>"
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
go test ./internal/preview/loader/ -v
```

Expected: FAIL with compile error (`undefined: Load`).

- [ ] **Step 4: Write `internal/preview/loader/loader.go`**

```go
// Package loader reads KDex CRs from a directory of YAML files and returns
// a typed Snapshot. Multi-doc YAML is supported. Subdirectories are walked
// recursively. Files not matching *.yaml or *.yml are ignored.
//
// Kustomize support is deferred to Phase 4 of the preview implementation.
package loader

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Snapshot is the typed view of the CR state on disk at the time Load was called.
type Snapshot struct {
	InternalHosts          []kdexv1alpha1.KDexInternalHost
	Themes                 []kdexv1alpha1.KDexTheme
	Pages                  []kdexv1alpha1.KDexPage
	Apps                   []kdexv1alpha1.KDexApp
	Functions              []kdexv1alpha1.KDexFunction
	InternalTranslations   []kdexv1alpha1.KDexInternalTranslation
	InternalUtilityPages   []kdexv1alpha1.KDexInternalUtilityPage
	ClusterPageArchetypes  []kdexv1alpha1.KDexClusterPageArchetype
}

// Load walks dir recursively for *.yaml/*.yml files, decodes them into Snapshot,
// and returns the Snapshot. Multi-doc YAML files are split on the standard
// document separator. Unknown kinds are ignored (not an error) — this lets a
// user's CR dir contain non-KDex resources without breaking preview.
func Load(dir string) (*Snapshot, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	snap := &Snapshot{}

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return decodeDocs(path, data, snap)
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func decodeDocs(path string, data []byte, snap *Snapshot) error {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for docIdx := 0; ; docIdx++ {
		doc, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		if err := decodeOne(path, docIdx, doc, snap); err != nil {
			return err
		}
	}
}

// peek at apiVersion/kind to decide which typed list to append to.
type meta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func decodeOne(path string, docIdx int, doc []byte, snap *Snapshot) error {
	var m meta
	if err := yaml.Unmarshal(doc, &m); err != nil {
		return fmt.Errorf("%s doc %d: parse meta: %w", path, docIdx, err)
	}
	if m.APIVersion != "kdex.dev/v1alpha1" {
		return nil // ignore non-KDex resources
	}
	switch m.Kind {
	case "KDexInternalHost":
		var obj kdexv1alpha1.KDexInternalHost
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.InternalHosts = append(snap.InternalHosts, obj)
	case "KDexTheme":
		var obj kdexv1alpha1.KDexTheme
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Themes = append(snap.Themes, obj)
	case "KDexPage":
		var obj kdexv1alpha1.KDexPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Pages = append(snap.Pages, obj)
	case "KDexApp":
		var obj kdexv1alpha1.KDexApp
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Apps = append(snap.Apps, obj)
	case "KDexFunction":
		var obj kdexv1alpha1.KDexFunction
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Functions = append(snap.Functions, obj)
	case "KDexInternalTranslation":
		var obj kdexv1alpha1.KDexInternalTranslation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.InternalTranslations = append(snap.InternalTranslations, obj)
	case "KDexInternalUtilityPage":
		var obj kdexv1alpha1.KDexInternalUtilityPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.InternalUtilityPages = append(snap.InternalUtilityPages, obj)
	case "KDexClusterPageArchetype":
		var obj kdexv1alpha1.KDexClusterPageArchetype
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.ClusterPageArchetypes = append(snap.ClusterPageArchetypes, obj)
	default:
		// Silently ignore other kdex.dev kinds we don't yet handle. Phase 2
		// scope: only the kinds listed above.
	}
	return nil
}

```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
go test ./internal/preview/loader/ -v
```

Expected: all three tests PASS.

- [ ] **Step 6: Verify the rest of the module still builds**

```bash
go build ./...
```

Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/preview/loader/
git commit -m "preview: add CR loader (flat-dir, multi-doc YAML)"
```

---

## Task 2.2: Override resolver (theme + app + function)

Parses CLI flags (`--theme`, `--app`, `--fn`, `--missing-app`, `--missing-fn`) into typed Override structs that downstream packages consume. For `--fn`, decides directory-vs-URL at parse time and rejects bad input.

**Files:**
- Create: `internal/preview/resolver/resolver.go`
- Create: `internal/preview/resolver/resolver_test.go`

- [ ] **Step 1: Write the failing test**

`internal/preview/resolver/resolver_test.go`:

```go
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test ./internal/preview/resolver/ -v
```

Expected: FAIL (compile errors).

- [ ] **Step 3: Write `internal/preview/resolver/resolver.go`**

```go
// Package resolver parses CLI/config-file override flags into typed
// structures that downstream packages (loader, supervisor, server) consume.
package resolver

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// FnOverrideKind is "dir" or "url" — determined at parse time.
type FnOverrideKind int

const (
	FnOverrideURL FnOverrideKind = iota
	FnOverrideDir
)

// FnLang is the recognized function-project language. v1 supports Go only;
// FnLangNode is reserved for when `kdex codegen node` lands.
type FnLang int

const (
	FnLangUnknown FnLang = iota
	FnLangGo
	FnLangNode
)

// FnOverride is one entry from a --fn flag or the config file's `functions:` map.
type FnOverride struct {
	Name string
	Kind FnOverrideKind
	URL  string // populated when Kind == FnOverrideURL OR after Supervisor binds a port
	Dir  string // populated when Kind == FnOverrideDir
	Lang FnLang  // populated when Kind == FnOverrideDir
}

// ThemeOverride and AppOverride are simpler: name + URL-or-path. Theme and app
// can both accept either a local filesystem path (served by preview at
// /__preview/{themes,apps}/<name>/) or an http(s) URL passed through.
type ThemeOverride struct {
	Name string
	// Path is set if the value is an existing local directory; otherwise URL.
	Path string
	URL  string
}

type AppOverride struct {
	Name string
	Path string
	URL  string
}

// MissingAppMode controls behavior when a referenced app has no override.
type MissingAppMode int

const (
	MissingAppPlaceholder MissingAppMode = iota
	MissingAppSkip
	MissingAppError
)

// MissingFnMode mirrors MissingAppMode for functions.
type MissingFnMode int

const (
	MissingFnPlaceholder MissingFnMode = iota
	MissingFnSkip
	MissingFnError
)

// ParseFnOverride parses a "name=<dir|URL>" string. Decides at parse time
// whether the value is a directory (resolved relative to PWD if not absolute),
// an http(s) URL, or neither (error).
func ParseFnOverride(spec string) (FnOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return FnOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return FnOverride{}, fmt.Errorf("fn override %q: invalid URL: %w", name, err)
		}
		return FnOverride{Name: name, Kind: FnOverrideURL, URL: value}, nil
	}
	// Treat as filesystem path.
	abs, err := filepath.Abs(value)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: resolve path: %w", name, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: path %q: %w", name, abs, err)
	}
	if !info.IsDir() {
		return FnOverride{}, fmt.Errorf("fn override %q: %q is not a directory", name, abs)
	}
	lang, err := detectLang(abs)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: %w", name, err)
	}
	return FnOverride{Name: name, Kind: FnOverrideDir, Dir: abs, Lang: lang}, nil
}

// detectLang looks for language-specific manifest files in dir. Phase 2 only
// recognizes go.mod (Go); package.json with scripts.dev is reserved for the
// codegen-node v2 milestone.
func detectLang(dir string) (FnLang, error) {
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return FnLangGo, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return FnLangUnknown, fmt.Errorf("directory %q has package.json but Node functions are not yet supported (waiting on kdex codegen node)", dir)
	}
	return FnLangUnknown, fmt.Errorf("directory %q is not a recognized KDex function project (no go.mod)", dir)
}

// ParseThemeOverride accepts either a local directory path or an http(s) URL.
// Files referenced by a directory must exist; URLs are not validated beyond
// shape.
func ParseThemeOverride(spec string) (ThemeOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return ThemeOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return ThemeOverride{}, fmt.Errorf("theme override %q: invalid URL: %w", name, err)
		}
		return ThemeOverride{Name: name, URL: value}, nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %w", name, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %w", name, err)
	}
	if !info.IsDir() {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %q is not a directory", name, abs)
	}
	return ThemeOverride{Name: name, Path: abs}, nil
}

// ParseAppOverride mirrors ParseThemeOverride.
func ParseAppOverride(spec string) (AppOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return AppOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return AppOverride{}, fmt.Errorf("app override %q: invalid URL: %w", name, err)
		}
		return AppOverride{Name: name, URL: value}, nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return AppOverride{}, fmt.Errorf("app override %q: %w", name, err)
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return AppOverride{}, fmt.Errorf("app override %q: %q is not a directory or valid URL", name, value)
	}
	return AppOverride{Name: name, Path: abs}, nil
}

// ParseMissingAppMode parses one of: "placeholder", "skip", "error".
func ParseMissingAppMode(s string) (MissingAppMode, error) {
	switch strings.ToLower(s) {
	case "placeholder", "":
		return MissingAppPlaceholder, nil
	case "skip":
		return MissingAppSkip, nil
	case "error":
		return MissingAppError, nil
	default:
		return 0, fmt.Errorf("invalid --missing-app mode %q (want placeholder|skip|error)", s)
	}
}

// ParseMissingFnMode parses one of: "placeholder", "skip", "error".
func ParseMissingFnMode(s string) (MissingFnMode, error) {
	switch strings.ToLower(s) {
	case "placeholder", "":
		return MissingFnPlaceholder, nil
	case "skip":
		return MissingFnSkip, nil
	case "error":
		return MissingFnError, nil
	default:
		return 0, fmt.Errorf("invalid --missing-fn mode %q (want placeholder|skip|error)", s)
	}
}

// splitNameValue parses "name=value". Empty name or value is an error.
func splitNameValue(spec string) (string, string, error) {
	idx := strings.Index(spec, "=")
	if idx <= 0 {
		return "", "", fmt.Errorf("override %q: expected NAME=VALUE", spec)
	}
	name := spec[:idx]
	value := spec[idx+1:]
	if value == "" {
		return "", "", fmt.Errorf("override %q: empty value", spec)
	}
	return name, value, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test ./internal/preview/resolver/ -v
```

Expected: all four tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/preview/resolver/
git commit -m "preview: add override resolver (theme, app, fn flags)"
```

---

## Task 2.3: Function supervisor — directory-form spawn

Spawns and supervises function children for directory-form `--fn` overrides. Ephemeral port allocation, intentional env-var omission, startup wait, lifecycle teardown.

**Files:**
- Create: `internal/preview/supervisor/supervisor.go`
- Create: `internal/preview/supervisor/supervisor_test.go`
- Create: `internal/preview/supervisor/testdata/echo-fn/go.mod`
- Create: `internal/preview/supervisor/testdata/echo-fn/main.go`

- [ ] **Step 1: Write the test fixture (a tiny Go function project)**

`internal/preview/supervisor/testdata/echo-fn/go.mod`:
```
module echofn

go 1.26
```

`internal/preview/supervisor/testdata/echo-fn/main.go`:
```go
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ECHO %s", r.URL.Path)
	})
	http.HandleFunc("/env", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "AUDIENCE=%q JWKS_URL=%q PKS_URL=%q",
			os.Getenv("AUDIENCE"), os.Getenv("JWKS_URL"), os.Getenv("PKS_URL"))
	})
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Write the failing test**

`internal/preview/supervisor/supervisor_test.go`:

```go
package supervisor

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
)

func TestSpawn_GoFunction_BindsPortAndServes(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, err := filepath.Abs("testdata/echo-fn")
	if err != nil {
		t.Fatal(err)
	}
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	defer sup.Shutdown(5 * time.Second)

	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	resp, err := http.Get(url + "/echo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); !strings.HasPrefix(got, "ECHO ") {
		t.Errorf("body: got %q, want prefix ECHO", got)
	}
}

func TestSpawn_GoFunction_OmitsAuthEnvVars(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, _ := filepath.Abs("testdata/echo-fn")
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	defer sup.Shutdown(5 * time.Second)

	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	resp, _ := http.Get(url + "/env")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, `AUDIENCE=""`) || !strings.Contains(got, `JWKS_URL=""`) || !strings.Contains(got, `PKS_URL=""`) {
		t.Errorf("auth env vars leaked into child env: %s", got)
	}
}

func TestShutdown_TerminatesChild(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, _ := filepath.Abs("testdata/echo-fn")
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if err := sup.Shutdown(5 * time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// After shutdown, the URL should refuse connections.
	client := http.Client{Timeout: 1 * time.Second}
	if _, err := client.Get(url + "/echo"); err == nil {
		t.Errorf("child still serving after Shutdown")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
go test ./internal/preview/supervisor/ -v -short=false
```

Expected: FAIL (compile errors — `New`, `Spawn`, `Shutdown`, `Options` undefined).

- [ ] **Step 4: Write `internal/preview/supervisor/supervisor.go`**

```go
// Package supervisor spawns and lifecycles supervised function children for
// directory-form --fn overrides. Each function gets an ephemeral port,
// auth env vars are deliberately omitted (§4.5 auth handling), and Shutdown
// tears all children down (SIGTERM then SIGKILL).
package supervisor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
)

// Options configures a Supervisor.
type Options struct {
	// StartupTimeout is how long to wait for a spawned child to bind its
	// allocated port. Default 30 seconds if zero.
	StartupTimeout time.Duration

	// Stderr is where supervisor messages and child stdout/stderr go.
	// Default os.Stderr if nil.
	Stderr io.Writer
}

// Supervisor manages a set of spawned function children.
type Supervisor struct {
	opts     Options
	mu       sync.Mutex
	children []*child
}

type child struct {
	name string
	url  string
	cmd  *exec.Cmd
}

// New constructs a Supervisor.
func New(opts Options) *Supervisor {
	if opts.StartupTimeout == 0 {
		opts.StartupTimeout = 30 * time.Second
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	return &Supervisor{opts: opts}
}

// Spawn starts a child for the directory-form override and returns the
// http://localhost:<port> URL after the child binds.
//
// Returns an error if:
//   - the override is not a directory form
//   - the language is not supported
//   - port allocation fails
//   - the child fails to start or bind its port before StartupTimeout
func (s *Supervisor) Spawn(ctx context.Context, ov resolver.FnOverride) (string, error) {
	if ov.Kind != resolver.FnOverrideDir {
		return "", fmt.Errorf("supervisor.Spawn: override %q is not directory-form", ov.Name)
	}

	port, err := allocatePort()
	if err != nil {
		return "", fmt.Errorf("allocate port for %q: %w", ov.Name, err)
	}

	cmd, err := buildCommand(ov, port)
	if err != nil {
		return "", err
	}
	cmd.Dir = ov.Dir
	cmd.Env = []string{
		"PORT=" + fmt.Sprint(port),
		"HOME=" + os.Getenv("HOME"),
		"PATH=" + os.Getenv("PATH"),
		"GOPATH=" + os.Getenv("GOPATH"),
		"GOCACHE=" + os.Getenv("GOCACHE"),
		"GOMODCACHE=" + os.Getenv("GOMODCACHE"),
		// AUDIENCE / ISSUER / JWKS_URL / PKS_URL deliberately omitted.
		// See §4.5 auth handling.
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	prefix := fmt.Sprintf("[%s] ", ov.Name)
	cmd.Stdout = prefixWriter{w: s.opts.Stderr, prefix: prefix}
	cmd.Stderr = prefixWriter{w: s.opts.Stderr, prefix: prefix}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %q: %w", ov.Name, err)
	}

	url := fmt.Sprintf("http://localhost:%d", port)

	if err := waitForPort(ctx, url, s.opts.StartupTimeout); err != nil {
		_ = killTree(cmd)
		return "", fmt.Errorf("function %q failed to bind port %d within %s: %w", ov.Name, port, s.opts.StartupTimeout, err)
	}

	s.mu.Lock()
	s.children = append(s.children, &child{name: ov.Name, url: url, cmd: cmd})
	s.mu.Unlock()
	return url, nil
}

// Shutdown sends SIGTERM to every child, waits up to gracePeriod, then SIGKILL.
func (s *Supervisor) Shutdown(gracePeriod time.Duration) error {
	s.mu.Lock()
	children := s.children
	s.children = nil
	s.mu.Unlock()

	for _, c := range children {
		fmt.Fprintf(s.opts.Stderr, "[%s] shutting down\n", c.name)
		_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
	}
	done := make(chan struct{})
	go func() {
		for _, c := range children {
			_ = c.cmd.Wait()
		}
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(gracePeriod):
		for _, c := range children {
			_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return nil
	}
}

// buildCommand picks the spawn command per detected language.
func buildCommand(ov resolver.FnOverride, _ int) (*exec.Cmd, error) {
	switch ov.Lang {
	case resolver.FnLangGo:
		return exec.Command("go", "run", "."), nil
	case resolver.FnLangNode:
		return exec.Command("npm", "run", "dev"), nil
	default:
		return nil, fmt.Errorf("unsupported language for %q", ov.Name)
	}
}

// allocatePort binds :0, reads the assigned port, then closes the listener.
// Race window: between close and the child re-binding, another process could
// claim the port. In practice this is rare (ephemeral port ranges are large)
// and documented as a known edge case for v1.
func allocatePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}

// waitForPort polls the URL until it returns any HTTP response (200, 404, etc.)
// or the context is canceled / timeout elapses.
func waitForPort(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout")
		}
		client := http.Client{Timeout: 500 * time.Millisecond}
		resp, err := client.Get(url + "/")
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// killTree sends SIGKILL to the child's process group.
func killTree(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

// prefixWriter prefixes every line written through it with prefix.
type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p prefixWriter) Write(b []byte) (int, error) {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	total := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if _, err := p.w.Write([]byte(p.prefix)); err != nil {
			return total, err
		}
		if _, err := p.w.Write(line); err != nil {
			return total, err
		}
		if _, err := p.w.Write([]byte{'\n'}); err != nil {
			return total, err
		}
		total += len(line) + 1
	}
	return len(b), nil
}

```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/preview/supervisor/ -v -short=false -timeout 120s
```

Expected: all three tests PASS. They are slow because each spawns `go run` which compiles the test fixture.

- [ ] **Step 6: Verify `go build ./...` still works**

```bash
go build ./...
```

Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/preview/supervisor/
git commit -m "preview: add function supervisor (dir-form spawn, ephemeral port)"
```

---

## Task 2.4: Stubbed 501 handlers for out-of-scope routes

Replace handlers for login/feedback/apitoken/openapi routes with 501 responses. Per the spec, these routes don't make sense without a real cluster.

**Files:**
- Create: `internal/preview/stubs/stubs.go`
- Create: `internal/preview/stubs/stubs_test.go`

- [ ] **Step 1: Write the failing test**

`internal/preview/stubs/stubs_test.go`:

```go
package stubs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotImplementedHandler_ReturnsHelpfulMessage(t *testing.T) {
	h := NotImplemented("login")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/-/login", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotImplemented {
		t.Errorf("Code: got %d, want %d", w.Code, http.StatusNotImplemented)
	}
	body := w.Body.String()
	if !strings.Contains(body, "preview") || !strings.Contains(body, "login") {
		t.Errorf("body should mention preview + feature; got: %q", body)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/preview/stubs/ -v
```

Expected: FAIL (compile error).

- [ ] **Step 3: Write `internal/preview/stubs/stubs.go`**

```go
// Package stubs provides 501 Not Implemented HTTP handlers for routes that
// preview cannot meaningfully serve (auth, login, feedback, OpenAPI
// aggregation). They register under their normal routes so requests don't
// silently 404 — instead, the user gets a clear explanation.
package stubs

import (
	"fmt"
	"net/http"
)

// NotImplemented returns an http.Handler that responds 501 with a body naming
// the feature and pointing the user at the design spec.
func NotImplemented(feature string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, "kdex preview does not serve %s.\nThis endpoint requires a live cluster. See docs/superpowers/specs/2026-05-31-kdex-unified-cli-design.md §6.\n", feature)
	})
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/preview/stubs/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/preview/stubs/
git commit -m "preview: add 501 stub handler for out-of-scope routes"
```

---

## Task 2.5: Fake-client + reconciler runner

Seeds `sigs.k8s.io/controller-runtime/pkg/client/fake` with a Snapshot from the loader, runs the reconciler set that DOES compose cleanly under fake.Client (page, translation, utility), and returns a populated `internal/cache` / `internal/host` state.

Skips `KDexInternalHostReconciler` and `KDexFunctionReconciler` — those are synthesized directly in Task 2.6 per the spike findings.

**Files:**
- Create: `internal/preview/fakeclient/fakeclient.go`
- Create: `internal/preview/fakeclient/fakeclient_test.go`

- [ ] **Step 1: Write the failing test**

`internal/preview/fakeclient/fakeclient_test.go`:

```go
package fakeclient

import (
	"context"
	"testing"

	"github.com/kdex-tech/host-manager/internal/preview/loader"
)

func TestSetup_RunsPageReconciler(t *testing.T) {
	snap, err := loader.Load("../loader/testdata/single")
	if err != nil {
		t.Fatalf("loader.Load: %v", err)
	}

	fc, err := Setup(context.Background(), snap)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if fc.HostHandler == nil {
		t.Fatal("HostHandler is nil")
	}
	if fc.CacheManager == nil {
		t.Fatal("CacheManager is nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/preview/fakeclient/ -v
```

Expected: FAIL (compile errors).

- [ ] **Step 3: Write `internal/preview/fakeclient/fakeclient.go`**

The structure follows `hack/spike-fakeclient/main.go` — refer to that file's `run()` for the canonical pattern. Key points the spike validated:

1. Build scheme with `clientgoscheme`, `kdexv1alpha1`, `configuration`.
2. Use `fake.NewClientBuilder().WithScheme(scheme).WithObjects(...).WithStatusSubresource(&kdexv1alpha1.KDexPage{})` — status subresource is required for `KDexPageReconciler.Reconcile` to call `r.Status().Update()`.
3. Construct `cache.NewCacheManager`, `host.NewHostHandler`, then construct each reconciler with the fake client and these dependencies.
4. Run `Reconcile` directly in a loop (don't try to instantiate a controller-runtime Manager — it requires a real `*rest.Config`).
5. Inject a default `KDexClusterPageArchetype` with `kdex.dev/default=true` label if the snapshot doesn't include one — Phase 0 spike confirmed page reconciler nil-derefs without it.

Skeleton (consult the spike for full constructor signatures):

```go
// Package fakeclient seeds a fake controller-runtime client from a loader
// Snapshot and runs the reconciler set that composes cleanly under fake.Client.
// Skips KDexInternalHost / KDexFunction reconcilers per the spike findings.
package fakeclient

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/controller"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/preview/loader"
)

// FakeClient bundles the fake client + the populated state.
type FakeClient struct {
	Client       client.Client
	CacheManager *cache.CacheManager
	HostHandler  *host.HostHandler
	Scheme       *runtime.Scheme
}

// Setup builds the fake client, runs the page/translation/utility reconcilers
// to populate the cache + host handler from snap's data, and returns the
// assembled FakeClient. The KDexInternalHost and KDexFunction reconcilers are
// NOT run; their state is synthesized in Task 2.6 from CR data + overrides.
func Setup(ctx context.Context, snap *loader.Snapshot) (*FakeClient, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kdexv1alpha1.AddToScheme(scheme))
	utilruntime.Must(configuration.AddToScheme(scheme))

	objs := snapshotToObjects(snap)
	objs = append(objs, ensureDefaultArchetype(snap))

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(
			&kdexv1alpha1.KDexPage{},
			&kdexv1alpha1.KDexInternalTranslation{},
			&kdexv1alpha1.KDexInternalUtilityPage{},
		).
		Build()

	cm := cache.NewCacheManager() // adjust to actual constructor — see spike
	hh := host.NewHostHandler( /* args per spike */ )

	if err := reconcilePages(ctx, cli, snap, cm, hh); err != nil {
		return nil, err
	}
	// translations + utility reconcilers similarly

	return &FakeClient{Client: cli, CacheManager: cm, HostHandler: hh, Scheme: scheme}, nil
}

func snapshotToObjects(snap *loader.Snapshot) []client.Object {
	var out []client.Object
	for i := range snap.Themes {
		out = append(out, &snap.Themes[i])
	}
	for i := range snap.Pages {
		out = append(out, &snap.Pages[i])
	}
	for i := range snap.InternalHosts {
		out = append(out, &snap.InternalHosts[i])
	}
	for i := range snap.InternalTranslations {
		out = append(out, &snap.InternalTranslations[i])
	}
	for i := range snap.InternalUtilityPages {
		out = append(out, &snap.InternalUtilityPages[i])
	}
	for i := range snap.ClusterPageArchetypes {
		out = append(out, &snap.ClusterPageArchetypes[i])
	}
	// Apps + Functions are NOT included; their proxy targets are synthesized.
	_ = corev1.Pod{} // keep import live until decided whether Pods are needed
	return out
}

// ensureDefaultArchetype injects a minimal default KDexClusterPageArchetype
// labeled kdex.dev/default=true if the snapshot doesn't already contain one.
// Without this, KDexPageReconciler nil-derefs — see spike findings.
func ensureDefaultArchetype(snap *loader.Snapshot) client.Object {
	for i := range snap.ClusterPageArchetypes {
		if snap.ClusterPageArchetypes[i].Labels["kdex.dev/default"] == "true" {
			return nil // already present
		}
	}
	// Construct a minimal default — copy from the spike's hack/spike-fakeclient/main.go.
	return &kdexv1alpha1.KDexClusterPageArchetype{
		// ... full literal — refer to spike main.go:235-247
	}
}

// reconcilePages runs KDexPageReconciler twice per CR (finalizer-add pass then
// real reconcile), matching the spike's two-pass pattern.
func reconcilePages(ctx context.Context, cli client.Client, snap *loader.Snapshot, cm *cache.CacheManager, hh *host.HostHandler) error {
	r := &controller.KDexPageReconciler{
		Client: cli,
		// other fields per spike
	}
	for i := range snap.Pages {
		p := &snap.Pages[i]
		for pass := 0; pass < 2; pass++ {
			req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(p)}
			if _, err := r.Reconcile(ctx, req); err != nil {
				return fmt.Errorf("page %s/%s reconcile pass %d: %w", p.Namespace, p.Name, pass, err)
			}
		}
	}
	return nil
}
```

**This skeleton intentionally has gaps** — the implementer must consult `hack/spike-fakeclient/main.go` and the `internal/cache` / `internal/host` source for the actual constructor signatures, the full default-archetype literal, and the reconciler field names. The spike already proved the pattern works; the implementer's job is to encode the spike's findings into this package.

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test ./internal/preview/fakeclient/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/preview/fakeclient/
git commit -m "preview: add fake-client setup + reconciler runner"
```

---

## Task 2.6: HostHandler synthesis (skip KDexInternalHost + KDexFunction reconcilers)

Mirrors the spike's `SetHost(...)` direct-call pattern: walks `KDexInternalHost` and `KDexFunction` CRs from the loader Snapshot + the function URL map (URLs from URL-form overrides + ephemeral URLs from supervised children), constructs the route table arguments, and calls `HostHandler.SetHost` directly.

This is the function-proxy plumbing per §4.5 resolution semantics.

**Files:**
- Create: `internal/preview/synth/synth.go`
- Create: `internal/preview/synth/synth_test.go`

- [ ] **Step 1: Write the failing test**

```go
package synth

import (
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestSynthesize_HostWithSingleFunction(t *testing.T) {
	host := kdexv1alpha1.KDexInternalHost{
		// minimal fixture
	}
	fn := kdexv1alpha1.KDexFunction{
		// matches host's namespace + has basePath /api/echo
	}
	urls := map[string]string{"echo": "http://localhost:12345"}

	routes, err := SynthesizeRoutes(host, []kdexv1alpha1.KDexFunction{fn}, urls)
	if err != nil {
		t.Fatalf("SynthesizeRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("expected 1 route; got %d", len(routes))
	}
	if routes[0].URL != "http://localhost:12345" {
		t.Errorf("URL: got %q", routes[0].URL)
	}
}
```

- [ ] **Step 2: Write `internal/preview/synth/synth.go`**

The implementer must consult `hack/spike-fakeclient/main.go:130-160` and `internal/host/host.go` to find the exact `SetHost` signature. Sketch:

```go
// Package synth synthesizes routing state for HostHandler from CR data +
// function URL overrides, skipping the reconcilers that depend on Knative
// status (KDexInternalHost, KDexFunction).
package synth

import (
	"fmt"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

	"github.com/kdex-tech/host-manager/internal/host"
)

// Route is a single proxy route synthesized from a KDexFunction CR + override URL.
type Route struct {
	BasePath string
	URL      string
}

// SynthesizeRoutes builds the route list for a host from its KDexFunction CRs
// and the resolved override URLs. Functions without an override are omitted
// from the route list (the caller can decide how to surface that — missing-fn
// placeholder is handled by the proxy resolver, not here).
func SynthesizeRoutes(h kdexv1alpha1.KDexInternalHost, fns []kdexv1alpha1.KDexFunction, urls map[string]string) ([]Route, error) {
	var routes []Route
	for i := range fns {
		fn := &fns[i]
		if fn.Namespace != h.Namespace {
			continue
		}
		url, ok := urls[fn.Name]
		if !ok {
			continue
		}
		routes = append(routes, Route{
			BasePath: fn.Spec.BasePath,
			URL:      url,
		})
	}
	return routes, nil
}

// ApplyToHostHandler calls hh.SetHost with the synthesized routing data.
// The exact SetHost signature comes from hack/spike-fakeclient/main.go.
func ApplyToHostHandler(hh *host.HostHandler, h kdexv1alpha1.KDexInternalHost, routes []Route) error {
	// hh.SetHost(...) per spike
	return fmt.Errorf("not yet wired — implementer fills this in from spike main.go:130-160")
}
```

- [ ] **Step 3: Implementer fills in `ApplyToHostHandler` from the spike**

This is the load-bearing call. Refer to `hack/spike-fakeclient/main.go` line 130-160 for the SetHost signature and argument projection. The spike's successful render is the existence proof; this function is the productionized version.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/preview/synth/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/preview/synth/
git commit -m "preview: synthesize routes for HostHandler (skip KDexInternalHost/Function reconcilers)"
```

---

## Task 2.7: Preview composition root

Wires loader → resolver → supervisor → fakeclient → synth → web server. Provides `Run(ctx, opts)` that blocks until ctx is canceled.

**Files:**
- Create: `internal/preview/server/server.go`
- Create: `internal/preview/server/server_test.go`

- [ ] **Step 1: Write `internal/preview/server/server.go`**

```go
// Package server wires the preview pipeline end-to-end. Loader reads CRs from
// disk, resolver parses CLI flags, supervisor spawns supervised function
// children, fakeclient seeds the reconciler state, synth wires the proxy
// routes, and a host-manager web.server.New HTTP server serves requests.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/fakeclient"
	"github.com/kdex-tech/host-manager/internal/preview/loader"
	"github.com/kdex-tech/host-manager/internal/preview/resolver"
	"github.com/kdex-tech/host-manager/internal/preview/supervisor"
	"github.com/kdex-tech/host-manager/internal/preview/synth"
	"github.com/kdex-tech/host-manager/internal/web/server"
)

// Options captures the CLI flag values.
type Options struct {
	CRsDir          string
	Addr            string
	Host            string
	ThemeOverrides  []resolver.ThemeOverride
	AppOverrides    []resolver.AppOverride
	FnOverrides     []resolver.FnOverride
	MissingApp      resolver.MissingAppMode
	MissingFn       resolver.MissingFnMode
	FnStartupTimeout time.Duration
}

// Run boots preview and blocks until ctx is canceled.
func Run(ctx context.Context, opts Options) error {
	snap, err := loader.Load(opts.CRsDir)
	if err != nil {
		return fmt.Errorf("load CRs: %w", err)
	}
	if len(snap.InternalHosts) == 0 {
		return fmt.Errorf("no KDexInternalHost found in %s", opts.CRsDir)
	}
	if len(snap.InternalHosts) > 1 && opts.Host == "" {
		return fmt.Errorf("%d KDexInternalHosts found; pass --host <name> to disambiguate", len(snap.InternalHosts))
	}
	host := pickHost(snap.InternalHosts, opts.Host)

	sup := supervisor.New(supervisor.Options{StartupTimeout: opts.FnStartupTimeout})
	defer sup.Shutdown(5 * time.Second)

	urls := map[string]string{}
	for _, ov := range opts.FnOverrides {
		switch ov.Kind {
		case resolver.FnOverrideURL:
			urls[ov.Name] = ov.URL
		case resolver.FnOverrideDir:
			url, err := sup.Spawn(ctx, ov)
			if err != nil {
				return fmt.Errorf("spawn fn %s: %w", ov.Name, err)
			}
			urls[ov.Name] = url
		}
	}

	fc, err := fakeclient.Setup(ctx, snap)
	if err != nil {
		return fmt.Errorf("fakeclient: %w", err)
	}

	routes, err := synth.SynthesizeRoutes(host, snap.Functions, urls)
	if err != nil {
		return fmt.Errorf("synth: %w", err)
	}
	if err := synth.ApplyToHostHandler(fc.HostHandler, host, routes); err != nil {
		return fmt.Errorf("apply routes: %w", err)
	}

	srv := server.New( /* args per spike spike-fakeclient/main.go */ )
	httpSrv := &http.Server{Addr: opts.Addr, Handler: srv.Handler}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
```

The `server.New` argument list comes from the spike — implementer fills in.

- [ ] **Step 2: Write `internal/preview/server/server_test.go`** with one smoke test that boots `Run`, hits `/` once, and tears down. Full end-to-end (page + function proxy) is Task 2.10; this one just proves the composition root wires up without crashing.

```go
package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRun_ServesBasicPage(t *testing.T) {
	if testing.Short() {
		t.Skip("server test boots a real listener")
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{
			CRsDir: "testdata/basic",
			Addr:   addr,
		})
	}()
	waitForServer(t, "http://"+addr+"/")

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) {
		t.Errorf("expected HTML; got: %s", body)
	}

	cancel()
	<-errCh // wait for Run to return
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		client := http.Client{Timeout: 200 * time.Millisecond}
		if resp, err := client.Get(url); err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start", url)
}
```

Remember to `import "bytes"` at the top.

- [ ] **Step 3: Run tests**

```bash
go test ./internal/preview/server/ -v -timeout 60s
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/preview/server/
git commit -m "preview: add composition root (wires loader, supervisor, fakeclient, synth, server)"
```

---

## Task 2.8: Wire the preview subcommand

Replace the "not yet implemented" stub in `cmd/kdex/cmd/preview.go` with the actual flag definitions and a call to `internal/preview/server.Run`.

**Files:**
- Modify: `cmd/kdex/cmd/preview.go`
- Modify: `cmd/kdex/cmd/preview_test.go` (update or delete the "not implemented" test)

- [ ] **Step 1: Replace `cmd/kdex/cmd/preview.go`**

```go
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
	"github.com/kdex-tech/host-manager/internal/preview/server"
)

func NewPreviewCmd() *cobra.Command {
	var (
		crsDir    string
		addr      string
		host      string
		themes    []string
		apps      []string
		fns       []string
		missApp   string
		missFn    string
		fnTimeout time.Duration
	)
	cmd := &cobra.Command{
		Use:   "preview",
		Short: "Preview the KCNAS runtime locally",
		Long: `Preview renders KDexHost composition (theme + pages + archetypes +
page-headers/footers/navigation) from a directory of CRs on disk and serves
the result on a local HTTP port. Function-proxy routes resolve via the
--fn flag, either to a supervised local directory (dev-friendly) or to an
external URL (fallback for tunnels / IDE-debug processes).

Manual refresh in v1; hot reload is Phase 3.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			themeOverrides := make([]resolver.ThemeOverride, 0, len(themes))
			for _, s := range themes {
				ov, err := resolver.ParseThemeOverride(s)
				if err != nil {
					return err
				}
				themeOverrides = append(themeOverrides, ov)
			}
			appOverrides := make([]resolver.AppOverride, 0, len(apps))
			for _, s := range apps {
				ov, err := resolver.ParseAppOverride(s)
				if err != nil {
					return err
				}
				appOverrides = append(appOverrides, ov)
			}
			fnOverrides := make([]resolver.FnOverride, 0, len(fns))
			for _, s := range fns {
				ov, err := resolver.ParseFnOverride(s)
				if err != nil {
					return err
				}
				fnOverrides = append(fnOverrides, ov)
			}
			ma, err := resolver.ParseMissingAppMode(missApp)
			if err != nil {
				return err
			}
			mf, err := resolver.ParseMissingFnMode(missFn)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sig
				fmt.Fprintln(os.Stderr, "shutdown signal received")
				cancel()
			}()

			return server.Run(ctx, server.Options{
				CRsDir:           crsDir,
				Addr:             addr,
				Host:             host,
				ThemeOverrides:   themeOverrides,
				AppOverrides:     appOverrides,
				FnOverrides:      fnOverrides,
				MissingApp:       ma,
				MissingFn:        mf,
				FnStartupTimeout: fnTimeout,
			})
		},
	}
	cmd.Flags().StringVar(&crsDir, "crs", "", "Directory containing KDex CR YAMLs (required)")
	cmd.Flags().StringVar(&addr, "addr", ":8080", "HTTP listen address")
	cmd.Flags().StringVar(&host, "host", "", "KDexInternalHost name (required if >1 in --crs)")
	cmd.Flags().StringArrayVar(&themes, "theme", nil, "Theme override: name=<path|URL>, repeatable")
	cmd.Flags().StringArrayVar(&apps, "app", nil, "App override: name=<path|URL>, repeatable")
	cmd.Flags().StringArrayVar(&fns, "fn", nil, "Function override: name=<dir|URL>, repeatable")
	cmd.Flags().StringVar(&missApp, "missing-app", "placeholder", "Behavior for unrowed apps: placeholder|skip|error")
	cmd.Flags().StringVar(&missFn, "missing-fn", "placeholder", "Behavior for unrowed functions: placeholder|skip|error")
	cmd.Flags().DurationVar(&fnTimeout, "fn-startup-timeout", 30*time.Second, "Wait for supervised functions to bind their port")
	_ = cmd.MarkFlagRequired("crs")
	return cmd
}
```

- [ ] **Step 2: Update `cmd/kdex/cmd/preview_test.go`**

Replace the "not yet implemented" tests with one that verifies `--help` shows the new flags. Drop `TestPreviewCmd_NotImplementedYet`.

```go
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestPreviewCmd_StubAdvertisesPreviewSubcommand(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.AddCommand(NewPreviewCmd())
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"preview", "--help"})

	_ = root.Execute()

	out := buf.String()
	for _, want := range []string{"--crs", "--fn", "--theme", "--app", "--missing-app", "--missing-fn"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview --help should mention %q; got: %q", want, out)
		}
	}
}

func TestPreviewCmd_RequiresCrsFlag(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.AddCommand(NewPreviewCmd())
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"preview"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --crs missing; got nil")
	}
	if !strings.Contains(err.Error(), "crs") {
		t.Errorf("error should mention --crs; got: %v", err)
	}
}
```

- [ ] **Step 3: Run tests to verify they pass**

```bash
go test ./cmd/kdex/cmd/ -v
```

Expected: all PASS.

- [ ] **Step 4: Build and smoke-test**

```bash
make build-kdex
./bin/kdex preview --help
./bin/kdex preview --crs internal/preview/server/testdata/basic --addr :18080 &
sleep 5
curl -s http://localhost:18080/ | head -5
kill %1
```

Expected: `--help` shows all flags; preview boots without crashing; `curl /` returns HTML (likely 404 if the testdata doesn't have a `/` route, but the response shape proves the server is up).

- [ ] **Step 5: Commit**

```bash
git add cmd/kdex/cmd/preview.go cmd/kdex/cmd/preview_test.go
git commit -m "preview: wire subcommand to internal/preview/server.Run"
```

---

## Task 2.9: Integration test fixtures

Create a small but realistic fixture set under `internal/preview/server/testdata/` that exercises page composition + a function proxy.

**Files:**
- Create: `internal/preview/server/testdata/basic/host.yaml`
- Create: `internal/preview/server/testdata/basic/theme.yaml`
- Create: `internal/preview/server/testdata/basic/page.yaml`
- Create: `internal/preview/server/testdata/basic/function.yaml`
- Create: `internal/preview/server/testdata/sample-fn-go/go.mod`
- Create: `internal/preview/server/testdata/sample-fn-go/main.go`

- [ ] **Step 1: Write the CR fixtures**

Mirror `hack/spike-fakeclient/testdata/*.yaml` for host/theme/page (those are known to work end-to-end). Add `function.yaml`:

```yaml
apiVersion: kdex.dev/v1alpha1
kind: KDexFunction
metadata:
  name: echo
  namespace: default
spec:
  basePath: /api/echo
  origin:
    image:
      reference: ignored-in-preview
```

- [ ] **Step 2: Write the sample Go function**

Mirror `internal/preview/supervisor/testdata/echo-fn/` exactly.

- [ ] **Step 3: Commit**

```bash
git add internal/preview/server/testdata/
git commit -m "preview: add integration fixtures (basic host + sample Go function)"
```

---

## Task 2.10: End-to-end integration test

One test that boots preview against the basic fixtures, hits the rendered page and the function proxy, then tears down cleanly.

**Files:**
- Modify: `internal/preview/server/server_test.go`

- [ ] **Step 1: Add the integration test**

```go
func TestPreview_RendersPageAndProxiesFunction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real server + go run child")
	}
	crsDir := "testdata/basic"
	fnDir, _ := filepath.Abs("testdata/sample-fn-go")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Pick a random port for the preview server itself.
	addr := freeAddr(t)

	go func() {
		_ = server.Run(ctx, server.Options{
			CRsDir: crsDir,
			Addr:   addr,
			FnOverrides: []resolver.FnOverride{
				{Name: "echo", Kind: resolver.FnOverrideDir, Dir: fnDir, Lang: resolver.FnLangGo},
			},
			FnStartupTimeout: 60 * time.Second,
		})
	}()

	waitForServer(t, "http://"+addr+"/")

	// Hit the page
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("<html")) {
		t.Errorf("expected HTML response; got: %s", body)
	}

	// Hit the proxied function
	resp, err = http.Get("http://" + addr + "/api/echo/echo")
	if err != nil {
		t.Fatalf("GET /api/echo/echo: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.HasPrefix(body, []byte("ECHO ")) {
		t.Errorf("expected ECHO prefix from function; got: %s", body)
	}

	cancel()
}
```

Reuse `freeAddr` and `waitForServer` from Task 2.7's `server_test.go` (same package).

- [ ] **Step 2: Run the test**

```bash
go test ./internal/preview/server/ -run TestPreview_Renders -v -timeout 120s
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/preview/server/server_test.go
git commit -m "preview: end-to-end integration test (page + function proxy)"
```

---

## Task 2.11: Verify the full Phase 2 deliverable

Final gate. Build, full test run, lint, manual smoke.

- [ ] **Step 1: Lint + test**

```bash
make lint
make test
```

Both PASS.

- [ ] **Step 2: Manual smoke**

```bash
make build
./bin/kdex preview \
  --crs internal/preview/server/testdata/basic \
  --fn echo=internal/preview/server/testdata/sample-fn-go \
  --addr :18080 &
PID=$!
sleep 8
curl -s http://localhost:18080/ | head -10
curl -s http://localhost:18080/api/echo/test
kill $PID
```

Expected: HTML response to `/`; `ECHO /test` from the proxy.

- [ ] **Step 3: Confirm preview tests stayed at 100% coverage on the new code**

```bash
go test -cover ./internal/preview/...
```

Expected: coverage is meaningful (≥70% for loader/resolver/supervisor/stubs; integration tests cover server/synth/fakeclient).

- [ ] **Step 4: No commit needed for verification.** If anything failed, file a fix-up; otherwise advance.

---

## Conclusion

After Task 2.11:

- `kdex preview` is functional and exits cleanly on SIGINT.
- Pages render with theme content.
- Function-proxy works for both directory-form (preview supervises) and URL-form overrides.
- Out-of-scope routes return helpful 501s.
- Spike `hack/` directories can be deleted in a follow-up (their findings are now encoded in `internal/preview/`).

Next plan: Phase 3 (hot reload) — fsnotify watcher covering CRs + theme/app/fn paths, WS hub, JS shim, error overlay, function-source restart-on-change.

## Out-of-band notes

- **Spike-to-real translation:** several tasks reference `hack/spike-fakeclient/main.go` line ranges for constructor signatures and call patterns. The implementer should consult those rather than re-discovering them — the spike's purpose was to surface this knowledge.
- **`KDexFunction.Spec.BasePath` field name:** verify against `kdex-crds/api/v1alpha1` types (the spec gives the conceptual name; the Go field name may differ).
- **Phase 2 ships supervised-function spawn-once, NOT hot-reload.** A function-source change requires the user to `Ctrl-C` and restart preview. Phase 3 fixes that.
- **No CI changes in Phase 2.** Distribution (brew, npm, container images) lands in Phase 5.

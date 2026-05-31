# kdex CLI — Phase 0 + Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate the two load-bearing technical assumptions of the unified kdex CLI design (fake-client + reconcilers; ogen-as-library), then perform the mechanical restructure that prepares the repo for the preview and codegen subcommand implementations to land in subsequent plans.

**Architecture:** Phase 0 is throwaway exploration under `hack/`. Phase 1 reshapes `cmd/` into a two-binary structure (`host-manager` keeps the operator; new `kdex` is the unified CLI with stub subcommands wired via cobra), updates the Makefile and Dockerfile to build both binaries, and leaves CI semantics unchanged for now.

**Tech Stack:** Go 1.26, cobra, sigs.k8s.io/controller-runtime, sigs.k8s.io/controller-runtime/pkg/client/fake, github.com/ogen-go/ogen (spike only).

**Spec reference:** [2026-05-31-kdex-unified-cli-design.md](../specs/2026-05-31-kdex-unified-cli-design.md), §2, §3, §5, §11 phases 0–1.

---

## Phase 0 — Spike validation

Two throwaway exercises live under `hack/`. They are committed (for evidence + reproducibility) but are **not consumed by any other code**. After phase 1 completes, the spike directories can be deleted by a future cleanup commit; they intentionally do not block.

### Task 0.1: Spike fake-client + reconcilers

Validate that host-manager's existing reconcilers (`internal/controller/*`) run correctly behind `sigs.k8s.io/controller-runtime/pkg/client/fake` and produce a populated `internal/cache` that `internal/web/server` can serve from.

**Files:**
- Create: `hack/spike-fakeclient/main.go`
- Create: `hack/spike-fakeclient/testdata/host.yaml` (minimal KDexHost CR)
- Create: `hack/spike-fakeclient/testdata/theme.yaml` (minimal KDexTheme CR)
- Create: `hack/spike-fakeclient/testdata/page.yaml` (minimal KDexPage CR)
- Create: `hack/spike-fakeclient/README.md` (results, what was learned)

- [ ] **Step 1: Sketch the minimal CR fixture set**

Write three YAML files under `hack/spike-fakeclient/testdata/`. Use the simplest valid form of each CR — refer to `kcnas/crds/` in the consuming infra repo for canonical examples, or `internal/controller/*_test.go` mock objects for in-repo references.

`host.yaml`: a KDexHost with `spec.routing.domains = ["spike.local"]`, `spec.themeRef.name = "spike-theme"`, no auth, no faasAdaptorRef.

`theme.yaml`: a KDexTheme with one minimal HTML asset (theme name `spike-theme`).

`page.yaml`: a KDexPage with `spec.path = "/"`, `spec.themeRef.name = "spike-theme"`, minimal content.

These fixtures don't need to be sophisticated — they're for proving the wiring works, not for exercising every CR feature.

- [ ] **Step 2: Write `hack/spike-fakeclient/main.go`**

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/controller"
)

func main() {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kdexv1alpha1.AddToScheme(scheme))
	utilruntime.Must(configuration.AddToScheme(scheme))

	objs, err := loadFixtures("hack/spike-fakeclient/testdata", scheme)
	if err != nil {
		die("load fixtures: %v", err)
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		Build()

	c := cache.New() // adjust constructor name to match internal/cache
	_ = c

	mgr, err := ctrl.NewManager(nil, ctrl.Options{
		Scheme:  scheme,
		Client:  cli, // NOTE: controller-runtime Manager normally takes a *rest.Config; for the spike we may need to construct reconcilers directly without a Manager. Document what works in README.md.
	})
	if err != nil {
		// Expected to fail: Manager requires a real rest.Config.
		// Spike documents this: directly construct reconcilers + Reconcile() in a loop instead.
		fmt.Fprintf(os.Stderr, "Manager creation needs rest.Config; falling back to direct reconciler invocation\n")
	}
	_ = mgr

	_ = controller.KDexInternalHostReconciler{} // confirm import resolves; spike fills in actual reconcile call

	srv := httptest.NewServer(makeServer(c))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Host = "spike.local"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		die("get: %v", err)
	}
	defer resp.Body.Close()
	fmt.Printf("status=%d\n", resp.StatusCode)

	_ = ctx //nolint
}

func makeServer(c interface{}) http.Handler {
	return http.NotFoundHandler() // placeholder; spike replaces with real internal/web/server constructor
}

func loadFixtures(dir string, scheme *runtime.Scheme) ([]ctrl.Object, error) {
	var objs []ctrl.Object
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		obj := &unstructuredAny{}
		if err := yaml.Unmarshal(data, obj); err != nil {
			return nil, err
		}
		objs = append(objs, obj)
	}
	return objs, nil
}

type unstructuredAny struct{} // fix during spike — use unstructured.Unstructured or typed scheme decoding

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

var ctx = context.Background()
```

This is a **scaffold** — the spike's job is to make it actually run. Expect:
- `controller-runtime` Manager probably needs a real `rest.Config`; if so, construct reconcilers directly and call `Reconcile(ctx, req)` in a loop manually instead.
- The cache constructor name in `internal/cache` may differ from `cache.New()` — adjust to whatever's actually exported.
- `internal/web/server` constructor signature is the spike's chief unknown; whatever it is, get it instantiated.

The spike succeeds when `go run ./hack/spike-fakeclient` exits 0 with `status=200` and a non-empty HTML body printed.

- [ ] **Step 3: Run the spike**

```bash
go run ./hack/spike-fakeclient
```

Expected on success: prints `status=200` and a recognizable HTML fragment.

- [ ] **Step 4: Document results in `hack/spike-fakeclient/README.md`**

Cover:
- Did `controller-runtime` Manager work with `fake.Client`, or did we have to invoke reconcilers directly?
- What were the constructor signatures for `internal/cache` and `internal/web/server`?
- Any controller assumptions that fake-client doesn't satisfy (resource versions, watch events, status subresource semantics)?
- **Decision:** PROCEED to Phase 1, or ESCALATE to envtest.

If ESCALATE: stop here. Open a discussion with the user about the envtest pivot before continuing. Do not silently roll forward.

- [ ] **Step 5: Commit**

```bash
git add hack/spike-fakeclient/
git commit -m "hack: spike fake-client + reconcilers for preview"
```

---

### Task 0.2: Spike ogen library API

Validate that ogen exposes a programmatic Generator that produces buildable Go from an OpenAPI spec, without requiring `go generate` or PATH dependence.

**Files:**
- Create: `hack/spike-ogen/main.go`
- Create: `hack/spike-ogen/testdata/openapi.json` (minimal OpenAPI 3.0 fixture)
- Create: `hack/spike-ogen/README.md`

- [ ] **Step 1: Add the minimal OpenAPI fixture**

`hack/spike-ogen/testdata/openapi.json`:

```json
{
  "openapi": "3.0.3",
  "info": { "title": "Spike", "version": "0.1.0" },
  "paths": {
    "/echo": {
      "get": {
        "operationId": "echo",
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": { "msg": { "type": "string" } }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 2: Write `hack/spike-ogen/main.go`**

```go
package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ogen-go/ogen"
	"github.com/ogen-go/ogen/gen"
)

func main() {
	specPath := "hack/spike-ogen/testdata/openapi.json"
	outDir := "/tmp/kdex-spike-ogen-out"

	if err := os.RemoveAll(outDir); err != nil {
		die("clean outdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "api"), 0o755); err != nil {
		die("mkdir: %v", err)
	}

	data, err := os.ReadFile(specPath)
	if err != nil {
		die("read spec: %v", err)
	}

	spec, err := ogen.Parse(data)
	if err != nil {
		die("parse spec: %v", err)
	}

	g, err := gen.NewGenerator(spec, gen.Options{
		Package: "api",
	})
	if err != nil {
		die("gen.NewGenerator: %v", err)
	}

	if err := g.WriteSource(osFS{root: filepath.Join(outDir, "api")}); err != nil {
		die("WriteSource: %v", err)
	}

	if err := writeGoMod(outDir); err != nil {
		die("write go.mod: %v", err)
	}

	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = outDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		die("go build: %v", err)
	}
	fmt.Println("spike-ogen OK: api package built")
}

type osFS struct{ root string }

func (o osFS) WriteFile(name string, content []byte) error {
	return os.WriteFile(filepath.Join(o.root, name), content, 0o644)
}

func (o osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(o.root, name))
}

func (o osFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(filepath.Join(o.root, name))
}

func writeGoMod(dir string) error {
	mod := `module spikegen

go 1.26

require github.com/ogen-go/ogen v0.0.0
`
	return os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
```

Caveats the spike must resolve:
- `gen.Generator.WriteSource` expects an `fs.FS`-shaped writer. The exact interface name may differ between ogen releases; check `go doc github.com/ogen-go/ogen/gen` and adjust.
- The output may need additional ogen-runtime deps in `go.mod` (`go-faster/errors`, `go-faster/jx`, etc.). Run `go mod tidy` after first failed build to capture them; commit the resulting `go.mod`.

- [ ] **Step 3: Add ogen to the host-manager go.mod**

```bash
go get github.com/ogen-go/ogen@latest
go mod tidy
```

This is needed even for the spike because the spike imports ogen as a library inside the host-manager module.

- [ ] **Step 4: Run the spike**

```bash
go run ./hack/spike-ogen
```

Expected: prints `spike-ogen OK: api package built` and exits 0. The `/tmp/kdex-spike-ogen-out/api/` directory contains the generated Go.

- [ ] **Step 5: Document results in `hack/spike-ogen/README.md`**

Cover:
- Exact ogen library API used (`ogen.Parse`, `gen.NewGenerator`, `g.WriteSource`).
- Output FS interface signature.
- Runtime deps ogen produced code requires (`go-faster/*`, etc.).
- **Decision:** PROCEED to library invocation in `kdex codegen go`, or ESCALATE to bundled-binary-subprocess fallback.

If ESCALATE: stop. Discuss the fallback before phase 1.

- [ ] **Step 6: Commit**

```bash
git add hack/spike-ogen/ go.mod go.sum
git commit -m "hack: spike ogen library API"
```

---

## Phase 1 — Restructure

Mechanical refactor. The exit criterion is `make build-host-manager build-kdex` produces both binaries and `make test` passes unchanged. CI is intentionally not touched in this phase; chart consumers still get the same `host-manager` image as before.

### Task 1.1: Rename `cmd/main.go` to `cmd/host-manager/main.go`

**Files:**
- Move: `cmd/main.go` → `cmd/host-manager/main.go`
- Modify: `Dockerfile` (update COPY + go build path)
- Modify: `Makefile` (update binary build path)
- Test: existing tests pass unchanged

- [ ] **Step 1: Move the file**

```bash
mkdir -p cmd/host-manager
git mv cmd/main.go cmd/host-manager/main.go
```

- [ ] **Step 2: Update Dockerfile**

In `Dockerfile`, change:

```dockerfile
COPY cmd/main.go cmd/main.go
```
to:
```dockerfile
COPY cmd/host-manager/main.go cmd/host-manager/main.go
```

And change:
```dockerfile
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go
```
to:
```dockerfile
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager ./cmd/host-manager
```

(Switch to package-style path so future per-package imports under `cmd/host-manager/` work without revisiting the Dockerfile.)

- [ ] **Step 3: Update Makefile `build:` target**

Find the existing `build:` recipe (which likely contains `go build ... cmd/main.go` or similar). Replace its build command with:

```makefile
go build -o bin/manager ./cmd/host-manager
```

If the recipe also produces the cli/ binaries (ecdsa, paseto, rsa, env), leave those lines alone.

- [ ] **Step 4: Verify the build still works**

```bash
make build
```

Expected: `bin/manager` exists; exit 0.

- [ ] **Step 5: Verify tests still pass**

```bash
make test
```

Expected: all tests pass. If a test references `cmd/main.go` as a string path, update it.

- [ ] **Step 6: Verify docker-build still works**

```bash
make docker-build
```

Expected: a Docker image is produced. If your local docker daemon isn't reachable, skip this step and note it for the reviewer.

- [ ] **Step 7: Commit**

```bash
git add cmd/host-manager/main.go Dockerfile Makefile
git commit -m "cmd: rename main.go to cmd/host-manager/main.go"
```

---

### Task 1.2: Add cobra dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add cobra**

```bash
go get github.com/spf13/cobra@latest
go mod tidy
```

- [ ] **Step 2: Verify go.mod includes cobra**

```bash
grep cobra go.mod
```

Expected: a line like `github.com/spf13/cobra v1.x.x`.

- [ ] **Step 3: Verify the module still compiles**

```bash
go build ./...
```

Expected: exit 0.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "go.mod: add cobra dependency for kdex CLI"
```

---

### Task 1.3: Add `cmd/kdex/cmd/root.go` (cobra root)

**Files:**
- Create: `cmd/kdex/cmd/root.go`
- Test: `cmd/kdex/cmd/root_test.go`

- [ ] **Step 1: Write the failing test**

`cmd/kdex/cmd/root_test.go`:

```go
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCmd_PrintsHelpByDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "kdex") {
		t.Errorf("expected help output to contain 'kdex'; got: %q", out)
	}
	if !strings.Contains(out, "Available Commands") {
		t.Errorf("expected help output to list commands; got: %q", out)
	}
}
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
go test ./cmd/kdex/cmd/ -run TestRootCmd_PrintsHelpByDefault -v
```

Expected: FAIL (`NewRootCmd` undefined).

- [ ] **Step 3: Write `cmd/kdex/cmd/root.go`**

```go
package cmd

import (
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kdex",
		Short: "KDex developer-experience CLI",
		Long: `kdex is the unified CLI for the KDex Function-as-a-Service platform.

It bundles developer-experience tools for the KDex SDLC:
  - kdex preview     — preview the KCNAS runtime locally
  - kdex codegen     — generate function scaffolding from an OpenAPI spec

See https://github.com/kdex-tech/host-manager for documentation.`,
	}
	return root
}
```

- [ ] **Step 4: Run the test to confirm it passes**

```bash
go test ./cmd/kdex/cmd/ -run TestRootCmd_PrintsHelpByDefault -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/kdex/cmd/root.go cmd/kdex/cmd/root_test.go
git commit -m "cmd: add kdex CLI root command (cobra)"
```

---

### Task 1.4: Add `cmd/kdex/cmd/preview.go` stub

**Files:**
- Create: `cmd/kdex/cmd/preview.go`
- Test: `cmd/kdex/cmd/preview_test.go`

- [ ] **Step 1: Write the failing test**

`cmd/kdex/cmd/preview_test.go`:

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
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "preview") {
		t.Errorf("expected root help to list 'preview' command; got: %q", out)
	}
}

func TestPreviewCmd_NotImplementedYet(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.AddCommand(NewPreviewCmd())
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"preview"})

	err := root.Execute()
	if err == nil {
		t.Fatalf("expected 'preview' stub to return an error; got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected 'not yet implemented' error; got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/kdex/cmd/ -run "TestPreviewCmd_" -v
```

Expected: FAIL (`NewPreviewCmd` undefined).

- [ ] **Step 3: Write `cmd/kdex/cmd/preview.go`**

```go
package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func NewPreviewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "preview",
		Short: "Preview the KCNAS runtime locally",
		Long: `Preview renders KDexHost composition (theme + pages + archetypes +
page-headers/footers/navigation) from a directory of CRs on disk and serves
the result on a local HTTP port with hot reload on source changes.

This command is not yet implemented in this build. Implementation is tracked
in docs/superpowers/plans/2026-05-31-kdex-cli-phase-0-1.md and follow-on plans.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("preview: not yet implemented in this build")
		},
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test ./cmd/kdex/cmd/ -run "TestPreviewCmd_" -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/kdex/cmd/preview.go cmd/kdex/cmd/preview_test.go
git commit -m "cmd: add kdex preview stub subcommand"
```

---

### Task 1.5: Add `cmd/kdex/cmd/codegen.go` (parent) and `codegen_go.go` (stub)

**Files:**
- Create: `cmd/kdex/cmd/codegen.go`
- Create: `cmd/kdex/cmd/codegen_go.go`
- Test: `cmd/kdex/cmd/codegen_test.go`

- [ ] **Step 1: Write the failing test**

`cmd/kdex/cmd/codegen_test.go`:

```go
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodegenCmd_ListsAvailableLanguages(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	codegen := NewCodegenCmd()
	codegen.AddCommand(NewCodegenGoCmd())
	root.AddCommand(codegen)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"codegen"})

	_ = root.Execute()

	out := buf.String()
	if !strings.Contains(out, "go") {
		t.Errorf("expected codegen help to list 'go' subcommand; got: %q", out)
	}
}

func TestCodegenGoCmd_NotImplementedYet(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	codegen := NewCodegenCmd()
	codegen.AddCommand(NewCodegenGoCmd())
	root.AddCommand(codegen)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"codegen", "go", "--spec", "x", "--target", "y", "--module", "z"})

	err := root.Execute()
	if err == nil {
		t.Fatalf("expected 'codegen go' stub to return an error; got nil")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected 'not yet implemented' error; got: %v", err)
	}
}

func TestCodegenGoCmd_RequiredFlags(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	codegen := NewCodegenCmd()
	codegen.AddCommand(NewCodegenGoCmd())
	root.AddCommand(codegen)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"codegen", "go"})

	err := root.Execute()
	if err == nil {
		t.Fatalf("expected error when required flags are missing; got nil")
	}
	if !strings.Contains(err.Error(), "spec") && !strings.Contains(err.Error(), "target") && !strings.Contains(err.Error(), "module") {
		t.Errorf("expected error to mention missing required flag; got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./cmd/kdex/cmd/ -run "TestCodegen" -v
```

Expected: FAIL (`NewCodegenCmd`, `NewCodegenGoCmd` undefined).

- [ ] **Step 3: Write `cmd/kdex/cmd/codegen.go`**

```go
package cmd

import (
	"github.com/spf13/cobra"
)

func NewCodegenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "codegen",
		Short: "Generate function scaffolding from an OpenAPI spec",
		Long: `Codegen produces a buildable function project for the target language
from an OpenAPI 3.x specification.

Available languages:
  go    KDex Go function scaffolding

NOT IN SCOPE for this CLI:
  - Generic OpenAPI codegen for arbitrary HTTP servers
  - Non-FaaS deployment targets
  - Customizable templating or plugin systems

See docs/superpowers/specs/2026-05-31-kdex-unified-cli-design.md for the design.`,
	}
}
```

- [ ] **Step 4: Write `cmd/kdex/cmd/codegen_go.go`**

```go
package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func NewCodegenGoCmd() *cobra.Command {
	var (
		spec   string
		target string
		module string
		force  bool
		yes    bool
	)
	cmd := &cobra.Command{
		Use:   "go",
		Short: "Generate KDex Go function scaffolding (EXPERIMENTAL)",
		Long: `Generate a KDex Go function project from an OpenAPI 3.x specification.

After this command returns, 'cd <target> && go build ./...' produces a working
binary with no intermediate steps. The generated project includes:
  - cmd/main.go         (regenerated each run)
  - cmd/default.go      (regenerated)
  - cmd/security.go     (regenerated)
  - cmd/custom.go       (preserved after first emit)
  - api/*.go            (regenerated; produced via ogen)
  - go.mod              (preserved after first emit)
  - project.toml        (regenerated; CNB metadata)

EXPERIMENTAL: not yet implemented in this build.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("codegen go: not yet implemented in this build")
		},
	}
	cmd.Flags().StringVar(&spec, "spec", "", "Path to OpenAPI 3.x JSON or YAML (required)")
	cmd.Flags().StringVar(&target, "target", "", "Output directory (required)")
	cmd.Flags().StringVar(&module, "module", "", "Go module path for the generated project, e.g. kdex.dev/fns/my-fn (required)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite preserved files (requires confirmation unless --yes)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Bypass confirmation prompts")
	_ = cmd.MarkFlagRequired("spec")
	_ = cmd.MarkFlagRequired("target")
	_ = cmd.MarkFlagRequired("module")
	return cmd
}
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
go test ./cmd/kdex/cmd/ -v
```

Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/kdex/cmd/codegen.go cmd/kdex/cmd/codegen_go.go cmd/kdex/cmd/codegen_test.go
git commit -m "cmd: add kdex codegen stub subcommands"
```

---

### Task 1.6: Add `cmd/kdex/main.go` (entry point)

**Files:**
- Create: `cmd/kdex/main.go`

- [ ] **Step 1: Write `cmd/kdex/main.go`**

```go
package main

import (
	"fmt"
	"os"

	"github.com/kdex-tech/host-manager/cmd/kdex/cmd"
)

func main() {
	root := cmd.NewRootCmd()
	root.AddCommand(cmd.NewPreviewCmd())
	codegen := cmd.NewCodegenCmd()
	codegen.AddCommand(cmd.NewCodegenGoCmd())
	root.AddCommand(codegen)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Verify it builds**

```bash
go build -o /tmp/kdex ./cmd/kdex
```

Expected: exit 0; `/tmp/kdex` exists.

- [ ] **Step 3: Smoke-test the CLI**

```bash
/tmp/kdex --help
```

Expected: prints help with `preview` and `codegen` subcommands.

```bash
/tmp/kdex preview
```

Expected: prints `preview: not yet implemented in this build` and exits non-zero.

```bash
/tmp/kdex codegen go --spec x --target y --module z
```

Expected: prints `codegen go: not yet implemented in this build` and exits non-zero.

```bash
/tmp/kdex codegen go
```

Expected: error mentioning required flags.

- [ ] **Step 4: Commit**

```bash
git add cmd/kdex/main.go
git commit -m "cmd: add kdex CLI entry point"
```

---

### Task 1.7: Update Makefile to build both binaries

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Read the current `build:` recipe**

Open `Makefile` and locate the `build:` target. Note the existing dependencies (`manifests generate fmt vet`) and the build command.

- [ ] **Step 2: Rewrite `build:` target and add `build-kdex:`**

Replace the existing `build:` block with:

```makefile
.PHONY: build
build: build-host-manager build-kdex ## Build both binaries.

.PHONY: build-host-manager
build-host-manager: manifests generate fmt vet ## Build host-manager binary.
	go build -o bin/host-manager ./cmd/host-manager

.PHONY: build-kdex
build-kdex: fmt vet ## Build kdex CLI binary.
	go build -o bin/kdex ./cmd/kdex
```

Notes:
- `build-host-manager` keeps the operator's full pipeline (manifests + generate).
- `build-kdex` skips manifests/generate (the CLI doesn't depend on CRD codegen output) but keeps `fmt vet` for sanity.
- The legacy `bin/manager` path is replaced by `bin/host-manager`. If any other Makefile target references `bin/manager`, update those too (search via `grep -n 'bin/manager' Makefile`).

- [ ] **Step 3: Verify both binaries build**

```bash
make build-host-manager build-kdex
```

Expected: `bin/host-manager` and `bin/kdex` both exist; exit 0.

- [ ] **Step 4: Verify tests still pass**

```bash
make test
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add Makefile
git commit -m "make: add build-host-manager and build-kdex targets"
```

---

### Task 1.8: Update Dockerfile to use the renamed cmd path

This may already have been done in Task 1.1's Step 2; if so, this task is a no-op. Otherwise, verify and finalize.

**Files:**
- Modify: `Dockerfile` (only if not already updated)

- [ ] **Step 1: Verify Dockerfile is correct**

```bash
grep -n "cmd/main.go\|cmd/host-manager" Dockerfile
```

Expected: only references to `cmd/host-manager/main.go` (in COPY) and `./cmd/host-manager` (in go build).

If any `cmd/main.go` references remain, fix them now and commit.

- [ ] **Step 2: Verify the image builds**

```bash
make docker-build TAG=phase1-verify
```

Expected: docker image built successfully. If docker isn't available locally, mark as skipped + run later.

- [ ] **Step 3: If changes were needed, commit**

```bash
git add Dockerfile
git commit -m "docker: use cmd/host-manager path"
```

If no changes were needed in this task, skip the commit.

---

### Task 1.9: Verify the full restructure

**Files:** (none; verification only)

- [ ] **Step 1: Run the full lint + test sweep**

```bash
make lint
make test
```

Expected: both pass.

- [ ] **Step 2: Verify both binaries exist and run**

```bash
ls -la bin/host-manager bin/kdex
./bin/kdex --help
./bin/kdex preview 2>&1 | head -3
./bin/kdex codegen go --spec x --target y --module z 2>&1 | head -3
```

Expected: both binaries present; help output looks right; both stubs print the experimental "not yet implemented" message.

- [ ] **Step 3: Verify chart consumer compatibility**

The chart in `chart/` references `image.repository=kdex-tech/host-manager` and the binary entrypoint at `/manager`. The Dockerfile builds to `/manager` (Task 1.1 should have preserved that). Sanity-check:

```bash
grep -n "^ENTRYPOINT\|^COPY --from=builder /workspace" Dockerfile
```

Expected: ENTRYPOINT is `["/manager"]`; the COPY for `manager` is from `/workspace/manager`.

If the rename broke chart compatibility, fix and commit. Otherwise no commit.

- [ ] **Step 4: If everything passes, no commit needed for this verification task**

This task is the dry-run gate before considering Phase 1 complete. If anything failed, file a fix-up commit; otherwise advance to the conclusion.

---

## Conclusion

After Task 1.9 passes:

- Two binaries (`host-manager`, `kdex`) build from one repo.
- `kdex` CLI dispatches help and stub subcommands.
- Host-manager operator behavior is unchanged (same Dockerfile output, same chart consumption, same tests).
- Two hack/ directories document spike outcomes and any follow-up decisions (envtest? bundled ogen?).
- The repo is ready for Plan B (preview MVP → hot reload → kustomize → distribution).

Open the next plan: `docs/superpowers/plans/<next-date>-kdex-cli-phase-2-5.md`, referencing this plan's conclusion as its starting point.

## Out-of-band notes

- **Spike artifacts under `hack/`**: per design-doc §11 phase 0, spikes are throwaway. We keep the directories committed for historical evidence but they're free to delete in a later cleanup commit. They do not import from production packages other than for the purpose of validating compatibility.
- **CI updates intentionally deferred to Plan B (phase 5).** Plan A maintains existing CI semantics: `make docker-build TAG=ci` still produces only the `host-manager` image; the `kdex` image is introduced when distribution lands.
- **No changes to `chart/`** in Plan A. The helm chart consumes the host-manager image, which is unchanged in shape and name.

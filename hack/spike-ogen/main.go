// Spike: validate that ogen exposes a programmatic Generator that produces
// buildable Go from an OpenAPI spec, without requiring a separate ogen binary
// on PATH or a `go generate` step.
//
// Run:  go run ./hack/spike-ogen
// Expected:  "spike-ogen OK: api package built" and exit 0.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ogen-go/ogen"
	"github.com/ogen-go/ogen/gen"
	"github.com/ogen-go/ogen/gen/genfs"
)

func main() {
	specPath := "hack/spike-ogen/testdata/openapi.json"
	outDir := "/tmp/kdex-spike-ogen-out"
	apiDir := filepath.Join(outDir, "api")

	if err := os.RemoveAll(outDir); err != nil {
		die("clean outdir: %v", err)
	}
	if err := os.MkdirAll(apiDir, 0o755); err != nil {
		die("mkdir: %v", err)
	}

	data, err := os.ReadFile(specPath)
	if err != nil {
		die("read spec: %v", err)
	}

	spec, err := ogen.Parse(data)
	if err != nil {
		die("ogen.Parse: %v", err)
	}

	g, err := gen.NewGenerator(spec, gen.Options{})
	if err != nil {
		die("gen.NewGenerator: %v", err)
	}

	// genfs.FormattedSource is the gen.FileSystem implementation ogen's own
	// CLI uses (cmd/ogen/main.go). gen.FileSystem only requires:
	//
	//   WriteFile(baseName string, source []byte) error
	//
	// FormattedSource additionally runs goimports on the written file when
	// Format is true; we leave it false because g.WriteSource already
	// formats via go/format internally.
	fs := genfs.FormattedSource{
		Format: false,
		Root:   apiDir,
	}

	// Signature: (*Generator).WriteSource(fs FileSystem, pkgName string) error
	if err := g.WriteSource(fs, "api"); err != nil {
		die("g.WriteSource: %v", err)
	}

	if err := writeGoMod(outDir); err != nil {
		die("write go.mod: %v", err)
	}

	// Force module resolution to pull in the ogen runtime deps (go-faster/*,
	// otel/*, etc.) the generated code imports. The spike's CTA is that this
	// "go mod tidy" + "go build" succeeds with zero hand-written shims.
	for _, args := range [][]string{
		{"mod", "tidy"},
		{"build", "./..."},
	} {
		cmd := exec.Command("go", args...)
		cmd.Dir = outDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			die("go %v: %v", args, err)
		}
	}

	fmt.Println("spike-ogen OK: api package built")
}

func writeGoMod(dir string) error {
	mod := `module spikegen

go 1.26
`
	return os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o644)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

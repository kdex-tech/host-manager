# spike-ogen — validate ogen library API for `kdex codegen go`

## Goal

Confirm that [ogen-go/ogen](https://github.com/ogen-go/ogen) exposes a
**programmatic Generator** so the unified `kdex codegen go` subcommand can
generate an OpenAPI client+server package by calling Go library functions
directly — no `go generate` directive, no `ogen` binary on PATH, no
`os/exec` shell-out to the ogen CLI.

Phase-0 task (b) of the kdex unified CLI design
(`docs/superpowers/specs/2026-05-31-kdex-unified-cli-design.md`, §5, §11).

## Result

**PROCEED.** ogen v1.20.3 exposes a clean, stable library surface that
end-to-end generates buildable Go from an OpenAPI 3.0 spec in-process.

```
$ go run ./hack/spike-ogen
... go mod tidy resolves ogen runtime deps ...
spike-ogen OK: api package built
```

Generated package: `/tmp/kdex-spike-ogen-out/api/` — 15 `oas_*_gen.go`
files (client, server, schemas, JSON encoders, router, middleware,
labeler, cfg, request/response codecs, unimplemented stub, handlers,
operations).

## ogen library API surface used

ogen module version: `github.com/ogen-go/ogen v1.20.3`

### Parse the spec

```go
import "github.com/ogen-go/ogen"

// func ogen.Parse(data []byte) (*ogen.Spec, error)
spec, err := ogen.Parse(data)
```

Accepts JSON or YAML. Returns the populated `*ogen.Spec` struct (the
in-memory OpenAPI 3.x document model). No filename/URL convenience —
callers do their own I/O.

### Build the generator

```go
import "github.com/ogen-go/ogen/gen"

// func gen.NewGenerator(spec *ogen.Spec, opts gen.Options) (*gen.Generator, error)
g, err := gen.NewGenerator(spec, gen.Options{})
```

`gen.Options` has four fields (all optional):

```go
type Options struct {
    Parser     ParseOptions       // schema-parsing knobs
    Generator  GenerateOptions    // code-emission knobs (features, filters, content-type aliases…)
    ExpandSpec string             // optional path to write the resolved/expanded spec
    Logger     *zap.Logger        // optional logger; nil → no-op
}
```

For the spike we passed the zero value and got sensible defaults
(`gen.DefaultFeatures` enables client+server+webhooks+etc.).

### Emit source

```go
// func (*gen.Generator).WriteSource(fs gen.FileSystem, pkgName string) error
err := g.WriteSource(fs, "api")
```

The `pkgName` argument is the **Go package name** stamped into every
generated file. (The scaffold guessed this was an `Options.Package`
field — it is not; it is a runtime argument to `WriteSource`.)

### FileSystem interface

```go
// gen.FileSystem is the writer ABI WriteSource targets.
type FileSystem interface {
    WriteFile(baseName string, source []byte) error
}
```

A single method. Caller controls where files land; ogen just hands over
`(name, bytes)` pairs.

ogen ships a ready-made implementation at
`github.com/ogen-go/ogen/gen/genfs`:

```go
type FormattedSource struct {
    Format bool   // run goimports on each file (we use false; WriteSource already gofmt's)
    Root   string // target directory
}
func (FormattedSource) WriteFile(name string, content []byte) error
```

We adopted `genfs.FormattedSource` rather than rolling our own — same
implementation ogen's own CLI uses
(`github.com/ogen-go/ogen/cmd/ogen/main.go`, ~line 92).

## Runtime deps the generated code requires

`go mod tidy` inside the output dir resolved this exact set
(`/tmp/kdex-spike-ogen-out/go.mod`):

**Direct (generated code imports these by name):**

| Module | Version |
| --- | --- |
| `github.com/go-faster/errors` | v0.7.1 |
| `github.com/go-faster/jx` | v1.2.0 |
| `github.com/ogen-go/ogen` | v1.20.3 |
| `go.opentelemetry.io/otel` | v1.44.0 |
| `go.opentelemetry.io/otel/metric` | v1.44.0 |
| `go.opentelemetry.io/otel/trace` | v1.44.0 |

(OTel is pulled in because the generated server wires labeler + metrics
hooks even when no telemetry handler is registered.)

**Indirect (transitive through ogen):** `go-faster/yaml`, `ghodss/yaml`,
`shopspring/decimal`, `dlclark/regexp2`, `segmentio/asm`,
`go.uber.org/zap`, `go.opentelemetry.io/auto/sdk`, plus
`golang.org/x/{exp,net,sync,sys,text}`.

**Implication for `kdex codegen go`:** the synthesized function project's
`go.mod` must declare (or `go mod tidy` after generation will add) the
six direct deps above. The CLI can ship a hardcoded `require (...)` stub
in the project template, then run `go mod tidy` once after generation to
collapse any version skew. The set is small and stable — no surprise
deps showed up.

## Caveats / notes for the production CLI

1. **`pkgName` is positional, not in `Options`.** The scaffold guessed
   `gen.Options{Package: "api"}`; the real API takes the package name as
   the second argument to `WriteSource`. The CLI must thread the
   `--package` flag value to `WriteSource`, not to `Options`.

2. **No top-level "generate everything" convenience.** The library
   gives you `Parse` + `NewGenerator` + `WriteSource` — three calls, in
   order. There is no `gen.Run(opts)` aggregate. That is fine; we want
   the granularity for error reporting in the CLI anyway.

3. **`Options.Logger` is `*zap.Logger`.** Passing `nil` works (the
   generator no-ops on the nil logger), but if we want to surface ogen
   warnings (e.g. `ErrNotImplemented`) under the CLI's normal logger we
   will need a small zap shim. Out of scope for the spike.

4. **ogen formats with `go/format` internally**, so
   `genfs.FormattedSource{Format: false, …}` is the right choice —
   setting `Format: true` would invoke `goimports` a second time on
   already-formatted source, slowing generation for no benefit.

5. **Generator default features.** `gen.DefaultFeatures` enables
   client, server, webhooks, and most common content-type encodings.
   `gen.AllFeatures` adds opt-in experimental ones. For `kdex codegen
   go` the defaults are correct; if a function project ever needs to
   trim features we expose `Options.Generator.Features`.

6. **No filesystem cleaning is done by ogen.** The CLI is responsible
   for deleting any stale `oas_*_gen.go` files before re-running, or
   they will be left behind on schema shrinkage. ogen's own CLI does
   this with a `cleanDir` helper around `os.ReadDir`; we should do the
   same in `kdex codegen go` (glob `oas_*_gen.go`).

## Files

- `main.go` — the spike driver. ~80 lines, no external deps beyond ogen.
- `testdata/openapi.json` — minimal OpenAPI 3.0.3 fixture (`GET /echo`
  returning `{ msg: string }`).
- `README.md` — this file.

## How to re-run

```sh
go run ./hack/spike-ogen
ls /tmp/kdex-spike-ogen-out/api/
```

The output dir is unconditionally wiped at the start of each run.

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

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

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

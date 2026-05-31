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

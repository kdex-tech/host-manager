package main

import (
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
		os.Exit(1)
	}
}

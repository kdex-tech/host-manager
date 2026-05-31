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

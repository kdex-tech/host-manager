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

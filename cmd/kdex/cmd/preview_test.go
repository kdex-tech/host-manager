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
	root.SetArgs([]string{"preview", "--help"})

	_ = root.Execute()

	out := buf.String()
	for _, want := range []string{"--crs", "--fn", "--theme", "--app", "--missing-app", "--missing-fn"} {
		if !strings.Contains(out, want) {
			t.Errorf("preview --help should mention %q; got: %q", want, out)
		}
	}
}

func TestPreviewCmd_RequiresCrsFlag(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.AddCommand(NewPreviewCmd())
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"preview"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --crs missing; got nil")
	}
	if !strings.Contains(err.Error(), "crs") {
		t.Errorf("error should mention --crs; got: %v", err)
	}
}

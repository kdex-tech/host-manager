package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCmd_PrintsHelpByDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	root := NewRootCmd()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{})

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "kdex") {
		t.Errorf("expected help output to contain 'kdex'; got: %q", out)
	}
	if !strings.Contains(out, "developer-experience tools") {
		t.Errorf("expected help output to describe the CLI; got: %q", out)
	}
}

/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package chart_test renders the host-manager Helm chart and asserts on the
// produced manifests. It shells out to the repo-local helm binary (bin/helm)
// and stubs the valkey dependency subchart so rendering is hermetic (no
// network fetch of the real subchart required).
package chart_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the test working directory until it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod)")
		}
		dir = parent
	}
}

// renderChart copies the chart into a temp dir, stubs the valkey dependency so
// the parent renders without a network fetch, runs `helm template` with the
// given --set overrides, and returns the rendered YAML.
func renderChart(t *testing.T, sets ...string) string {
	t.Helper()
	root := repoRoot(t)
	helmBin := filepath.Join(root, "bin", "helm")
	if _, err := os.Stat(helmBin); err != nil {
		t.Skipf("helm binary not found at %s (run `make helm`): %v", helmBin, err)
	}

	tmp := t.TempDir()
	dst := filepath.Join(tmp, "chart")
	if out, err := exec.Command("cp", "-r", filepath.Join(root, "chart"), dst).CombinedOutput(); err != nil {
		t.Fatalf("copy chart: %v\n%s", err, out)
	}

	// Stub the valkey dependency: helm template requires the dependency to be
	// present in charts/, but the wait-on-valkey init container under test
	// lives in the PARENT chart, gated on .Values.valkey.enabled. A Chart.yaml
	// alone is a valid (empty) chart and satisfies the presence check.
	stub := filepath.Join(dst, "charts", "valkey")
	if err := os.MkdirAll(stub, 0o755); err != nil {
		t.Fatal(err)
	}
	stubChart := "apiVersion: v2\nname: valkey\nversion: 0.9.3\n"
	if err := os.WriteFile(filepath.Join(stub, "Chart.yaml"), []byte(stubChart), 0o644); err != nil {
		t.Fatal(err)
	}
	// Drop the lock so helm doesn't try to reconcile the stub against the
	// pinned digest.
	_ = os.Remove(filepath.Join(dst, "Chart.lock"))

	args := []string{"template", "t", dst}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	cmd := exec.Command(helmBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
}

// waitOnValkeyImage extracts the image of the wait-on-valkey init container
// from rendered chart YAML.
func waitOnValkeyImage(t *testing.T, manifests string) string {
	t.Helper()
	lines := strings.Split(manifests, "\n")
	for i, line := range lines {
		if strings.Contains(line, "name: wait-on-valkey") {
			// Scan a small window around the container entry for its image.
			lo := i - 8
			if lo < 0 {
				lo = 0
			}
			hi := i + 8
			if hi > len(lines) {
				hi = len(lines)
			}
			for _, l := range lines[lo:hi] {
				l = strings.TrimSpace(l)
				if strings.HasPrefix(l, "image:") {
					return strings.TrimSpace(strings.TrimPrefix(l, "image:"))
				}
			}
		}
	}
	t.Fatalf("wait-on-valkey init container image not found in rendered manifests:\n%s", manifests)
	return ""
}

// TestWaitOnValkeyImage_DefaultIsMultiArch pins #107/#108: the default
// wait-on-valkey init image must NOT be the amd64-broken cli-tools:0.3.9, and
// must come from a configurable value.
func TestWaitOnValkeyImage_DefaultIsMultiArch(t *testing.T) {
	img := waitOnValkeyImage(t, renderChart(t))

	if strings.Contains(img, "cli-tools:0.3.9") {
		t.Fatalf("default wait-on-valkey image is the arm64-broken cli-tools:0.3.9 (#107); got %q", img)
	}
	if want := "ghcr.io/kdex-tech/cli-tools:0.3.18"; img != want {
		t.Fatalf("default wait-on-valkey image = %q, want %q", img, want)
	}
}

// TestWaitOnValkeyImage_Overridable pins #108: operators must be able to point
// the init container at a known-good image via a chart value.
func TestWaitOnValkeyImage_Overridable(t *testing.T) {
	const custom = "ghcr.io/kdex-tech/cli-tools:0.3.99"
	img := waitOnValkeyImage(t, renderChart(t, "valkey.waitImage="+custom))
	if img != custom {
		t.Fatalf("overridden wait-on-valkey image = %q, want %q", img, custom)
	}
}

// TestServerTimeoutArgs pins that chart server.* values reach the binary's
// --server-* flags (kdex-tech/host-manager#167). The zero case matters most:
// an operator disabling the write deadline must produce an explicit
// `--server-write-timeout=0`, not an omitted flag that silently restores the
// 60s default.
func TestServerTimeoutArgs(t *testing.T) {
	manifests := renderChart(t,
		"server.readHeaderTimeout=5s",
		"server.readTimeout=30s",
		"server.writeTimeout=0",
		"server.idleTimeout=45s",
		"server.streamStallTimeout=0",
	)

	for _, want := range []string{
		"--server-read-header-timeout=5s",
		"--server-read-timeout=30s",
		"--server-write-timeout=0",
		"--server-idle-timeout=45s",
		// Quad-findings item 1: streamStallTimeout follows the same
		// no-per-field-`with`-guard pattern as its four siblings, so an
		// operator disabling the SSE stall window gets an explicit 0
		// rather than a dropped flag silently restoring the 5m default.
		"--server-stream-stall-timeout=0",
	} {
		if !strings.Contains(manifests, want) {
			t.Errorf("rendered manifests missing %q:\n%s", want, manifests)
		}
	}
}

// TestServerTimeoutArgs_Defaults pins that the shipped defaults render.
func TestServerTimeoutArgs_Defaults(t *testing.T) {
	manifests := renderChart(t)

	for _, want := range []string{
		"--server-read-header-timeout=10s",
		"--server-read-timeout=60s",
		"--server-write-timeout=60s",
		"--server-idle-timeout=120s",
		"--server-stream-stall-timeout=5m",
	} {
		if !strings.Contains(manifests, want) {
			t.Errorf("rendered manifests missing default %q:\n%s", want, manifests)
		}
	}
}

// TestRefreshGraceWindowArg pins that the chart value reaches the flag,
// including 0 (kdex-tech/host-manager#169).
func TestRefreshGraceWindowArg(t *testing.T) {
	if got := renderChart(t); !strings.Contains(got, "--refresh-grace-window=10s") {
		t.Errorf("default refresh grace window not rendered:\n%s", got)
	}
	if got := renderChart(t, "auth.refreshGraceWindow=0"); !strings.Contains(got, "--refresh-grace-window=0") {
		t.Errorf("refreshGraceWindow=0 must render explicitly, not be dropped:\n%s", got)
	}
}

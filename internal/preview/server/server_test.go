package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
)

// TestRun_ServesBasicPage boots Run with the testdata/basic fixture set and
// verifies that GET / returns 200 + HTML. The fixture is intentionally minimal:
// one InternalHost, one KDexTheme, one KDexPage. No functions — the
// function-proxy mux isn't exercised here (that's Task 2.10's e2e test).
func TestRun_ServesBasicPage(t *testing.T) {
	if testing.Short() {
		t.Skip("server test boots a real listener")
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{CRsDir: "testdata/basic", Addr: addr})
	}()
	waitForServer(t, "http://"+addr+"/")

	resp, err := http.Get("http://" + addr + "/") //nolint:noctx // smoke test, deliberate
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) {
		t.Errorf("expected HTML; got: %s", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			t.Errorf("Run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestPreview_RendersPageAndProxiesFunction boots Run with the basic fixture
// set + a dir-form function override pointing at testdata/sample-fn-go, then
// verifies that:
//  1. GET / returns HTML from host-manager's page renderer.
//  2. GET /api/echo/echo is reverse-proxied to the supervised Go process and
//     returns "ECHO /echo" (the function's /echo handler echoes its path).
//
// Path-strip math: basePath=/api/echo, request=/api/echo/echo →
// strip prefix → /echo → hits the supervised process's /echo handler.
func TestPreview_RendersPageAndProxiesFunction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real server + go run child")
	}
	crsDir := "testdata/basic"
	fnDir, _ := filepath.Abs("testdata/sample-fn-go")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	addr := freeAddr(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{
			CRsDir: crsDir,
			Addr:   addr,
			FnOverrides: []resolver.FnOverride{
				{Name: "echo", Kind: resolver.FnOverrideDir, Dir: fnDir, Lang: resolver.FnLangGo},
			},
			FnStartupTimeout: 60 * time.Second,
		})
	}()

	waitForServer(t, "http://"+addr+"/")

	// Hit the page
	resp, err := http.Get("http://" + addr + "/") //nolint:noctx // integration test, deliberate
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) {
		t.Errorf("expected HTML response; got: %s", body)
	}

	// Hit the proxied function — /api/echo/echo strips /api/echo → /echo on
	// the supervised process, which returns "ECHO /echo".
	resp, err = http.Get("http://" + addr + "/api/echo/echo") //nolint:noctx // integration test, deliberate
	if err != nil {
		t.Fatalf("GET /api/echo/echo: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !bytes.Equal(body, []byte("ECHO /echo")) {
		t.Errorf("expected exact body %q (verifies basePath strip); got: %s", "ECHO /echo", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
			t.Errorf("Run returned: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestPreview_StubRoutes_Return501 boots Run against testdata/basic (no
// function overrides) and verifies that the out-of-scope /-/ routes return
// 501 Not Implemented rather than host-manager's default 404.
func TestPreview_StubRoutes_Return501(t *testing.T) {
	if testing.Short() {
		t.Skip("server test boots a real listener")
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{CRsDir: "testdata/basic", Addr: addr})
	}()
	waitForServer(t, "http://"+addr+"/")

	for _, route := range []string{"/-/login", "/-/logout", "/-/feedback", "/-/apitoken"} {
		resp, err := http.Get("http://" + addr + route) //nolint:noctx // smoke test, deliberate
		if err != nil {
			t.Errorf("GET %s: %v", route, err)
			continue
		}
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("GET %s: got status %d, want 501", route, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
	}
}

// TestPreview_LoadsRealClusterCRShape is the Phase 2.5 gate test. It boots
// preview against a CR set written in the user-facing form (KDexHost,
// KDexTranslation, KDexUtilityPage, KDexClusterPageArchetype,
// KDexClusterPageHeader, KDexClusterPageFooter) — the shape people actually
// author — and verifies that loader projection + fakeclient seeding +
// host-manager's page reconciler all compose to render a page.
//
// The fixture set at testdata/knowdrive-mini/ is a minimized model of the
// user's real dev cluster CRs at /home/rotty/projects/RSI/knowdrive-site/k8s/
// dev/. It exercises the user-facing-CR-only intake path Phase 2.5 added.
func TestPreview_LoadsRealClusterCRShape(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real server")
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{CRsDir: "testdata/knowdrive-mini", Addr: addr})
	}()
	waitForServer(t, "http://"+addr+"/")

	resp, err := http.Get("http://" + addr + "/") //nolint:noctx // smoke test, deliberate
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("<html")) && !bytes.Contains(body, []byte("<!doctype")) {
		t.Errorf("expected HTML; got: %s", body)
	}

	cancel()
	select {
	case <-errCh:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// freeAddr allocates a free TCP address on 127.0.0.1 for the test server.
// Closes the listener immediately; small race between close and re-bind is
// acceptable for a one-shot test.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// waitForServer polls until the server responds (any HTTP status), the timeout
// fires, or the test deadline is hit. Failure is fatal — without this guard the
// subsequent GET races the server boot.
func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		client := http.Client{Timeout: 200 * time.Millisecond}
		if resp, err := client.Get(url); err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start", url)
}

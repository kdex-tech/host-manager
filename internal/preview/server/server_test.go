package server

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
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

package supervisor

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
)

func TestSpawn_GoFunction_BindsPortAndServes(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, err := filepath.Abs("testdata/echo-fn")
	if err != nil {
		t.Fatal(err)
	}
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	defer sup.Shutdown(5 * time.Second)

	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	resp, err := http.Get(url + "/echo")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); !strings.HasPrefix(got, "ECHO ") {
		t.Errorf("body: got %q, want prefix ECHO", got)
	}
}

func TestSpawn_GoFunction_OmitsAuthEnvVars(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, _ := filepath.Abs("testdata/echo-fn")
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	defer sup.Shutdown(5 * time.Second)

	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	resp, err := http.Get(url + "/env")
	if err != nil {
		t.Fatalf("GET /env: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, `AUDIENCE=""`) || !strings.Contains(got, `JWKS_URL=""`) || !strings.Contains(got, `PKS_URL=""`) {
		t.Errorf("auth env vars leaked into child env: %s", got)
	}
}

func TestShutdown_TerminatesChild(t *testing.T) {
	if testing.Short() {
		t.Skip("go run is slow")
	}
	abs, _ := filepath.Abs("testdata/echo-fn")
	ov := resolver.FnOverride{Name: "echo", Kind: resolver.FnOverrideDir, Dir: abs, Lang: resolver.FnLangGo}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sup := New(Options{StartupTimeout: 30 * time.Second})
	defer sup.Shutdown(5 * time.Second) // cleanup even if the test panics; Shutdown is idempotent
	url, err := sup.Spawn(ctx, ov)
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	if err := sup.Shutdown(5 * time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// After shutdown, the URL should refuse connections.
	client := http.Client{Timeout: 1 * time.Second}
	if _, err := client.Get(url + "/echo"); err == nil {
		t.Errorf("child still serving after Shutdown")
	}
}

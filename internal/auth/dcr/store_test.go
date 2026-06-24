package dcr

import (
	"context"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

func newMemStore(t *testing.T, max int32) *Store {
	t.Helper()
	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "testhost", &ttl)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	return NewStore(cm, "testhost", time.Hour, max)
}

func TestRegisterAndGet(t *testing.T) {
	s := newMemStore(t, 10)
	ctx := context.Background()
	c, err := s.Register(ctx, Client{
		RedirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.ClientID == "" {
		t.Fatal("expected assigned client_id")
	}
	got, ok, err := s.Get(ctx, c.ClientID)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.RedirectURIs[0] != "https://claude.ai/api/mcp/auth_callback" {
		t.Fatalf("redirect = %v", got.RedirectURIs)
	}
}

func TestRegisterDefaultsAuthMethod(t *testing.T) {
	s := newMemStore(t, 10)
	ctx := context.Background()
	c, err := s.Register(ctx, Client{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c.TokenEndpointAuthMethod != "none" {
		t.Fatalf("Register returned TokenEndpointAuthMethod=%q, want %q", c.TokenEndpointAuthMethod, "none")
	}
	got, ok, err := s.Get(ctx, c.ClientID)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.TokenEndpointAuthMethod != "none" {
		t.Fatalf("Get returned TokenEndpointAuthMethod=%q, want %q", got.TokenEndpointAuthMethod, "none")
	}
}

func TestGetMissing(t *testing.T) {
	s := newMemStore(t, 10)
	_, ok, err := s.Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("expected not found")
	}
}

// TestRegisteredClientSurvivesCacheCycle pins kdex-tech/host-manager#122: a
// DCR client registration is session-grade state that refresh tokens are bound
// to, so it must survive a cache cycle (a routine host config reconcile) the
// same way refresh-tokens/auth-codes do. The "dcr" cache must therefore be
// registered Uncycled. Pre-fix, the cycle rotates the cache to a fresh
// generation and the registration is orphaned, so the token endpoint returns
// "Invalid client_id" on an otherwise-valid refresh.
func TestRegisteredClientSurvivesCacheCycle(t *testing.T) {
	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "testhost", &ttl)
	if err != nil {
		t.Fatalf("cache: %v", err)
	}
	s := NewStore(cm, "testhost", time.Hour, 10)
	ctx := context.Background()

	c, err := s.Register(ctx, Client{
		RedirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Routine host config reconciles rotate the cache checksum. The
	// in-memory cache keeps a two-generation grace window (current +
	// previous), so it takes a second cycle to evict the original
	// generation — whereas production Valkey orphans on the FIRST cycle
	// (the {host:class:checksum} key prefix rotates, no grace). An Uncycled
	// cache survives any number of cycles because its generation never
	// rotates; that is exactly the property #122 requires for "dcr".
	if err := cm.Cycle("reconcile-1", false); err != nil {
		t.Fatalf("Cycle 1: %v", err)
	}
	if err := cm.Cycle("reconcile-2", false); err != nil {
		t.Fatalf("Cycle 2: %v", err)
	}

	got, ok, err := s.Get(ctx, c.ClientID)
	if err != nil {
		t.Fatalf("Get after cycle: err=%v", err)
	}
	if !ok {
		t.Fatal("registered DCR client orphaned by cache cycle; the \"dcr\" cache must be Uncycled (#122)")
	}
	if got.ClientID != c.ClientID {
		t.Fatalf("Get after cycle returned ClientID=%q, want %q", got.ClientID, c.ClientID)
	}
}

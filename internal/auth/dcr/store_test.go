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

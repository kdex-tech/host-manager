package auth

import (
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// newTestConfigBuilder returns a ConfigBuilder wired with an ECDSA key generator
// and no-op loaders for the other optional dependencies, suitable for DCR tests.
func newTestConfigBuilder(t *testing.T) *ConfigBuilder {
	t.Helper()
	cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))
	return NewConfigBuilder().
		WithKeyLoader(func() (*keys.KeyPairs, error) {
			return keys.GenerateECDSAKeyPair(), nil
		}).
		WithAuthClientLoader(func() (map[string]AuthClient, error) {
			return map[string]AuthClient{}, nil
		}).
		WithOIDCClientConfigLoader(func() (*OIDCClientConfig, error) {
			return nil, nil
		}).
		WithAudience("audience").
		WithIssuer("issuer").
		WithDevMode(true).
		WithCacheManager(cacheManager)
}

func TestBuildPopulatesDCRConfig(t *testing.T) {
	cb := newTestConfigBuilder(t)
	auth := &kdexv1alpha1.Auth{
		DynamicClientRegistration: &kdexv1alpha1.DynamicClientRegistration{
			Enabled:                true,
			ClientTTL:              "720h",
			MaxClients:             500,
			AllowedRedirectSchemes: []string{"https", "http-loopback"},
		},
	}
	cfg, err := cb.Build(auth)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !cfg.DCR.Enabled {
		t.Fatal("expected DCR.Enabled true")
	}
	if cfg.DCR.ClientTTL != 720*time.Hour {
		t.Fatalf("ClientTTL = %v, want 720h", cfg.DCR.ClientTTL)
	}
	if cfg.DCR.MaxClients != 500 {
		t.Fatalf("MaxClients = %d, want 500", cfg.DCR.MaxClients)
	}
}

func TestBuildDCRDisabledWhenNil(t *testing.T) {
	cb := newTestConfigBuilder(t)
	cfg, err := cb.Build(&kdexv1alpha1.Auth{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cfg.DCR.Enabled {
		t.Fatal("expected DCR disabled when field omitted")
	}
}

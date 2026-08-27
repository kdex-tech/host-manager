package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// newOIDCConfigBuilder returns a ConfigBuilder that will take the OIDC branch of
// Build — i.e. its OIDCClientConfigLoader returns a usable client config rather
// than the nil the DCR helper uses.
func newOIDCConfigBuilder(t *testing.T, issuer string) *ConfigBuilder {
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
			return &OIDCClientConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				BlockKey:     "block-key",
			}, nil
		}).
		// Audience is set independently of issuer: Build guards a missing
		// audience earlier than a missing issuer, and the empty-issuer test
		// below needs the issuer guard to be the one that fires.
		WithAudience("https://audience.example.com").
		WithIssuer(issuer).
		WithDevMode(true).
		WithCacheManager(cacheManager)
}

func oidcAuth() *kdexv1alpha1.Auth {
	return &kdexv1alpha1.Auth{
		OIDCProvider: &kdexv1alpha1.OIDCProvider{
			OIDCProviderURL: "https://accounts.example.com",
		},
	}
}

// The redirect_uri sent to an OIDC provider must be an absolute URI: RFC 6749
// §3.1.2 requires it, and OIDC Core §3.1.2.1 requires it to match a
// pre-registered value exactly — which a bare path can never do. Providers that
// validate strictly (Google among them) reject the authorization request
// outright, so the failure lands on the very first hop of the login flow.
//
// See kdex-tech/host-manager#188, where this shipped as "/-/oauth/callback".
func TestBuildDerivesAbsoluteOIDCRedirectURL(t *testing.T) {
	const issuer = "https://public.knowdrive.ai"

	cfg, err := newOIDCConfigBuilder(t, issuer).Build(oidcAuth())
	if err != nil {
		t.Fatalf("Build() returned an unexpected error: %v", err)
	}

	want := issuer + OAuthCallbackPath
	if cfg.OIDC.RedirectURL != want {
		t.Errorf("cfg.OIDC.RedirectURL = %q, want %q", cfg.OIDC.RedirectURL, want)
	}

	// Guard the property rather than only the literal: a future refactor that
	// reintroduces a relative value would still satisfy a naive suffix check.
	if !strings.HasPrefix(cfg.OIDC.RedirectURL, "https://") {
		t.Errorf("cfg.OIDC.RedirectURL = %q, want an absolute https URL", cfg.OIDC.RedirectURL)
	}
}

// A trailing slash on the issuer must not produce a doubled separator: the
// provider compares redirect_uri byte-for-byte against what was registered, so
// "https://host//-/oauth/callback" is a different URI and fails the match.
func TestBuildTrimsTrailingSlashFromIssuerForRedirectURL(t *testing.T) {
	cfg, err := newOIDCConfigBuilder(t, "https://public.knowdrive.ai/").Build(oidcAuth())
	if err != nil {
		t.Fatalf("Build() returned an unexpected error: %v", err)
	}

	want := "https://public.knowdrive.ai" + OAuthCallbackPath
	if cfg.OIDC.RedirectURL != want {
		t.Errorf("cfg.OIDC.RedirectURL = %q, want %q", cfg.OIDC.RedirectURL, want)
	}
}

// With no issuer there is nothing to build an absolute redirect_uri from. Fail
// at Build rather than emitting a relative one: the relative value is accepted
// everywhere locally and only rejected by the provider, mid-login, which is the
// most expensive place to discover it.
func TestBuildRejectsOIDCWithoutIssuer(t *testing.T) {
	_, err := newOIDCConfigBuilder(t, "").Build(oidcAuth())
	if err == nil {
		t.Fatal("Build() with OIDC configured and no issuer returned nil error, want an error")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("Build() error = %q, want it to name the missing issuer", err)
	}
}

package auth

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/idtoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

type AuthClient struct {
	AllowedGrantTypes []string
	AllowedScopes     []string
	ClientID          string
	ClientSecret      string
	Description       string
	Name              string
	Public            bool
	RedirectURIs      []string
	RequirePKCE       bool
}

type Config struct {
	ActivePair            *keys.KeyPair
	AnonymousEntitlements []string
	AutoExtendSession     bool
	Clients               map[string]AuthClient
	CookieName            string
	KeyPairs              *keys.KeyPairs
	MaxSessionAge         time.Duration
	OIDC                  struct {
		BlockKey     string
		ClientID     string
		ClientSecret string
		IDTokenStore idtoken.IDTokenStore
		Name         string
		ProviderURL  string
		RedirectURL  string
		Scopes       []string
	}
	RefreshTokenTTL time.Duration
	Signer          sign.Signer
	TokenTTL        time.Duration
}

func NewConfig(
	auth *kdexv1alpha1.Auth,
	authClientLoader func() (map[string]AuthClient, error),
	keyLoader func() (*keys.KeyPairs, error),
	oidcClientConfigLoader func() (*OIDCClientConfig, error),
	audience string,
	issuer string,
	devMode bool,
	cacheManager cache.CacheManager,
) (*Config, error) {
	cfg := &Config{}

	if auth != nil {
		keyPairs, err := keyLoader()
		if err != nil {
			return nil, err
		}
		if keyPairs == nil || len(*keyPairs) == 0 {
			return nil, fmt.Errorf("no key pairs found")
		}

		cfg.AnonymousEntitlements = auth.AnonymousEntitlements
		cfg.CookieName = auth.JWT.CookieName

		if cfg.CookieName == "" {
			cfg.CookieName = "auth_token"
		}

		cfg.KeyPairs = keyPairs
		cfg.ActivePair = keyPairs.ActiveKey()
		cfg.AutoExtendSession = auth.AutoExtendSession

		maxSessionAgeString := "24h"
		if auth.MaxSessionAge != "" {
			maxSessionAgeString = auth.MaxSessionAge
		}
		maxSessionAge, err := time.ParseDuration(maxSessionAgeString)
		if err != nil {
			return nil, err
		}
		cfg.MaxSessionAge = maxSessionAge

		refreshTokenTTLString := "12h"
		if auth.RefreshTokenTTL != "" {
			refreshTokenTTLString = auth.RefreshTokenTTL
		}
		refreshTokenTTL, err := time.ParseDuration(refreshTokenTTLString)
		if err != nil {
			return nil, err
		}
		cfg.RefreshTokenTTL = refreshTokenTTL

		tokenTTLString := "1h"
		if auth.JWT.TokenTTL != "" {
			tokenTTLString = auth.JWT.TokenTTL
		}
		tokenTTL, err := time.ParseDuration(tokenTTLString)
		if err != nil {
			return nil, err
		}
		cfg.TokenTTL = tokenTTL

		var mapper *dmapper.Mapper
		if len(auth.ClaimMappings) > 0 {
			mapper, err = dmapper.NewMapper(auth.ClaimMappings)
			if err != nil {
				return nil, err
			}
		}
		signer, err := sign.NewSigner(
			audience,
			tokenTTL,
			issuer,
			&cfg.ActivePair.Private,
			cfg.ActivePair.KeyId,
			mapper,
		)
		if err != nil {
			return nil, err
		}
		cfg.Signer = *signer

		clients, err := authClientLoader()
		if err != nil {
			return nil, err
		}
		cfg.Clients = clients

		if auth.OIDCProvider != nil && auth.OIDCProvider.OIDCProviderURL != "" {
			oidcClientConfig, err := oidcClientConfigLoader()
			if err != nil {
				return nil, err
			}

			cfg.OIDC.BlockKey = getOrGenerate(oidcClientConfig.BlockKey)
			cfg.OIDC.ClientID = oidcClientConfig.ClientID
			cfg.OIDC.ClientSecret = oidcClientConfig.ClientSecret
			cfg.OIDC.Name = oidcClientConfig.Name
			cfg.OIDC.ProviderURL = auth.OIDCProvider.OIDCProviderURL
			cfg.OIDC.RedirectURL = "/-/oauth/callback"
			cfg.OIDC.Scopes = auth.OIDCProvider.Scopes
			cfg.OIDC.IDTokenStore = idtoken.NewCacheIDTokenStore(cacheManager, cfg.TokenTTL)

			if cfg.OIDC.Name == "" {
				providerURL, err := url.Parse(cfg.OIDC.ProviderURL)
				if err != nil {
					return nil, err
				}
				cfg.OIDC.Name = providerURL.Host
			}
		}
	}

	return cfg, nil
}

func (c *Config) AddAuthentication(mux http.Handler, exchanger *Exchanger) http.Handler {
	if !c.IsAuthEnabled() {
		return mux
	}
	return WithAuthentication(c.ActivePair.Private.Public(), c.CookieName, exchanger, c.AutoExtendSession)(mux)
}

func (c *Config) IsAuthEnabled() bool {
	if c == nil || c.ActivePair == nil {
		return false
	}
	return true
}

func (c *Config) IsOIDCEnabled() bool {
	if c == nil || c.OIDC.ProviderURL == "" {
		return false
	}
	return true
}

func (c *Config) IsM2MEnabled() bool {
	if c == nil || c.ActivePair == nil || len(c.Clients) == 0 {
		return false
	}
	return true
}

func getOrGenerate(blockKey string) string {
	if blockKey == "" {
		return rand.Text()
	}
	return blockKey
}

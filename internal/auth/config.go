package auth

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/auth/idtoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/kdex-tech/host-manager/internal/utils"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// DCRConfig is the resolved per-host Dynamic Client Registration config.
type DCRConfig struct {
	Enabled                bool
	ClientTTL              time.Duration
	MaxClients             int32
	AllowedRedirectSchemes []string
}

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
	Audience              string
	AutoExtendSession     bool
	Clients               map[string]AuthClient
	CookieName            string
	FunctionURLs          []string
	Issuer                string
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
	DCR             DCRConfig
	RefreshTokenTTL time.Duration
	Signer          sign.Signer
	TokenManager    *apitoken.TokenManager
	TokenTTL        time.Duration
}

type ConfigBuilder struct {
	APITokenManagerLoader  func() (*apitoken.TokenManager, error)
	Audience               string
	AuthClientLoader       func() (map[string]AuthClient, error)
	CacheManager           cache.CacheManager
	DevMode                bool
	Functions              kdexv1alpha1.KDexFunctionList
	Issuer                 string
	KeyLoader              func() (*keys.KeyPairs, error)
	OIDCClientConfigLoader func() (*OIDCClientConfig, error)
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{}
}

func (cb *ConfigBuilder) WithAuthClientLoader(authClientLoader func() (map[string]AuthClient, error)) *ConfigBuilder {
	cb.AuthClientLoader = authClientLoader
	return cb
}

func (cb *ConfigBuilder) WithKeyLoader(keyLoader func() (*keys.KeyPairs, error)) *ConfigBuilder {
	cb.KeyLoader = keyLoader
	return cb
}

func (cb *ConfigBuilder) WithOIDCClientConfigLoader(oidcClientConfigLoader func() (*OIDCClientConfig, error)) *ConfigBuilder {
	cb.OIDCClientConfigLoader = oidcClientConfigLoader
	return cb
}

func (cb *ConfigBuilder) WithAPITokenManagerLoader(apiTokenManagerLoader func() (*apitoken.TokenManager, error)) *ConfigBuilder {
	cb.APITokenManagerLoader = apiTokenManagerLoader
	return cb
}

func (cb *ConfigBuilder) WithAudience(audience string) *ConfigBuilder {
	cb.Audience = audience
	return cb
}

func (cb *ConfigBuilder) WithFunctions(functions kdexv1alpha1.KDexFunctionList) *ConfigBuilder {
	cb.Functions = functions
	return cb
}

func (cb *ConfigBuilder) WithIssuer(issuer string) *ConfigBuilder {
	cb.Issuer = issuer
	return cb
}

func (cb *ConfigBuilder) WithDevMode(devMode bool) *ConfigBuilder {
	cb.DevMode = devMode
	return cb
}

func (cb *ConfigBuilder) WithCacheManager(cacheManager cache.CacheManager) *ConfigBuilder {
	cb.CacheManager = cacheManager
	return cb
}

func (cb *ConfigBuilder) Build(auth *kdexv1alpha1.Auth) (*Config, error) {
	cfg := &Config{}

	if auth != nil {
		if cb.KeyLoader != nil {
			keyPairs, err := cb.KeyLoader()
			if err != nil {
				return nil, err
			}
			cfg.KeyPairs = keyPairs
			cfg.ActivePair = keyPairs.ActiveKey()
		}

		if cfg.ActivePair == nil {
			return nil, fmt.Errorf("no key pairs found")
		}

		cfg.AnonymousEntitlements = auth.AnonymousEntitlements
		cfg.Audience = cb.Audience
		cfg.AutoExtendSession = auth.AutoExtendSession
		cfg.CookieName = utils.IfElse(auth.JWT.CookieName == "", "auth_token", auth.JWT.CookieName)

		if len(cb.Functions.Items) > 0 {
			functionURLs := make([]string, 0, len(cb.Functions.Items))
			for _, fn := range cb.Functions.Items {
				if fn.Status.URL != "" {
					functionURLs = append(functionURLs, fn.Status.URL)
				}
			}
			cfg.FunctionURLs = functionURLs
		}

		cfg.Issuer = cb.Issuer

		maxSessionAgeString := utils.IfElse(auth.MaxSessionAge == "", "24h", auth.MaxSessionAge)
		maxSessionAge, err := time.ParseDuration(maxSessionAgeString)
		if err != nil {
			return nil, err
		}
		cfg.MaxSessionAge = maxSessionAge

		refreshTokenTTLString := utils.IfElse(auth.RefreshTokenTTL == "", "12h", auth.RefreshTokenTTL)
		refreshTokenTTL, err := time.ParseDuration(refreshTokenTTLString)
		if err != nil {
			return nil, err
		}
		cfg.RefreshTokenTTL = refreshTokenTTL

		tokenTTLString := utils.IfElse(auth.JWT.TokenTTL == "", "1h", auth.JWT.TokenTTL)
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
			cb.Audience,
			tokenTTL,
			cb.Issuer,
			&cfg.ActivePair.Private,
			cfg.ActivePair.KeyId,
			mapper,
		)
		if err != nil {
			return nil, err
		}
		cfg.Signer = *signer

		if cb.APITokenManagerLoader != nil {
			tokenManager, err := cb.APITokenManagerLoader()
			if err != nil {
				return nil, err
			}
			cfg.TokenManager = tokenManager
		}

		if cb.AuthClientLoader != nil {
			clients, err := cb.AuthClientLoader()
			if err != nil {
				return nil, err
			}
			cfg.Clients = clients
		}

		if cb.OIDCClientConfigLoader != nil && auth.OIDCProvider != nil && auth.OIDCProvider.OIDCProviderURL != "" {
			oidcClientConfig, err := cb.OIDCClientConfigLoader()
			if err != nil {
				return nil, err
			}

			cfg.OIDC.BlockKey = getOrGenerate(oidcClientConfig.BlockKey)
			cfg.OIDC.ClientID = oidcClientConfig.ClientID
			cfg.OIDC.ClientSecret = oidcClientConfig.ClientSecret
			cfg.OIDC.IDTokenStore = idtoken.NewCacheIDTokenStore(cb.CacheManager, cfg.TokenTTL)
			cfg.OIDC.Name = oidcClientConfig.Name
			cfg.OIDC.ProviderURL = auth.OIDCProvider.OIDCProviderURL
			cfg.OIDC.RedirectURL = "/-/oauth/callback"
			cfg.OIDC.Scopes = auth.OIDCProvider.Scopes

			if cfg.OIDC.Name == "" {
				providerURL, err := url.Parse(cfg.OIDC.ProviderURL)
				if err != nil {
					return nil, err
				}
				cfg.OIDC.Name = providerURL.Host
			}
		}
	}

	if auth != nil && auth.DynamicClientRegistration != nil {
		dcr := auth.DynamicClientRegistration
		ttl := 720 * time.Hour
		if dcr.ClientTTL != "" {
			if d, derr := time.ParseDuration(dcr.ClientTTL); derr == nil {
				ttl = d
			}
		}
		schemes := dcr.AllowedRedirectSchemes
		if len(schemes) == 0 {
			schemes = []string{"https", "http-loopback"}
		}
		maxClients := dcr.MaxClients
		if maxClients <= 0 {
			maxClients = 1000
		}
		cfg.DCR = DCRConfig{
			Enabled:                dcr.Enabled,
			ClientTTL:              ttl,
			MaxClients:             maxClients,
			AllowedRedirectSchemes: schemes,
		}
	}

	return cfg, nil
}

func (c *Config) AddAuthentication(mux http.Handler, exchanger *Exchanger) http.Handler {
	if !c.IsAuthEnabled() {
		return mux
	}
	return c.WithAuthentication(exchanger)(mux)
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

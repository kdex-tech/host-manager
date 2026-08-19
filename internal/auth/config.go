package auth

import (
	"crypto/rand"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"time"

	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/auth/dcr"
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
	DCR      DCRConfig
	DCRStore *dcr.Store
	// OAuth2ResourceMetadata maps an oauth2-protected resource's basePath to
	// that resource's RFC 9728 metadata URL. It exists so the 401 this
	// middleware returns for an invalid bearer can carry the same
	// resource_metadata challenge the proxy's oauth2 gate emits for an
	// anonymous caller (#180) — the middleware wraps the whole mux and has no
	// other way to know which function a path belongs to.
	//
	// A read-only snapshot of internal/host.oauth2ProtectedResources(),
	// installed by SetHost whenever the host's functions change. Nil is fine:
	// the challenge then omits resource_metadata and is still RFC 6750
	// conformant.
	OAuth2ResourceMetadata    map[string]string
	MintCapCache              cache.Cache
	MintTokenEnabled          bool
	MintTokenTTLCap           time.Duration
	MintTokenUsesCap          int
	MintTokenDestructiveVerbs []string
	MintTokenURLDelivery      bool
	RefreshTokenTTL           time.Duration
	// RefreshGraceWindow keeps a rotated refresh token's RESULT replayable
	// for a short period so concurrent refreshes from one client do not
	// race (RFC 9700 4.14; kdex-tech/host-manager#169). Zero disables it,
	// restoring strict single-winner rotation.
	//
	// Deliberately NOT a KDexHost.spec.auth field: a CRD change would force
	// a paired nexus-manager release. Per-host override goes through
	// KDexHost.spec.helm.hostManager.values instead.
	RefreshGraceWindow time.Duration
	Signer             sign.Signer
	// ClaimMappings are the host's spec.auth.claimMappings rules. They shape
	// EVERY token the host issues: the session Signer above bakes them in, and
	// the per-function FAT signer (proxy.go) prepends them to its own
	// fn.Spec.ClaimMappings — so a rule authored once on the host applies
	// uniformly. See #138.
	ClaimMappings []dmapper.MappingRule
	TokenManager  *apitoken.TokenManager
	TokenTTL      time.Duration
}

// EnrichAuthContext applies mapper (compiled ClaimMappings) to the auth context
// IN PLACE, so any enrichment a mapping performs (e.g. folding a backend-supplied
// source claim into entitlements) is reflected BEFORE the context is used to
// derive `held`, the identity gate, or a downstream token. It is the single
// authContext-enrichment primitive; callers MUST pass the SAME mapper the token
// or FAT signer uses for that context — host ClaimMappings for a session token,
// host + fn.Spec.ClaimMappings for a function's proxy path — so the enriched
// context and the token it yields never disagree. Idempotent for an
// already-enriched context (no raw source claims remain to re-fold);
// attenuation-safe (only ADDS mapped output, never removes a claim, and a
// downscoped capability token carries no source claims to re-expand); fail-safe
// (a mapping error leaves the context unchanged). No claim name is special-cased
// — ClaimMappings are the generic enrichment mechanism.
func EnrichAuthContext(ac AuthContext, mapper *dmapper.Mapper) {
	if mapper == nil || ac == nil {
		return
	}
	extra, err := mapper.Execute(map[string]any(ac))
	if err != nil {
		return
	}
	maps.Copy(ac, extra)
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
	RefreshGraceWindow     time.Duration
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

func (cb *ConfigBuilder) WithRefreshGraceWindow(d time.Duration) *ConfigBuilder {
	cb.RefreshGraceWindow = d
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
		jwt := auth.GetJWT()
		cfg.CookieName = utils.IfElse(jwt.CookieName == "", "auth_token", jwt.CookieName)

		applyMintTokenPolicy(cfg, auth.MintToken)
		cb.buildMintCapCache(cfg)

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
		cfg.RefreshGraceWindow = cb.RefreshGraceWindow

		jwtTTL := auth.GetJWT()
		tokenTTLString := utils.IfElse(jwtTTL.TokenTTL == "", "1h", jwtTTL.TokenTTL)
		tokenTTL, err := time.ParseDuration(tokenTTLString)
		if err != nil {
			return nil, err
		}
		cfg.TokenTTL = tokenTTL

		// Expose the host claimMappings so the per-function FAT signer can apply
		// them too (they otherwise only shape the session token). See #138.
		cfg.ClaimMappings = auth.ClaimMappings

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
		dcrSpec := auth.DynamicClientRegistration
		ttl := 720 * time.Hour
		if dcrSpec.ClientTTL != "" {
			d, derr := time.ParseDuration(dcrSpec.ClientTTL)
			if derr != nil {
				return nil, derr
			}
			ttl = d
		}
		schemes := dcrSpec.AllowedRedirectSchemes
		if len(schemes) == 0 {
			schemes = []string{"https", "http-loopback"}
		}
		maxClients := dcrSpec.MaxClients
		if maxClients <= 0 {
			maxClients = 1000
		}
		cfg.DCR = DCRConfig{
			Enabled:                dcrSpec.Enabled,
			ClientTTL:              ttl,
			MaxClients:             maxClients,
			AllowedRedirectSchemes: schemes,
		}
		cfg.DCRStore = cb.buildDCRStore(cfg.DCR)
	}

	return cfg, nil
}

// buildMintCapCache populates cfg.MintCapCache with the "cap" cache when mint
// token is enabled and a cache manager is available. That cache holds
// jti-keyed bounded-use counters provisioned at mint time
// (internal/host/mint_token.go) and decremented by the inbound middleware
// (WithAuthentication) on every request bearing a CapUsesClaim-marked token.
// Uncycled: true — these keys carry their own TTL (== the token's ttl)
// rather than the cache's default cycle.
func (cb *ConfigBuilder) buildMintCapCache(cfg *Config) {
	if !cfg.MintTokenEnabled || cb.CacheManager == nil {
		return
	}
	cfg.MintCapCache = cb.CacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
}

// buildDCRStore constructs a DCR store when DCR is enabled and a cache is available.
func (cb *ConfigBuilder) buildDCRStore(dcrCfg DCRConfig) *dcr.Store {
	if !dcrCfg.Enabled || cb.CacheManager == nil {
		return nil
	}
	return dcr.NewStore(cb.CacheManager, cb.Issuer, dcrCfg.ClientTTL, dcrCfg.MaxClients)
}

// applyMintTokenPolicy resolves spec.auth.mintToken into cfg's MintToken*
// fields, applying defaults when unset. A nil or disabled policy leaves cfg
// unchanged (MintTokenEnabled stays false).
func applyMintTokenPolicy(cfg *Config, mintToken *kdexv1alpha1.MintToken) {
	if mintToken == nil || !mintToken.Enabled {
		return
	}
	cfg.MintTokenEnabled = true

	ttlCap := mintToken.TTLCapSeconds
	if ttlCap <= 0 {
		ttlCap = 60
	}
	cfg.MintTokenTTLCap = time.Duration(ttlCap) * time.Second

	usesCap := mintToken.UsesCap
	if usesCap <= 0 {
		usesCap = 32
	}
	cfg.MintTokenUsesCap = usesCap

	cfg.MintTokenDestructiveVerbs = mintToken.DestructiveVerbs
	if cfg.MintTokenDestructiveVerbs == nil {
		cfg.MintTokenDestructiveVerbs = []string{"delete", "own"}
	}

	cfg.MintTokenURLDelivery = mintToken.URLDelivery
}

func (c *Config) AddAuthentication(mux http.Handler, exchanger *Exchanger) http.Handler {
	if !c.IsAuthEnabled() {
		return mux
	}
	return c.WithAuthentication(exchanger)(mux)
}

// TokenPrefix returns this host's white-label API token prefix (empty when no
// TokenManager is configured or prefixing is off). Used by the Bearer auth path
// (both the WithAuthentication middleware and the proxy PAT bridge) to recognize
// a brand-prefixed PAT.
func (c *Config) TokenPrefix() string {
	if c == nil || c.TokenManager == nil {
		return ""
	}
	return c.TokenManager.TokenPrefix()
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

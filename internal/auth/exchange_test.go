package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"kdex.dev/crds/api/v1alpha1"
)

type IH struct {
	http.HandlerFunc
	Handler http.HandlerFunc
}

func (f *IH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Handler(w, r)
}

func MockOIDCProvider(cfg Config) http.HandlerFunc {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		// Use server.URL to get the actual assigned port/address
		issuer := cfg.OIDC.ProviderURL

		config := map[string]any{
			"authorization_endpoint":                issuer + "/auth",
			"end_session_endpoint":                  issuer + "/logout",
			"id_token_signing_alg_values_supported": []string{"ES256", "RS256"},
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks.json",
			"response_types_supported":              []string{"code", "id_token"},
			"subject_types_supported":               []string{"public"},
			"token_endpoint":                        issuer + "/token",
			"userinfo_endpoint":                     issuer + "/userinfo",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	})

	mux.HandleFunc("/jwks.json", JWKSHandler(cfg.KeyPairs))
	mux.HandleFunc("POST /token", TokenHandler(cfg))
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// 1. Validate the id_token_hint (optional for mocks)
		// 2. Redirect back to the post_logout_redirect_uri
		redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
		if redirectURI == "" {
			redirectURI = "/"
		}
		http.Redirect(w, r, redirectURI, http.StatusFound)
	})
	return mux.ServeHTTP
}

func MockRunningServer(innerHandler *IH) *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerHandler.ServeHTTP(w, r)
	})

	return httptest.NewServer(handler)
}

func TestNewExchanger(t *testing.T) {
	scopeProvider := &mockScopeProvider{
		resolveIdentity: func(subject string, password string) (jwt.MapClaims, error) {
			if subject == "not-allowed" {
				return nil, fmt.Errorf("invalid credentials")
			}

			return jwt.MapClaims{
				"address": map[string]any{
					"street":  "1 Long Dr",
					"city":    "Baytown",
					"country": "Supernautica",
				},
				"email":        subject,
				"entitlements": []string{"foo", "bar"},
				"firstName":    "Joe",
				"lastName":     "Bar",
				"sub":          subject,
			}, nil
		},
		resolveRolesAndEntitlements: func(subject string) ([]string, []string, error) {
			return nil, []string{"page:read"}, nil
		},
	}

	tests := []struct {
		name       string
		namespace  string
		devMode    bool
		secrets    []v1.Secret
		authConfig *v1alpha1.Auth
		sp         InternalIdentityProvider
		assertions func(t *testing.T, got *Exchanger, goterr error)
	}{
		{
			name: "constructor",
			sp:   scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				assert.Nil(t, goterr)
			},
		},
		{
			name: "AuthCodeURL when there is no OIDC provider",
			sp:   scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				url := got.AuthCodeURL("foo")
				assert.Equal(t, "", url)
			},
		},
		{
			name: "ExchangeCode when there is no OIDC provider",
			sp:   scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				_, err := got.ExchangeCode(context.Background(), "foo")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "OIDC is not configured")
			},
		},
		{
			name: "VerifyIDToken when there is no OIDC provider",
			sp:   scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				_, err := got.verifyIDToken(context.Background(), "foo")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "OIDC is not configured")
			},
		},
		{
			name: "ExchangeToken when there is no OIDC provider",
			sp:   scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				_, err := got.ExchangeToken(context.Background(), "foo")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "OIDC is not configured")
			},
		},
		{
			name:      "LoginLocal when there is no auth.Config",
			namespace: "foo",
			devMode:   true,
			sp:        scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "not-allowed", "password", "", "test-client", AuthMethodLocal)
				assert.Equal(t, "", ts.AccessToken)
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "local auth not configured")
			},
		},
		{
			name:       "LoginLocal invalid subject",
			namespace:  "foo",
			devMode:    true,
			authConfig: &v1alpha1.Auth{},
			sp:         scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "not-allowed", "password", "", "test-client", AuthMethodLocal)
				assert.Equal(t, "", ts.AccessToken)
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "invalid credentials")
			},
		},
		{
			name:       "LoginLocal valid subject",
			namespace:  "foo",
			devMode:    true,
			authConfig: &v1alpha1.Auth{},
			sp:         scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "joe", "password", "", "test-client", "local")
				assert.True(t, len(ts.AccessToken) > 100)
				assert.Nil(t, err)
			},
		},
		{
			name:      "Mapping rules - simple",
			namespace: "foo",
			devMode:   true,
			authConfig: &v1alpha1.Auth{
				ClaimMappings: []dmapper.MappingRule{
					{
						SourceExpression: "self.address",
						TargetPropPath:   "address",
					},
				},
			},
			sp: scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "joe", "password", "", "test-client", AuthMethodLocal)
				assert.True(t, len(ts.AccessToken) > 100)
				assert.Nil(t, err)

				claims := jwt.MapClaims{}
				parser := new(jwt.Parser)
				jwtToken, _, err := parser.ParseUnverified(ts.AccessToken, claims)
				assert.Nil(t, err)
				assert.NotNil(t, jwtToken)
				assert.Contains(t, jwtToken.Header["kid"], "kdex-dev-")
				assert.NotNil(t, claims["address"])
				assert.Equal(t, "1 Long Dr", claims["address"].(map[string]any)["street"])
				assert.Equal(t, "Baytown", claims["address"].(map[string]any)["city"])
			},
		},
		{
			name:      "Mapping rules - required, but fails",
			namespace: "foo",
			devMode:   true,
			authConfig: &v1alpha1.Auth{
				ClaimMappings: []dmapper.MappingRule{
					{
						Required:         true,
						SourceExpression: "self.job",
						TargetPropPath:   "job",
					},
				},
			},
			sp: scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				_, err := got.LoginLocal(context.Background(), "joe", "password", "", "test-client", AuthMethodLocal)
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "failed to map claims: failed to eval expression")
			},
		},
		{
			name:      "Mapping rules - required, success",
			namespace: "foo",
			devMode:   true,
			authConfig: &v1alpha1.Auth{
				ClaimMappings: []dmapper.MappingRule{
					{
						Required:         true,
						SourceExpression: "self.address.street",
						TargetPropPath:   "street",
					},
					{
						SourceExpression: "self.job",
						TargetPropPath:   "job",
					},
				},
			},
			sp: scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "joe", "password", "", "test-client", AuthMethodLocal)
				assert.True(t, len(ts.AccessToken) > 100)
				assert.Nil(t, err)

				claims := jwt.MapClaims{}
				parser := new(jwt.Parser)
				jwtToken, _, err := parser.ParseUnverified(ts.AccessToken, claims)
				assert.Nil(t, err)
				assert.NotNil(t, jwtToken)
				assert.Contains(t, jwtToken.Header["kid"], "kdex-dev-")
				assert.Equal(t, "1 Long Dr", claims["street"])
				assert.Nil(t, claims["job"])
			},
		},
		{
			name:      "Mapping rules - deeply nest",
			namespace: "foo",
			devMode:   true,
			authConfig: &v1alpha1.Auth{
				ClaimMappings: []dmapper.MappingRule{
					{
						Required:         true,
						SourceExpression: "self.address.street",
						TargetPropPath:   "other.place.street",
					},
				},
			},
			sp: scopeProvider,
			assertions: func(t *testing.T, got *Exchanger, goterr error) {
				assert.NotNil(t, got)
				ts, err := got.LoginLocal(context.Background(), "joe", "password", "", "test-client", AuthMethodLocal)
				assert.True(t, len(ts.AccessToken) > 100)
				assert.Nil(t, err)

				claims := jwt.MapClaims{}
				parser := new(jwt.Parser)
				jwtToken, _, err := parser.ParseUnverified(ts.AccessToken, claims)
				assert.Nil(t, err)
				assert.NotNil(t, jwtToken)
				assert.Contains(t, jwtToken.Header["kid"], "kdex-dev-")
				assert.Equal(t, "1 Long Dr", claims["other"].(map[string]any)["place"].(map[string]any)["street"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

			configBuilder := NewConfigBuilder().WithAuthClientLoader(
				func() (map[string]AuthClient, error) {
					return map[string]AuthClient{}, nil
				},
			).WithKeyLoader(
				func() (*keys.KeyPairs, error) {
					return keys.GenerateECDSAKeyPair(), nil
				},
			).WithOIDCClientConfigLoader(
				func() (*OIDCClientConfig, error) {
					return nil, nil
				},
			).WithAudience(
				"audience",
			).WithIssuer(
				"issuer",
			).WithDevMode(
				true,
			).WithCacheManager(
				cacheManager,
			)

			cfg, err := configBuilder.Build(tt.authConfig)
			if err != nil && tt.authConfig != nil {
				assert.Nil(t, err)
			}
			var got *Exchanger
			var gotErr error
			if cfg != nil {
				got, gotErr = NewExchanger(ctx, *cfg, cacheManager, tt.sp)
			} else {
				got, gotErr = NewExchanger(ctx, Config{}, cacheManager, tt.sp) // Pass an empty config if NewConfig failed
			}
			tt.assertions(t, got, gotErr)
		})
	}
}

func TestNewExchanger_OIDC(t *testing.T) {
	scopeProvider := &mockScopeProvider{
		resolveIdentity: func(subject string, password string) (jwt.MapClaims, error) {
			if subject == "not-allowed" {
				return nil, fmt.Errorf("invalid credentials")
			}

			return jwt.MapClaims{
				"email":     subject,
				"firstName": "Joe",
				"lastName":  "Bar",
				"address": map[string]any{
					"street":  "1 Long Dr",
					"city":    "Baytown",
					"country": "Supernautica",
				},
				"sub":          subject,
				"entitlements": []string{"foo", "bar"},
			}, nil
		},
		resolveRolesAndEntitlements: func(subject string) ([]string, []string, error) {
			return nil, []string{"page:read"}, nil
		},
	}

	tests := []struct {
		name       string
		authConfig *v1alpha1.Auth
		sp         InternalIdentityProvider
		assertions func(t *testing.T, serverURL string, innerHandler *IH)
	}{
		{
			name: "OIDC - constructor, bad provider url",
			authConfig: &v1alpha1.Auth{
				OIDCProvider: &v1alpha1.OIDCProvider{
					OIDCProviderURL: "http://bad",
				},
			},
			sp: scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					"http://bad",
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: "http://bad",
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				_, gotErr = NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.NotNil(t, gotErr)
				assert.Contains(t, gotErr.Error(), `failed to initialize OIDC provider: Get "http://bad/.well-known/openid-configuration"`)
			},
		},
		{
			name: "OIDC - constructor, good provider url",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				_, gotErr = NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
			},
		},
		{
			name: "OIDC - AuthCodeURL",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				url := ex.AuthCodeURL("foo")
				assert.Contains(t, url, "http://", "client_id=foo", "scope=openid+profile+email", "state=foo")
			},
		},
		{
			name: "OIDC - AuthCodeURL, extra scopes",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
							Scopes:          []string{"job"},
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				url := ex.AuthCodeURL("foo")
				assert.Contains(t, url, "http://", "client_id=foo", "scope=openid+profile+email+job", "state=foo")
			},
		},
		{
			name: "OIDC - ExchangeCode",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				rawIDToken, err := ex.ExchangeCode(ctx, "foo")
				claims := jwt.MapClaims{}
				parser := new(jwt.Parser)
				jwtToken, _, err := parser.ParseUnverified(rawIDToken, claims)
				assert.Nil(t, err)
				assert.NotNil(t, jwtToken)
				assert.Contains(t, jwtToken.Header["kid"], "kdex-dev-")
				iss, err := claims.GetIssuer()
				assert.Nil(t, err)
				assert.Equal(t, cfg.OIDC.ProviderURL, iss)
			},
		},
		{
			name: "OIDC - ExchangeCode, failed exchange",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				_, err := ex.ExchangeCode(ctx, "fail_exchange")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "Internal Server Error")
			},
		},
		{
			name: "OIDC - ExchangeCode, id token missing",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				_, err := ex.ExchangeCode(ctx, "no_id_token")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "no id_token in response")
			},
		},
		{
			name: "OIDC - VerifyIDToken",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				rawIDToken, err := ex.ExchangeCode(ctx, "foo")
				assert.Nil(t, err)
				oidcToken, err := ex.verifyIDToken(ctx, rawIDToken)
				assert.Nil(t, err)
				assert.NotNil(t, oidcToken)
				assert.Equal(t, cfg.OIDC.ClientID, oidcToken.Audience[0])
			},
		},
		{
			name: "OIDC - ExchangeToken",
			sp:   scopeProvider,
			assertions: func(t *testing.T, serverURL string, innerHandler *IH) {
				ctx := context.Background()
				cacheManager, _ := cache.NewCacheManager("", "foo", new(1*time.Hour))

				configBuilder := NewConfigBuilder().WithAuthClientLoader(
					func() (map[string]AuthClient, error) {
						return map[string]AuthClient{}, nil
					},
				).WithKeyLoader(
					func() (*keys.KeyPairs, error) {
						return keys.GenerateECDSAKeyPair(), nil
					},
				).WithOIDCClientConfigLoader(
					func() (*OIDCClientConfig, error) {
						return &OIDCClientConfig{
							ClientID:     "foo",
							ClientSecret: "bar",
						}, nil
					},
				).WithAudience(
					"foo",
				).WithIssuer(
					serverURL,
				).WithDevMode(
					true,
				).WithCacheManager(
					cacheManager,
				)

				cfg, gotErr := configBuilder.Build(
					&v1alpha1.Auth{
						OIDCProvider: &v1alpha1.OIDCProvider{
							OIDCProviderURL: serverURL,
						},
					},
				)
				assert.Nil(t, gotErr)
				assert.Equal(t, "bar", cfg.OIDC.ClientSecret)

				innerHandler.Handler = MockOIDCProvider(*cfg)
				ex, gotErr := NewExchanger(ctx, *cfg, cacheManager, scopeProvider)
				assert.Nil(t, gotErr)
				rawIDToken, err := ex.ExchangeCode(ctx, "foo")
				assert.Nil(t, err)
				ts, err := ex.ExchangeToken(ctx, rawIDToken)
				assert.Nil(t, err)
				claims := jwt.MapClaims{}
				parser := new(jwt.Parser)
				jwtToken, _, err := parser.ParseUnverified(ts.AccessToken, claims)
				assert.Nil(t, err)
				assert.NotNil(t, jwtToken)
				assert.Contains(t, jwtToken.Header["kid"], "kdex-dev-")
				iss, err := claims.GetIssuer()
				assert.Nil(t, err)
				assert.Equal(t, cfg.OIDC.ProviderURL, iss)
				entitlements := []string{}
				for _, s := range claims["entitlements"].([]any) {
					entitlements = append(entitlements, s.(string))
				}
				assert.Equal(t, []string{"page:read"}, entitlements)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ih := &IH{}
			server := MockRunningServer(ih)
			defer server.Close()
			tt.assertions(t, server.URL, ih)
		})
	}
}

func TokenHandler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 0. OIDC Token requests are almost always POST with form-encoded data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		code := r.FormValue("code")

		if code == "fail_exchange" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		clientID := r.FormValue("client_id")

		if clientID == "" {
			username, _, ok := r.BasicAuth()
			if ok {
				clientID = username
			}
		}

		// 1. Validation: In a mock, you might just check it's not empty
		if clientID == "" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}

		// 2. Validate the Grant Type
		if grantType != "authorization_code" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}

		// 3. Simple Mock Validation
		// In a real mock, you'd check if 'code' exists in a map from the /auth step.
		if code == "" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}

		// 4. Generate the ID Token (using your SignToken function)
		// We usually include 'aud' (client_id) and 'sub' (user id)
		idToken, err := cfg.Signer.Sign(jwt.MapClaims{
			"sub":   code,
			"email": "email@foo.bar",
			"aud":   clientID,
		})
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		// 5. Construct the Response
		resp := map[string]any{
			"access_token": "mock-access-token-" + rand.Text(),
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "openid email",
		}

		if code != "no_id_token" {
			resp["id_token"] = idToken
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type mockScopeProvider struct {
	resolveIdentity             func(subject string, password string) (jwt.MapClaims, error)
	resolveRolesAndEntitlements func(subject string) ([]string, []string, error)
	resolveClaims               func(subject string) jwt.MapClaims
}

func (m *mockScopeProvider) FindInternal(subject string, password string) (jwt.MapClaims, error) {
	return m.resolveIdentity(subject, password)
}

func (m *mockScopeProvider) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	return m.resolveRolesAndEntitlements(subject)
}

// ResolveClaims implements the optional password-less subject->backend-claims
// interface that Exchanger.ResolveSubjectClaims type-asserts. Returns nil when
// unset, so tests that don't wire it exercise the role-only (fail-safe) path.
func (m *mockScopeProvider) ResolveClaims(subject string) jwt.MapClaims {
	if m.resolveClaims == nil {
		return nil
	}
	return m.resolveClaims(subject)
}

// enrichmentClaimMappingConfig returns the production-shaped host claimMapping that folds
// a data-driven backend claim (extra_grants) into entitlements at mint time.
func enrichmentClaimMappingConfig() *v1alpha1.Auth {
	return &v1alpha1.Auth{
		ClaimMappings: []dmapper.MappingRule{{
			SourceExpression: `(has(self.entitlements) ? self.entitlements : []) + (has(self.extra_grants) ? self.extra_grants : [])`,
			TargetPropPath:   "entitlements",
		}},
	}
}

func newTestExchanger(t *testing.T, sp InternalIdentityProvider, authConfig *v1alpha1.Auth) *Exchanger {
	t.Helper()
	ctx := context.Background()
	ttl := 1 * time.Hour
	cacheManager, err := cache.NewCacheManager("", "foo", &ttl)
	require.NoError(t, err)
	cfg, err := NewConfigBuilder().
		WithAuthClientLoader(func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil }).
		WithKeyLoader(func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil }).
		WithOIDCClientConfigLoader(func() (*OIDCClientConfig, error) { return nil, nil }).
		WithAudience("audience").
		WithIssuer("issuer").
		WithDevMode(true).
		WithCacheManager(cacheManager).
		Build(authConfig)
	require.NoError(t, err)
	e, err := NewExchanger(ctx, *cfg, cacheManager, sp)
	require.NoError(t, err)
	return e
}

func tokenClaim(t *testing.T, token, key string) (any, bool) {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, claims)
	require.NoError(t, err)
	v, ok := claims[key]
	return v, ok
}

func tokenEntitlements(t *testing.T, token string) []string {
	t.Helper()
	raw, ok := tokenClaim(t, token, "entitlements")
	if !ok {
		return nil
	}
	out := []string{}
	switch l := raw.(type) {
	case []any:
		for _, e := range l {
			out = append(out, e.(string))
		}
	case []string:
		out = append(out, l...)
	}
	return out
}

// TestMint_SubjectMints_MergeBackendClaimsPreAttenuation pins kdex-tech/host-manager#140:
// the OAuth authorization-code mint and the refresh mint fold the subject's
// data-driven backend claims (here extra_grants) into the signing context
// pre-attenuation, so the access token carries the resolved grant — and the same
// scope gate that governs static entitlements governs the mapped result.
func TestMint_SubjectMints_MergeBackendClaimsPreAttenuation(t *testing.T) {
	ctx := context.Background()
	newSP := func(withClaims bool) *mockScopeProvider {
		sp := &mockScopeProvider{
			resolveIdentity: func(s, _ string) (jwt.MapClaims, error) { return jwt.MapClaims{"sub": s}, nil },
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) {
				return []string{"member"}, []string{"functions:/api/v1/ingest:read"}, nil
			},
		}
		if withClaims {
			sp.resolveClaims = func(string) jwt.MapClaims {
				return jwt.MapClaims{"extra_grants": []any{"resource:rx:all"}}
			}
		}
		return sp
	}

	t.Run("oauth code mint carries backend grant (entitlements scope)", func(t *testing.T) {
		e := newTestExchanger(t, newSP(true), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{
			Subject: "alice", Scope: "entitlements", ClientID: "c", AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		ents := tokenEntitlements(t, ts.AccessToken)
		assert.Contains(t, ents, "resource:rx:all", "OAuth token must carry the resolved resolved grant (#140)")
		assert.Contains(t, ents, "functions:/api/v1/ingest:read", "and still carry static role entitlements")
	})

	t.Run("refresh mint carries backend grant", func(t *testing.T) {
		e := newTestExchanger(t, newSP(true), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromSubject("alice", "c", "entitlements", AuthMethodOAuth2, nil)
		require.NoError(t, err)
		assert.Contains(t, tokenEntitlements(t, ts.AccessToken), "resource:rx:all")
	})

	t.Run("AMP-2 entitlements scope denied strips backend + static grants", func(t *testing.T) {
		e := newTestExchanger(t, newSP(true), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{
			Subject: "alice", Scope: "openid", ClientID: "c", AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		_, present := tokenClaim(t, ts.AccessToken, "entitlements")
		assert.False(t, present, "no entitlements claim when entitlements scope not granted")
	})

	t.Run("AMP-5 empty scope grants no entitlements", func(t *testing.T) {
		e := newTestExchanger(t, newSP(true), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{
			Subject: "alice", Scope: "", ClientID: "c", AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		_, present := tokenClaim(t, ts.AccessToken, "entitlements")
		assert.False(t, present)
	})

	t.Run("AMP-1 nil resolver degrades to role-only, no crash", func(t *testing.T) {
		e := newTestExchanger(t, newSP(false), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{
			Subject: "alice", Scope: "entitlements", ClientID: "c", AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		ents := tokenEntitlements(t, ts.AccessToken)
		assert.Contains(t, ents, "functions:/api/v1/ingest:read")
		assert.NotContains(t, ents, "resource:rx:all")
	})

	t.Run("AMP-6 id_token confined too when entitlements scope denied", func(t *testing.T) {
		e := newTestExchanger(t, newSP(true), enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{
			Subject: "alice", Scope: "openid", ClientID: "c", AuthMethod: AuthMethodOAuth2,
		})
		require.NoError(t, err)
		require.NotEmpty(t, ts.IDToken, "openid granted -> id_token issued")
		_, present := tokenClaim(t, ts.IDToken, "entitlements")
		assert.False(t, present, "id_token must not carry entitlements when scope denies it")
	})
}

// TestMint_UserStoreCannotHijackReservedClaims pins the #140-review hardening:
// the authoritative user store (ResolveClaims for code/refresh; FindInternal for
// login) MAY supplement roles/entitlements/email/extra_grants/custom claims,
// but MUST NOT set reserved auth-flow / identity / mint-time claims. In
// particular a backend-supplied `scope` must never widen claim confinement, and
// `sub`/`idp` must never rebind identity.
func TestMint_UserStoreCannotHijackReservedClaims(t *testing.T) {
	ctx := context.Background()

	t.Run("code: backend scope cannot materialize entitlements", func(t *testing.T) {
		sp := &mockScopeProvider{
			resolveIdentity:             func(s, _ string) (jwt.MapClaims, error) { return jwt.MapClaims{"sub": s}, nil },
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, []string{"pages:*:admin"}, nil },
			resolveClaims:               func(string) jwt.MapClaims { return jwt.MapClaims{"scope": "entitlements roles"} },
		}
		e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{Subject: "alice", Scope: "openid", ClientID: "c", AuthMethod: AuthMethodOAuth2})
		require.NoError(t, err)
		_, present := tokenClaim(t, ts.AccessToken, "entitlements")
		assert.False(t, present, "backend-supplied scope must not materialize entitlements the client did not request")
	})

	t.Run("login: FindInternal scope cannot materialize entitlements", func(t *testing.T) {
		sp := &mockScopeProvider{
			resolveIdentity: func(s, _ string) (jwt.MapClaims, error) {
				return jwt.MapClaims{"sub": s, "scope": "entitlements", "entitlements": []string{"pages:*:admin"}}, nil
			},
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, nil, nil },
		}
		e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())
		ts, err := e.LoginLocal(ctx, "alice", "pw", "openid", "c", AuthMethodLocal)
		require.NoError(t, err)
		_, present := tokenClaim(t, ts.AccessToken, "entitlements")
		assert.False(t, present, "identity-supplied scope must not materialize entitlements")
	})

	t.Run("backend cannot rebind sub or inject idp", func(t *testing.T) {
		sp := &mockScopeProvider{
			resolveIdentity:             func(s, _ string) (jwt.MapClaims, error) { return jwt.MapClaims{"sub": s}, nil },
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, []string{"x:read"}, nil },
			resolveClaims: func(string) jwt.MapClaims {
				return jwt.MapClaims{"sub": "attacker", "idp": "evil", "grant_type": "hax"}
			},
		}
		e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{Subject: "alice", Scope: "openid", ClientID: "c", AuthMethod: AuthMethodOAuth2})
		require.NoError(t, err)
		sub, _ := tokenClaim(t, ts.AccessToken, "sub")
		assert.Equal(t, "alice", sub, "backend must not rebind sub")
		_, idpPresent := tokenClaim(t, ts.AccessToken, "idp")
		assert.False(t, idpPresent, "backend must not inject idp")
		_, gtPresent := tokenClaim(t, ts.AccessToken, "grant_type")
		assert.False(t, gtPresent, "backend must not inject grant_type")
	})

	t.Run("backend cannot extend token lifetime via exp", func(t *testing.T) {
		sp := &mockScopeProvider{
			resolveIdentity:             func(s, _ string) (jwt.MapClaims, error) { return jwt.MapClaims{"sub": s}, nil },
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, []string{"x:read"}, nil },
			resolveClaims:               func(string) jwt.MapClaims { return jwt.MapClaims{"exp": int64(9999999999)} },
		}
		e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{Subject: "alice", Scope: "openid", ClientID: "c", AuthMethod: AuthMethodOAuth2})
		require.NoError(t, err)
		exp, _ := tokenClaim(t, ts.AccessToken, "exp")
		assert.NotEqual(t, float64(9999999999), exp, "backend must not control exp (server mint-time value)")
	})

	t.Run("user store CAN supplement non-reserved claims (feature not castrated)", func(t *testing.T) {
		sp := &mockScopeProvider{
			resolveIdentity:             func(s, _ string) (jwt.MapClaims, error) { return jwt.MapClaims{"sub": s}, nil },
			resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, []string{"functions:x:read"}, nil },
			resolveClaims:               func(string) jwt.MapClaims { return jwt.MapClaims{"extra_grants": []any{"resource:ry:all"}} },
		}
		e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())
		ts, err := e.mintTokensFromCode(ctx, AuthorizationCodeClaims{Subject: "alice", Scope: "entitlements", ClientID: "c", AuthMethod: AuthMethodOAuth2})
		require.NoError(t, err)
		assert.Contains(t, tokenEntitlements(t, ts.AccessToken), "resource:ry:all", "non-reserved backend supplement must still flow through ClaimMappings")
	})
}

// TestLoginLocal_ClosesLatentPostMapperLeak pins that password login also confines
// entitlements post-mapper: with a claimMapping that folds a backend claim
// (extra_grants, supplied by FindInternal) into entitlements, a login whose
// scope omits `entitlements` must emit NO entitlements claim — the pre-mapper
// strip the old code used could not guarantee this. See kdex-tech/host-manager#140.
func TestLoginLocal_ClosesLatentPostMapperLeak(t *testing.T) {
	sp := &mockScopeProvider{
		resolveIdentity: func(s, _ string) (jwt.MapClaims, error) {
			return jwt.MapClaims{
				"sub":          s,
				"entitlements": []string{"pages:*:read"},
				"extra_grants": []any{"resource:rx:all"},
			}, nil
		},
		resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, nil, nil },
	}
	e := newTestExchanger(t, sp, enrichmentClaimMappingConfig())

	// scope omits "entitlements" -> mapper would fold extra_grants into
	// entitlements, but post-mapper confinement must strip the whole family.
	ts, err := e.LoginLocal(context.Background(), "alice", "pw", "openid", "c", AuthMethodLocal)
	require.NoError(t, err)
	_, present := tokenClaim(t, ts.AccessToken, "entitlements")
	assert.False(t, present, "no entitlements when scope denies it, even via ClaimMappings")

	// scope grants entitlements -> the folded grant is present.
	ts2, err := e.LoginLocal(context.Background(), "alice", "pw", "entitlements", "c", AuthMethodLocal)
	require.NoError(t, err)
	assert.Contains(t, tokenEntitlements(t, ts2.AccessToken), "resource:rx:all")
}

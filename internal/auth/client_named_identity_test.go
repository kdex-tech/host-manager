package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// KDexRoleBinding.subject is one namespace shared by users and clients, so a
// user identity named like a client would inherit that client's bindings. No
// user identity may be issued whose sub or role-binding key names a client.
// See kdex-tech/host-manager#243.

const clientNamed = "orchestrator"

func withClient(e *Exchanger, id string) *Exchanger {
	e.config.Clients = map[string]AuthClient{id: {ClientID: id, ClientSecret: "s"}}
	return e
}

func identityProvider(sub string) *mockScopeProvider {
	return &mockScopeProvider{
		resolveIdentity: func(string, string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": sub}, nil
		},
		resolveRolesAndEntitlements: func(string) ([]string, []string, error) {
			return []string{"client-role"}, []string{"apitokens_impersonate_provisioned"}, nil
		},
	}
}

func TestRefuseClientNamedIdentity(t *testing.T) {
	e := withClient(newTestExchanger(t, identityProvider("alice"), &v1alpha1.Auth{}), clientNamed)

	assert.NoError(t, e.refuseClientNamedIdentity("alice", ""))
	assert.ErrorIs(t, e.refuseClientNamedIdentity("alice", clientNamed), ErrSubjectNamesClient, "a binding key naming a client")
	assert.ErrorIs(t, e.refuseClientNamedIdentity(clientNamed), ErrSubjectNamesClient, "a sub naming a client")
	assert.ErrorIs(t, e.refuseClientNamedIdentity("dcr_0a1b2c"), ErrSubjectNamesClient,
		"the dcr_ prefix belongs to dynamically registered clients, so no user may carry it")
}

func TestLoginLocal_RefusesAClientNamedSubject(t *testing.T) {
	for _, sub := range []string{clientNamed, "dcr_0a1b2c"} {
		t.Run(sub, func(t *testing.T) {
			e := withClient(newTestExchanger(t, identityProvider(sub), &v1alpha1.Auth{}), clientNamed)

			ts, err := e.LoginLocal(context.Background(), sub, "pw", "openid entitlements", "c", AuthMethodLocal)

			require.ErrorIs(t, err, ErrSubjectNamesClient)
			assert.Empty(t, ts.AccessToken)
		})
	}
}

func TestMintTokensFromSubject_RefusesAClientNamedSubject(t *testing.T) {
	e := withClient(newTestExchanger(t, identityProvider(clientNamed), &v1alpha1.Auth{}), clientNamed)

	ts, _, err := e.mintTokensFromSubject(clientNamed, "c", "openid entitlements", AuthMethodLocal, nil)

	require.ErrorIs(t, err, ErrSubjectNamesClient)
	assert.Empty(t, ts.AccessToken)
}

func TestMintTokensFromCode_RefusesAClientNamedSubject(t *testing.T) {
	e := withClient(newTestExchanger(t, identityProvider(clientNamed), &v1alpha1.Auth{}), clientNamed)

	ts, err := e.mintTokensFromCode(context.Background(), AuthorizationCodeClaims{
		Subject: clientNamed, ClientID: "c", Scope: "openid entitlements", AuthMethod: AuthMethodLocal,
	})

	require.ErrorIs(t, err, ErrSubjectNamesClient)
	assert.Empty(t, ts.AccessToken)
}

// A user who never logs in again still has a cookie session. Its per-request
// grant refresh must not keep handing it the client's bindings.
func TestRefreshSessionGrants_DropsGrantsForAClientNamedSubject(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)
	cfg := &Config{
		Issuer: "test-iss", Audience: "test-aud", CookieName: "auth_token",
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Signer:     *signer,
		Clients:    map[string]AuthClient{clientNamed: {ClientID: clientNamed}},
	}
	cm, err := cache.NewCacheManager("", "grant-client-named-243", nil)
	require.NoError(t, err)
	ex, err := NewExchanger(context.Background(), *cfg, cm, newRoleBindingScopeProvider(t, clientNamed), nil)
	require.NoError(t, err)

	ac := AuthContext{
		"sub":          clientNamed,
		"scope":        "openid roles entitlements",
		"roles":        []any{"acme-admin"},
		"entitlements": []any{"page:read"},
	}
	cfg.refreshSessionGrants(context.Background(), ac, ex)

	assert.Empty(t, ac["roles"], "a client-named session keeps none of the client's roles")
	assert.Empty(t, ac["entitlements"], "a client-named session keeps none of the client's entitlements")
}

// The client itself is unaffected: client_credentials resolves the client's own
// bindings exactly as before.
func TestClientCredentials_StillResolvesTheClientsOwnBindings(t *testing.T) {
	e := newTestExchanger(t, identityProvider("unused"), &v1alpha1.Auth{})
	e.config.Clients = map[string]AuthClient{clientNamed: {ClientID: clientNamed, ClientSecret: "s"}}

	ctx, _, err := e.buildClientSigningContext(context.Background(), clientNamed, "s", "entitlements")

	require.NoError(t, err)
	assert.Equal(t, clientNamed, ctx["sub"])
	assert.Contains(t, ctx["entitlements"], "apitokens_impersonate_provisioned")
}

// The OIDC login checks both the IdP sub and the role-binding key, since with
// RoleBindingClaim the binding key (e.g. email) is what selects the bindings.
func TestExchangeToken_RefusesAClientNamedSubOrBindingKey(t *testing.T) {
	for name, tc := range map[string]struct{ sub, email string }{
		"sub names a client":         {sub: clientNamed, email: "alice@acme.io"},
		"binding key names a client": {sub: "104187opaque", email: "ops@acme.io"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			ih := &IH{}
			server := MockRunningServer(ih)
			defer server.Close()

			cm, err := cache.NewCacheManager("", "client-named-oidc-243", new(1*time.Hour))
			require.NoError(t, err)
			cfg, err := NewConfigBuilder().WithAuthClientLoader(
				func() (map[string]AuthClient, error) {
					return map[string]AuthClient{
						clientNamed:   {ClientID: clientNamed, ClientSecret: "s"},
						"ops@acme.io": {ClientID: "ops@acme.io", ClientSecret: "s"},
					}, nil
				},
			).WithKeyLoader(
				func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
			).WithOIDCClientConfigLoader(
				func() (*OIDCClientConfig, error) { return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil },
			).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(cm).Build(
				&v1alpha1.Auth{OIDCProvider: &v1alpha1.OIDCProvider{OIDCProviderURL: server.URL, RoleBindingClaim: "email"}},
			)
			require.NoError(t, err)
			ih.Handler = MockOIDCProvider(*cfg)

			ex, err := NewExchanger(ctx, *cfg, cm, newRoleBindingScopeProvider(t, tc.email), nil)
			require.NoError(t, err)
			oidcTokens, err := ex.ExchangeCode(ctx, "rbc:"+tc.sub+"|"+tc.email+"|true")
			require.NoError(t, err)

			ts, err := ex.ExchangeToken(ctx, oidcTokens)

			require.ErrorIs(t, err, ErrSubjectNamesClient)
			assert.Empty(t, ts.AccessToken)
		})
	}
}

// A grant cached for the subject (by a replica still on an older version, or
// before the client existed) must not outlive the guard.
func TestRefreshSessionGrants_GuardPrecedesTheGrantCache(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)
	cfg := &Config{
		Issuer: "test-iss", Audience: "test-aud", CookieName: "auth_token",
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Signer:     *signer,
		Clients:    map[string]AuthClient{clientNamed: {ClientID: clientNamed}},
	}
	cm, err := cache.NewCacheManager("", "grant-client-named-cache-243", nil)
	require.NoError(t, err)
	ex, err := NewExchanger(context.Background(), *cfg, cm, newRoleBindingScopeProvider(t, clientNamed), nil)
	require.NoError(t, err)
	require.NotNil(t, ex.grantCache)
	key := ex.grantGeneration(context.Background()) + "|" + clientNamed
	require.NoError(t, ex.grantCache.Set(context.Background(), key, `{"roles":["acme-admin"],"entitlements":["page::read"]}`))

	ac := AuthContext{"sub": clientNamed, "scope": "openid roles entitlements", "roles": []any{}, "entitlements": []any{}}
	cfg.refreshSessionGrants(context.Background(), ac, ex)

	assert.Empty(t, ac["roles"])
	assert.Empty(t, ac["entitlements"])
}

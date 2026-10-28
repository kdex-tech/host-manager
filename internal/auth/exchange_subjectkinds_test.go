package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kdex.dev/crds/api/v1alpha1"
)

const (
	kindsClientID    = "svc-client"
	kindsAppClientID = "app"
	kindsRedirectURI = "https://app.example.com/cb"
)

// kindRecordingProvider records every BindingSubject a resolution site hands
// the role resolver, so a test can assert the kind each site passes.
type kindRecordingProvider struct {
	mu   sync.Mutex
	seen []BindingSubject
}

func (p *kindRecordingProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"sub": subject}, nil
}

func (p *kindRecordingProvider) FindInternalRolesAndEntitlements(bs BindingSubject, _ *BindingNames) ([]string, []string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, bs)
	return []string{}, []string{}, nil
}

// take returns what was recorded since the last take.
func (p *kindRecordingProvider) take() []BindingSubject {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := p.seen
	p.seen = nil
	return seen
}

// newKindsSiteExchanger wires one Exchanger able to drive every resolution
// site that needs no upstream IdP: an auth-code client, a client_credentials
// client, a refresh lineage, a host-audience PAT and a FAT exchange.
func newKindsSiteExchanger(t *testing.T, sp InternalIdentityProvider) (*Config, *Exchanger, *apitoken.TokenManager, crypto.Signer) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cm, err := cache.NewCacheManager("", "subject-kinds-sites", nil)
	require.NoError(t, err)
	tm, err := apitoken.NewTokenManager("test-iss", apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}))
	require.NoError(t, err)

	cfg := Config{
		Issuer:          "test-iss",
		Audience:        "test-aud",
		CookieName:      "auth_token",
		Signer:          *signer,
		ActivePair:      &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		TokenTTL:        time.Hour,
		RefreshTokenTTL: time.Hour,
		MaxSessionAge:   time.Hour,
		TokenManager:    tm,
		Clients: map[string]AuthClient{
			kindsAppClientID: {ClientID: kindsAppClientID, RedirectURIs: []string{kindsRedirectURI}},
			kindsClientID: {
				ClientID:          kindsClientID,
				ClientSecret:      "s3cret",
				AllowedGrantTypes: []string{GRANT_TYPE_CLIENT_CREDENTIALS},
			},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	ex, err := NewExchanger(context.Background(), cfg, cm, sp, nil)
	require.NoError(t, err)
	return &cfg, ex, tm, cs
}

// TestSubjectKindOf pins the classifier: a sub naming a client is a Client,
// anything else a User.
func TestSubjectKindOf(t *testing.T) {
	_, ex, _, _ := newKindsSiteExchanger(t, &kindRecordingProvider{})

	assert.Equal(t, v1alpha1.SubjectKindClient, ex.SubjectKindOf(kindsClientID), "a configured client id")
	assert.Equal(t, v1alpha1.SubjectKindClient, ex.SubjectKindOf("dcr_abc"), "a dynamically registered client id")
	assert.Equal(t, v1alpha1.SubjectKindUser, ex.SubjectKindOf("alice"))
	assert.Equal(t, v1alpha1.SubjectKindUser, ex.SubjectKindOf(""))
}

// TestResolutionSites_PassKinds is the structural guard: every role
// resolution site hands the resolver a kind, and the right one. The proxy PAT
// bridge and whoami live in internal/host and are pinned there
// (TestResolutionSites_PassKinds_HostSites).
func TestResolutionSites_PassKinds(t *testing.T) {
	user, cl := v1alpha1.SubjectKindUser, v1alpha1.SubjectKindClient
	ctx := context.Background()

	expect := func(t *testing.T, seen []BindingSubject, site string, kind v1alpha1.SubjectKind) {
		t.Helper()
		require.NotEmpty(t, seen, "site %q resolved no roles", site)
		for _, bs := range seen {
			assert.Equal(t, site, bs.Site)
			assert.NotEmpty(t, bs.Kind, "site %q passed no kind", site)
			assert.Equal(t, kind, bs.Kind, "site %q", site)
		}
	}

	t.Run("local login", func(t *testing.T) {
		// Local login resolves inside the provider (Ruling 1), so it is
		// observed through the shared role-binding line rather than a stub.
		sp := newKindsScopeProvider(t, []Lookup{NewSecretLookup(v1alpha1.Secrets{{
			ObjectMeta: metav1.ObjectMeta{Name: "alice", Annotations: map[string]string{"kdex.dev/secret-type": "subject"}},
			Data:       map[string][]byte{"sub": []byte("alice"), "password": []byte("pw")},
		}})})
		out := captureRoleBindingLog(t, 2)
		_, _, err := sp.FindInternalWithSource("alice", "pw")
		require.NoError(t, err)
		assert.Contains(t, out.String(), `"site"="local login"`)
		assert.Contains(t, out.String(), `"kind"="User"`)
	})

	t.Run("oidc login", func(t *testing.T) {
		p := &kindRecordingProvider{}
		ex := newKindsOIDCExchanger(t, p, "")
		oidcTokens, err := ex.ExchangeCode(ctx, "rbc:opaque|alice@acme.io|true")
		require.NoError(t, err)
		_, err = ex.ExchangeToken(ctx, oidcTokens)
		require.NoError(t, err)
		expect(t, p.take(), SiteOIDCLogin, user)
	})

	p := &kindRecordingProvider{}
	cfg, ex, tm, cs := newKindsSiteExchanger(t, p)

	t.Run("auth-code redeem", func(t *testing.T) {
		code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
			AuthMethod: AuthMethodOAuth2, ClientID: kindsAppClientID, RedirectURI: kindsRedirectURI,
			Subject: "alice", Exp: time.Now().Add(time.Minute).Unix(), Scope: "openid roles",
		})
		require.NoError(t, err)
		_, err = ex.RedeemAuthorizationCode(ctx, code, kindsAppClientID, kindsRedirectURI, "")
		require.NoError(t, err)
		expect(t, p.take(), SiteAuthCode, user)
	})

	t.Run("refresh", func(t *testing.T) {
		seedRefreshToken(t, ex, "kinds-refresh", RefreshTokenClaims{
			ClientID: kindsAppClientID, Subject: "alice", AuthMethod: AuthMethodLocal, Scope: "openid",
			ExpiresAt: time.Now().Add(time.Hour).Unix(), OriginalIssuedAt: time.Now().Unix(),
		})
		_, err := ex.RedeemRefreshToken(ctx, "kinds-refresh", kindsAppClientID)
		require.NoError(t, err)
		expect(t, p.take(), SiteRefresh, user)
	})

	t.Run("session-grant refresh", func(t *testing.T) {
		cfg.refreshSessionGrants(ctx, AuthContext{
			"sub": "alice", "scope": "openid roles entitlements",
			"roles": []any{}, "entitlements": []any{},
		}, ex)
		expect(t, p.take(), SiteSessionGrantRefresh, user)
	})

	t.Run("client_credentials", func(t *testing.T) {
		_, err := ex.LoginClient(ctx, kindsClientID, "s3cret", "")
		require.NoError(t, err)
		expect(t, p.take(), SiteClientCredentials, cl)
	})

	// The FAT and PAT sites resolve with the kind the credential carries, so
	// each is driven with a Client and a User. A known kind the classifier
	// would contradict is exactly what the veto refuses (#255), so those are
	// pinned as refused, resolving nothing. Where the veto lets a carried kind
	// through, it still wins over the classifier: a kind this release does not
	// know (token exchange only; a PAT cannot be minted with one, and
	// TestPATAuthContext_Kind pins the PAT helper's half).
	carried := []struct {
		name string
		sub  string
		kind v1alpha1.SubjectKind
	}{
		{"a Client", kindsClientID, cl},
		{"a User", "alice", user},
	}
	contradicted := []struct {
		name string
		sub  string
		kind v1alpha1.SubjectKind
	}{
		{"a Client kind on a user's sub is vetoed", "alice", cl},
		{"a User kind on a client's sub is vetoed", kindsClientID, user},
	}

	t.Run("token exchange", func(t *testing.T) {
		fatSigner, err := sign.NewSigner("https://fn-a.example", time.Hour, "test-iss", &cs, "test-kid", nil)
		require.NoError(t, err)
		exchange := func(t *testing.T, claims jwt.MapClaims) (TokenSet, error) {
			t.Helper()
			fat, err := fatSigner.Sign(claims)
			require.NoError(t, err)
			return ex.ExchangeSubjectToken(fat, "https://fn-b.example")
		}
		for _, tc := range carried {
			t.Run(tc.name, func(t *testing.T) {
				ts, err := exchange(t, jwt.MapClaims{"sub": tc.sub, ClaimSubjectKind: string(tc.kind)})
				require.NoError(t, err)
				expect(t, p.take(), SiteTokenExchange, tc.kind)
				assert.Equal(t, string(tc.kind), claimsOf(t, ts.AccessToken)[ClaimSubjectKind],
					"the exchanged token carries the kind on")
			})
		}
		for _, tc := range contradicted {
			t.Run(tc.name, func(t *testing.T) {
				_, err := exchange(t, jwt.MapClaims{"sub": tc.sub, ClaimSubjectKind: string(tc.kind)})
				require.ErrorIs(t, err, ErrCredentialKindRefused)
				assert.Empty(t, p.take(), "a vetoed FAT resolves nothing")
			})
		}
		t.Run("a carried unknown kind wins over the classifier", func(t *testing.T) {
			const sa = v1alpha1.SubjectKind("ServiceAccount")
			ts, err := exchange(t, jwt.MapClaims{"sub": "alice", ClaimSubjectKind: string(sa)})
			require.NoError(t, err)
			expect(t, p.take(), SiteTokenExchange, sa)
			assert.Equal(t, string(sa), claimsOf(t, ts.AccessToken)[ClaimSubjectKind])
		})
		t.Run("a kind-less FAT falls back to the classifier", func(t *testing.T) { // LEGACY(#268)
			_, err := exchange(t, jwt.MapClaims{"sub": kindsClientID})
			require.NoError(t, err)
			expect(t, p.take(), SiteTokenExchange, cl)
		})
	})

	t.Run("host pat", func(t *testing.T) {
		hostPAT := func(t *testing.T, sub string, kind v1alpha1.SubjectKind) (AuthContext, bool) {
			t.Helper()
			pat, err := tm.MintStatelessKey(cfg.Audience, sub, kind, "read", "", time.Hour)
			require.NoError(t, err)
			return cfg.hostPATIdentity(ctx, pat, ex)
		}
		for _, tc := range carried {
			t.Run(tc.name, func(t *testing.T) {
				ac, ok := hostPAT(t, tc.sub, tc.kind)
				require.True(t, ok)
				expect(t, p.take(), SiteHostPAT, tc.kind)
				assert.Equal(t, string(tc.kind), ac[ClaimSubjectKind])
			})
		}
		for _, tc := range contradicted {
			t.Run(tc.name, func(t *testing.T) {
				_, ok := hostPAT(t, tc.sub, tc.kind)
				assert.False(t, ok)
				assert.Empty(t, p.take(), "a vetoed PAT resolves nothing")
			})
		}
	})
}

// TestIssuedTokens_CarryKind pins that every token a login or grant issues
// records its subject's kind in knd: User for a person, Client for a
// client_credentials client. See kdex-tech/host-manager#255.
func TestIssuedTokens_CarryKind(t *testing.T) {
	ctx := context.Background()
	_, ex, _, _ := newKindsSiteExchanger(t, &kindRecordingProvider{})
	kindOf := func(t *testing.T, token string) any {
		t.Helper()
		return claimsOf(t, token)[ClaimSubjectKind]
	}

	t.Run("local login", func(t *testing.T) {
		ts, err := ex.LoginLocal(ctx, "alice", "pw", "", "", AuthMethodLocal)
		require.NoError(t, err)
		assert.Equal(t, "User", kindOf(t, ts.AccessToken))
	})

	t.Run("oidc login", func(t *testing.T) {
		oex := newKindsOIDCExchanger(t, &kindRecordingProvider{}, "")
		oidcTokens, err := oex.ExchangeCode(ctx, "alice")
		require.NoError(t, err)
		ts, err := oex.ExchangeToken(ctx, oidcTokens)
		require.NoError(t, err)
		assert.Equal(t, "User", kindOf(t, ts.AccessToken))
	})

	t.Run("auth-code redeem", func(t *testing.T) {
		code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
			AuthMethod: AuthMethodOAuth2, ClientID: kindsAppClientID, RedirectURI: kindsRedirectURI,
			Subject: "alice", Exp: time.Now().Add(time.Minute).Unix(), Scope: "openid roles",
		})
		require.NoError(t, err)
		ts, err := ex.RedeemAuthorizationCode(ctx, code, kindsAppClientID, kindsRedirectURI, "")
		require.NoError(t, err)
		assert.Equal(t, "User", kindOf(t, ts.AccessToken))
		assert.Equal(t, "User", kindOf(t, ts.IDToken))
	})

	t.Run("refresh", func(t *testing.T) {
		seedRefreshToken(t, ex, "kinds-issued-refresh", RefreshTokenClaims{
			ClientID: kindsAppClientID, Subject: "alice", AuthMethod: AuthMethodLocal, Scope: "openid",
			ExpiresAt: time.Now().Add(time.Hour).Unix(), OriginalIssuedAt: time.Now().Unix(),
		})
		ts, err := ex.RedeemRefreshToken(ctx, "kinds-issued-refresh", kindsAppClientID)
		require.NoError(t, err)
		assert.Equal(t, "User", kindOf(t, ts.AccessToken))
	})

	t.Run("client_credentials", func(t *testing.T) {
		ts, err := ex.LoginClient(ctx, kindsClientID, "s3cret", "")
		require.NoError(t, err)
		// LoginClientResource builds the same signing context
		// (buildClientSigningContext), so this covers it too.
		assert.Equal(t, "Client", kindOf(t, ts.AccessToken))
	})
}

// TestKindClaim_NotInjectable pins that knd is the mint's alone: neither an
// upstream IdP nor a claimMappings rule can choose it. See
// kdex-tech/host-manager#255.
func TestKindClaim_NotInjectable(t *testing.T) {
	ctx := context.Background()

	t.Run("an id_token's knd never reaches the session", func(t *testing.T) {
		ex := newKindsOIDCExchanger(t, &kindRecordingProvider{}, "")
		oidcTokens, err := ex.ExchangeCode(ctx, "knd:alice|Client")
		require.NoError(t, err)
		ts, err := ex.ExchangeToken(ctx, oidcTokens)
		require.NoError(t, err)
		assert.Equal(t, "User", claimsOf(t, ts.AccessToken)[ClaimSubjectKind])

		require.NotEmpty(t, ts.RefreshToken, "precondition: the session can rotate")
		rotated, err := ex.RedeemRefreshToken(ctx, ts.RefreshToken, "")
		require.NoError(t, err)
		assert.Equal(t, "User", claimsOf(t, rotated.AccessToken)[ClaimSubjectKind],
			"the refresh record's IdP snapshot does not carry it either")
	})

	setter := []dmapper.MappingRule{{SourceExpression: `"User"`, TargetPropPath: ClaimSubjectKind}}

	t.Run("a claimMapping cannot change the signed token's knd", func(t *testing.T) {
		_, ex, _, cs := newKindsSiteExchanger(t, &kindRecordingProvider{})
		mapped, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", mustMapper(t, setter))
		require.NoError(t, err)
		ex.config.Signer = *mapped

		ts, err := ex.LoginClient(ctx, kindsClientID, "s3cret", "")
		require.NoError(t, err)
		assert.Equal(t, "Client", claimsOf(t, ts.AccessToken)[ClaimSubjectKind])
	})

	t.Run("a claimMapping cannot change, add or remove a context's knd", func(t *testing.T) {
		mapper := mustMapper(t, setter)
		ac := AuthContext{"sub": "svc", ClaimSubjectKind: "Client"}
		EnrichAuthContext(ac, mapper)
		assert.Equal(t, "Client", ac[ClaimSubjectKind])

		ac = AuthContext{"sub": "svc"}
		EnrichAuthContext(ac, mapper)
		assert.NotContains(t, ac, ClaimSubjectKind)
	})
}

func mustMapper(t *testing.T, rules []dmapper.MappingRule) *dmapper.Mapper {
	t.Helper()
	m, err := dmapper.NewMapper(rules)
	require.NoError(t, err)
	return m
}

// newKindsOIDCExchanger builds an Exchanger behind a mock OIDC provider, as
// TestExchangeTokenEmailRoleBinding does, with roleBindingClaim configured.
func newKindsOIDCExchanger(t *testing.T, sp InternalIdentityProvider, roleBindingClaim string) *Exchanger {
	t.Helper()
	ih := &IH{}
	server := MockRunningServer(ih)
	t.Cleanup(server.Close)

	cm, err := cache.NewCacheManager("", "subject-kinds-oidc", new(1*time.Hour))
	require.NoError(t, err)
	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(cm).Build(
		&v1alpha1.Auth{OIDCProvider: &v1alpha1.OIDCProvider{
			OIDCProviderURL:  server.URL,
			RoleBindingClaim: roleBindingClaim,
		}},
	)
	require.NoError(t, err)
	ih.Handler = MockOIDCProvider(*cfg)

	ex, err := NewExchanger(context.Background(), *cfg, cm, sp, nil)
	require.NoError(t, err)
	return ex
}

// TestClientCredentials_UserOnlyWildcardGrantsNothing is Review Focus 1: a
// `*` binding narrowed to [User] no longer grants a client_credentials client
// its roles, while the client keeps the binding written for it. With the
// kinds absent it grants both, exactly as before #255.
func TestClientCredentials_UserOnlyWildcardGrantsNothing(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kinds        []v1alpha1.SubjectKind
		wantUserRole bool
	}{
		{"wildcard narrowed to [User]", []v1alpha1.SubjectKind{v1alpha1.SubjectKindUser}, false},
		{"wildcard without subjectKinds (today's behavior)", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := newKindsScopeProvider(t, nil,
				kindsBinding("people", "*", "user-role", tc.kinds...),
				kindsBinding("launcher", "sim-launcher", "client-role"),
			)
			ex := newClientCredsExchanger(t, nil, sp)

			ts, err := ex.LoginClient(context.Background(), "sim-launcher", "s3cret", "")
			require.NoError(t, err)
			roles := accessTokenRoles(t, ts.AccessToken)
			assert.Contains(t, roles, "client-role", "the client keeps the binding written for it")
			assert.Equal(t, tc.wantUserRole, slices.Contains(roles, "user-role"))
		})
	}
}

// TestClientCredentials_ClientKindBindingMatches: a `*` binding narrowed to
// [Client] grants a client_credentials token its role, and not a user who
// logs in with a password.
func TestClientCredentials_ClientKindBindingMatches(t *testing.T) {
	sp := newKindsScopeProvider(t, []Lookup{NewSecretLookup(v1alpha1.Secrets{{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", Annotations: map[string]string{"kdex.dev/secret-type": "subject"}},
		Data:       map[string][]byte{"sub": []byte("alice"), "password": []byte("pw")},
	}})}, kindsBinding("machines", "*", "machine-role", v1alpha1.SubjectKindClient))
	ex := newClientCredsExchanger(t, nil, sp)

	ts, err := ex.LoginClient(context.Background(), "sim-launcher", "s3cret", "")
	require.NoError(t, err)
	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "machine-role")

	identity, err := sp.FindInternal("alice", "pw")
	require.NoError(t, err)
	assert.NotContains(t, identity["roles"], "machine-role", "a [Client] binding grants a password login nothing")
}

// TestOIDCLogin_EmailKeyedUserKindStillMatches is Review Focus 3: under
// RoleBindingClaim=email the lookup key is an email, not the sub, and an
// exact email binding narrowed to [User] still grants the role on login. The
// role-binding output never carries the email (#215).
func TestOIDCLogin_EmailKeyedUserKindStillMatches(t *testing.T) {
	const email = "alice@acme.io"
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("alice-by-email", email, "acme-admin", v1alpha1.SubjectKindUser))
	ex := newKindsOIDCExchanger(t, sp, "email")

	out := captureRoleBindingLog(t, 3)
	ctx := context.Background()
	oidcTokens, err := ex.ExchangeCode(ctx, "rbc:104187opaque|"+email+"|true")
	require.NoError(t, err)
	ts, err := ex.ExchangeToken(ctx, oidcTokens)
	require.NoError(t, err)

	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin")
	assert.Contains(t, out.String(), `"contributed"=["alice-by-email"]`)
	assert.NotContains(t, out.String(), email, "the role-binding output never carries the email key")
}

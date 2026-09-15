/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	rbcFocalHost = "acme-host"
	rbcNamespace = "acme-ns"
)

// newRoleBindingScopeProvider builds a REAL scopeProvider (roles.go, not the
// mockScopeProvider used elsewhere in this package) backed by a fake
// controller-runtime client carrying one KDexRole/KDexRoleBinding pair. This
// task threads the OIDC login's binding key into
// FindInternalRolesAndEntitlements, so the fixture must exercise the actual
// KDexRoleBinding.Spec.Subject match, not a stub that ignores its argument.
// Modeled on TestNewRoleProvider's cb() helper (roles_test.go).
func newRoleBindingScopeProvider(t *testing.T, boundSubject string) InternalIdentityProvider {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, v1.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))

	c := fake.NewClientBuilder().WithScheme(s).WithIndex(
		&v1alpha1.KDexRoleBinding{},
		"spec.hostRef.name", func(rawObj client.Object) []string {
			rb := rawObj.(*v1alpha1.KDexRoleBinding)
			if rb.Spec.HostRef.Name == "" {
				return nil
			}
			return []string{rb.Spec.HostRef.Name}
		},
	).WithIndex(
		&v1alpha1.KDexRole{},
		"spec.hostRef.name", func(rawObj client.Object) []string {
			role := rawObj.(*v1alpha1.KDexRole)
			if role.Spec.HostRef.Name == "" {
				return nil
			}
			return []string{role.Spec.HostRef.Name}
		},
	).WithObjects(
		&v1alpha1.KDexRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "acme-admin",
				Namespace: rbcNamespace,
			},
			Spec: v1alpha1.KDexRoleSpec{
				HostRef: v1.LocalObjectReference{Name: rbcFocalHost},
				Rules: []v1alpha1.PolicyRule{
					{Resources: []string{"page"}, Verbs: []string{"read"}},
				},
			},
		},
		&v1alpha1.KDexRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "acme-admin-binding",
				Namespace: rbcNamespace,
			},
			Spec: v1alpha1.KDexRoleBindingSpec{
				HostRef: v1.LocalObjectReference{Name: rbcFocalHost},
				Subject: boundSubject,
				Roles:   []string{"acme-admin"},
			},
		},
	).Build()

	sp, err := NewRoleProvider(context.Background(), c, rbcFocalHost, rbcNamespace, nil)
	require.NoError(t, err)
	return sp
}

// accessTokenRoles decodes the (unverified) `roles` claim of a minted access
// token, mirroring tokenEntitlements's decode of `entitlements` above.
func accessTokenRoles(t *testing.T, token string) []string {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, claims)
	require.NoError(t, err)
	out := []string{}
	switch v := claims["roles"].(type) {
	case []any:
		for _, r := range v {
			if s, ok := r.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, v...)
	}
	return out
}

// accessTokenSubject decodes the (unverified) `sub` claim of a minted access
// token.
func accessTokenSubject(t *testing.T, token string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(token, claims)
	require.NoError(t, err)
	sub, _ := claims.GetSubject()
	return sub
}

// TestExchangeTokenEmailRoleBinding pins the RoleBindingClaim feature on the
// OIDC login path: with RoleBindingClaim: "email" configured, a login whose
// verified id_token carries an opaque `sub` and a distinct `email` must
// resolve roles/entitlements against the EMAIL (the only claim any
// KDexRoleBinding in this fixture names), while identity -- the signed
// token's `sub` -- remains the opaque IdP subject untouched.
//
// Before Task 5's change, ExchangeToken called
// FindInternalRolesAndEntitlements(sub) directly: a KDexRoleBinding keyed on
// the email could never match, and this test fails with no "acme-admin" role
// on the minted token.
func TestExchangeTokenEmailRoleBinding(t *testing.T) {
	const (
		opaqueSub = "104187opaque"
		email     = "alice@acme.io"
	)

	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	defer server.Close()

	cacheManager, err := cache.NewCacheManager("", "rbc-login-test", new(1*time.Hour))
	require.NoError(t, err)

	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(
		cacheManager,
	).Build(
		&v1alpha1.Auth{
			OIDCProvider: &v1alpha1.OIDCProvider{
				OIDCProviderURL: server.URL,
				// The feature under test: bind roles on `email`, not `sub`.
				// RequireEmailVerified is left nil, which config.go resolves to
				// the secure default (true) -- exercised here because the
				// synthetic id_token below asserts email_verified=true.
				RoleBindingClaim: "email",
			},
		},
	)
	require.NoError(t, err)
	assert.Equal(t, "email", cfg.OIDC.RoleBindingClaim)
	assert.True(t, cfg.OIDC.RequireEmailVerified)

	ih.Handler = MockOIDCProvider(*cfg)

	sp := newRoleBindingScopeProvider(t, email)
	ex, err := NewExchanger(ctx, *cfg, cacheManager, sp, nil)
	require.NoError(t, err)

	// See TokenHandler (exchange_test.go): an "rbc:<sub>|<email>|<verified>"
	// code is the synthetic escape hatch for minting an id_token whose sub and
	// email differ, which every other fixture in this package cannot express.
	oidcTokens, err := ex.ExchangeCode(ctx, "rbc:"+opaqueSub+"|"+email+"|true")
	require.NoError(t, err)

	ts, err := ex.ExchangeToken(ctx, oidcTokens)
	require.NoError(t, err)

	// Role from the email-keyed binding is present.
	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin",
		"the email-keyed KDexRoleBinding must resolve a role for this login")
	// Identity is still the opaque sub, NOT the email.
	assert.Equal(t, opaqueSub, accessTokenSubject(t, ts.AccessToken),
		"identity must remain the opaque IdP sub -- only role resolution keys on email")
	assert.Equal(t, opaqueSub, ts.Subject, "TokenSet.Subject must also remain the opaque sub")
}

// TestExchangeTokenEmailRoleBinding_UnverifiedEmailFallsBackToSub is the
// negative half of the feature: RequireEmailVerified defaults to true, so an
// id_token whose email_verified is false must NOT bind roles via email --
// resolution falls back to `sub`, which the fixture's KDexRoleBinding does not
// name, so no role is resolved.
func TestExchangeTokenEmailRoleBinding_UnverifiedEmailFallsBackToSub(t *testing.T) {
	const (
		opaqueSub = "104187opaque"
		email     = "alice@acme.io"
	)

	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	defer server.Close()

	cacheManager, err := cache.NewCacheManager("", "rbc-unverified-test", new(1*time.Hour))
	require.NoError(t, err)

	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(
		cacheManager,
	).Build(
		&v1alpha1.Auth{
			OIDCProvider: &v1alpha1.OIDCProvider{
				OIDCProviderURL:  server.URL,
				RoleBindingClaim: "email",
			},
		},
	)
	require.NoError(t, err)

	ih.Handler = MockOIDCProvider(*cfg)

	sp := newRoleBindingScopeProvider(t, email)
	ex, err := NewExchanger(ctx, *cfg, cacheManager, sp, nil)
	require.NoError(t, err)

	oidcTokens, err := ex.ExchangeCode(ctx, "rbc:"+opaqueSub+"|"+email+"|false")
	require.NoError(t, err)

	ts, err := ex.ExchangeToken(ctx, oidcTokens)
	require.NoError(t, err)

	assert.NotContains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin",
		"an unverified email must not bind roles; resolution falls back to sub, "+
			"which the fixture's KDexRoleBinding does not name")
	assert.Equal(t, opaqueSub, accessTokenSubject(t, ts.AccessToken))
}

// TestAuthCodeEmailRoleBinding pins Task 7: the authorization-code mint must
// resolve the role-binding key from the IdP-claims snapshot carried inside the
// auth code (AuthorizationCodeClaims.IDPClaims), the same way the OIDC login
// (ExchangeToken) and refresh (mintTokensFromSubject) paths already do.
//
// This is a genuine round trip: CreateAuthorizationCode encrypts the claims
// (including IDPClaims) into a JWE, and RedeemAuthorizationCode decrypts it
// and calls mintTokensFromCode -- exercising the `idpc` JSON tag along the
// way. Before Task 7, mintTokensFromCode resolved roles/entitlements on
// claims.Subject (the opaque sub), so the email-keyed KDexRoleBinding here
// could never match and the test fails with no "acme-admin" role on the
// minted token.
func TestAuthCodeEmailRoleBinding(t *testing.T) {
	const (
		opaqueSub   = "104187opaque"
		email       = "alice@acme.io"
		clientID    = "app"
		redirectURI = "https://app.example.com/cb"
	)

	ctx := context.Background()

	// Real signer so mintTokensFromCode can complete on redemption, mirroring
	// newReplayTestExchanger (exchange_authcode_replay_test.go).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	cfg := Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		Clients: map[string]AuthClient{
			clientID: {
				ClientID:     clientID,
				RedirectURIs: []string{redirectURI},
			},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"
	// The feature under test: bind roles on `email`, not `sub`, exactly as
	// applyOIDC would configure from KDexHost.Spec.Auth.OIDCProvider.
	cfg.OIDC.RoleBindingClaim = "email"
	cfg.OIDC.RequireEmailVerified = true

	cm, err := cache.NewCacheManager("", "auth-code-rbc-test", nil)
	require.NoError(t, err)

	sp := newRoleBindingScopeProvider(t, email)
	ex, err := NewExchanger(ctx, cfg, cm, sp, nil)
	require.NoError(t, err)

	// IDPClaims mirrors what the /-/authorize handler snapshots from the
	// session's authContext (idpClaimSnapshot(jwt.MapClaims(authCtx))): the
	// non-reserved claims asserted at login, including email/email_verified.
	code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
		AuthMethod:  AuthMethodOAuth2,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Subject:     opaqueSub,
		Exp:         time.Now().Add(time.Minute).Unix(),
		// "roles" must be requested: SignScoped strips the `roles` claim
		// unless the granted scope includes it (sign.go), independent of
		// role-binding resolution.
		Scope: "openid roles",
		IDPClaims: jwt.MapClaims{
			"email":          email,
			"email_verified": true,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, code)

	ts, err := ex.RedeemAuthorizationCode(ctx, code, clientID, redirectURI, "")
	require.NoError(t, err)

	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin",
		"the email-keyed KDexRoleBinding must resolve a role for this auth-code redemption")
	assert.Equal(t, opaqueSub, accessTokenSubject(t, ts.AccessToken),
		"identity must remain the opaque IdP sub -- only role resolution keys on email")
	assert.Equal(t, opaqueSub, ts.Subject, "TokenSet.Subject must also remain the opaque sub")
}

// TestAuthorizeAndRedeem_EmailRoleBinding_SurvivesSessionProjection is the
// Task 8 regression: TestAuthCodeEmailRoleBinding above proves mintTokensFromCode
// resolves roles correctly GIVEN a populated AuthorizationCodeClaims.IDPClaims,
// but it hand-builds that IDPClaims map with email_verified already present --
// it never exercises how IDPClaims is actually produced in production.
//
// In production (oauth2.go AuthorizeHandler), IDPClaims is a snapshot of the
// SESSION token's claims (idpClaimSnapshot(jwt.MapClaims(authCtx))), and that
// session token was itself minted by a real login via SignScoped, which runs
// sign.Signer.Project. Project's custom-claim whitelist historically allow-
// listed "email" but not "email_verified", so the session token -- and thus
// the auth code's IDPClaims snapshot taken from it -- NEVER carried
// email_verified. Under the default secure config (RequireEmailVerified unset
// => true), resolveBindingKey then always fell back to `sub`, silently
// under-granting the email-keyed role on every authorization-code redemption
// (OAuth2/MCP/PKCE clients), even though the OIDC-login and refresh paths
// (which resolve the binding key from the RAW, pre-projection id_token claims)
// granted it correctly.
//
// This test drives the REAL production path end-to-end instead of hand-
// building IDPClaims:
//  1. ExchangeToken performs a real OIDC login (via the "rbc:" mock-IdP escape
//     hatch) and mints the SESSION access token exactly as production does
//     (SignScoped -> sign.Project/confineByScope).
//  2. That session token is decoded, exactly as the auth middleware would, to
//     build the request's AuthContext.
//  3. The REAL AuthorizeHandler (not a hand-built AuthorizationCodeClaims)
//     snapshots that AuthContext into the auth code's IDPClaims.
//  4. RedeemAuthorizationCode mints the final access token.
//
// Before the sign.go fix (email_verified added to Project's whitelist and to
// confineByScope's email-scope family), this test FAILS: the redeemed token
// carries no "acme-admin" role because email_verified never survived the
// session token's projection into the auth code's IDPClaims snapshot.
func TestAuthorizeAndRedeem_EmailRoleBinding_SurvivesSessionProjection(t *testing.T) {
	const (
		opaqueSub   = "104187opaque"
		email       = "alice@acme.io"
		clientID    = "app"
		redirectURI = "https://app.example.com/cb"
	)

	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	defer server.Close()

	cacheManager, err := cache.NewCacheManager("", "rbc-authorize-roundtrip-test", new(1*time.Hour))
	require.NoError(t, err)

	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) {
			return map[string]AuthClient{
				clientID: {ClientID: clientID, RedirectURIs: []string{redirectURI}},
			}, nil
		},
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(
		cacheManager,
	).Build(
		&v1alpha1.Auth{
			OIDCProvider: &v1alpha1.OIDCProvider{
				OIDCProviderURL: server.URL,
				// The feature under test: bind roles on `email`, not `sub`.
				// RequireEmailVerified is left nil/unset, which config.go
				// resolves to the secure DEFAULT (true) -- the exact config
				// under which the defect silently under-granted the role.
				RoleBindingClaim: "email",
			},
		},
	)
	require.NoError(t, err)
	require.Equal(t, "email", cfg.OIDC.RoleBindingClaim)
	require.True(t, cfg.OIDC.RequireEmailVerified, "precondition: exercising the DEFAULT secure config")

	ih.Handler = MockOIDCProvider(*cfg)

	sp := newRoleBindingScopeProvider(t, email)
	ex, err := NewExchanger(ctx, *cfg, cacheManager, sp, nil)
	require.NoError(t, err)

	// Step 1: a REAL OIDC login mints the session access token exactly as
	// production does -- ExchangeToken -> SignScoped -> sign.Project /
	// confineByScope. Role resolution inside ExchangeToken itself reads the
	// RAW (pre-projection) id_token claims, so this step alone would already
	// grant the role; the defect is downstream, in what the MINTED token
	// carries forward.
	oidcTokens, err := ex.ExchangeCode(ctx, "rbc:"+opaqueSub+"|"+email+"|true")
	require.NoError(t, err)
	sessionTS, err := ex.ExchangeToken(ctx, oidcTokens)
	require.NoError(t, err)

	// Step 2: decode the session token the way the auth middleware would, to
	// build the AuthContext the real AuthorizeHandler reads.
	sessionClaims := jwt.MapClaims{}
	_, _, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(sessionTS.AccessToken, sessionClaims)
	require.NoError(t, err)

	// Step 3: drive the REAL /-/authorize handler -- no hand-built
	// AuthorizationCodeClaims anywhere in this test.
	o := &OAuth2{AuthConfig: cfg, AuthExchanger: ex}

	u, _ := url.Parse("/-/oauth/authorize")
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	// "roles" must be requested: SignScoped strips the `roles` claim unless
	// the granted scope includes it, independent of role-binding resolution.
	q.Set("scope", "openid roles")
	u.RawQuery = q.Encode()

	req := httptest.NewRequest("GET", u.String(), nil)
	req = req.WithContext(SetAuthContext(req.Context(), AuthContext(sessionClaims)))

	w := httptest.NewRecorder()
	o.AuthorizeHandler(w, req)

	resp := w.Result()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := resp.Location()
	require.NoError(t, err)
	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "a real authorization code should have been minted")

	// Step 4: redeem the code exactly as the token endpoint does.
	ts, err := ex.RedeemAuthorizationCode(ctx, code, clientID, redirectURI, "")
	require.NoError(t, err)

	assert.Contains(t, accessTokenRoles(t, ts.AccessToken), "acme-admin",
		"the email-keyed KDexRoleBinding must resolve a role on the auth-code path under "+
			"the DEFAULT secure config (RequireEmailVerified unset => true); this requires "+
			"email_verified to survive the session token's projection so the auth code's "+
			"IDPClaims snapshot carries it")
	assert.Equal(t, opaqueSub, accessTokenSubject(t, ts.AccessToken),
		"identity must remain the opaque IdP sub -- only role resolution keys on email")
	assert.Equal(t, opaqueSub, ts.Subject, "TokenSet.Subject must also remain the opaque sub")
}

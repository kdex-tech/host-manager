package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// The RFC 9068 client_id claim names the client a token was issued to. The
// mint decides it, Project carries it into every FAT, and no claimMappings
// rule, credential store, backend Lookup or upstream IdP can set it. A
// backend partitions per-client state (knowdb's watches) by it, so a forged
// value would read another client's state. See kdex-tech/host-manager#295.

// fatOf projects an access token's claims as the proxy does for a function
// (signer.Project over the caller's auth context), returning the FAT's claims.
func fatOf(t *testing.T, signer *sign.Signer, accessToken string) jwt.MapClaims {
	t.Helper()
	projected, err := signer.Project(claimsOf(t, accessToken))
	require.NoError(t, err)
	return projected
}

// TestIssuedTokens_CarryClientID: every grant that issues a token to a client
// records that client in client_id, and the FAT projected from the token
// carries it on.
func TestIssuedTokens_CarryClientID(t *testing.T) {
	ctx := context.Background()
	_, ex, _, cs := newKindsSiteExchanger(t, &kindRecordingProvider{})
	fatSigner, err := sign.NewSigner("https://fn-a.example", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)

	expect := func(t *testing.T, accessToken, want string) {
		t.Helper()
		assert.Equal(t, want, claimsOf(t, accessToken)[ClaimClientID], "the access token")
		assert.Equal(t, want, fatOf(t, fatSigner, accessToken)[ClaimClientID], "the FAT projected from it")
	}

	t.Run("authorization code", func(t *testing.T) {
		code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
			AuthMethod: AuthMethodOAuth2, ClientID: kindsAppClientID, RedirectURI: kindsRedirectURI,
			Subject: "alice", Exp: time.Now().Add(time.Minute).Unix(), Scope: "openid roles",
		})
		require.NoError(t, err)
		ts, err := ex.RedeemAuthorizationCode(ctx, code, kindsAppClientID, kindsRedirectURI, "")
		require.NoError(t, err)
		expect(t, ts.AccessToken, kindsAppClientID)
	})

	t.Run("refresh", func(t *testing.T) {
		seedRefreshToken(t, ex, "client-id-refresh", RefreshTokenClaims{
			ClientID: kindsAppClientID, Subject: "alice", AuthMethod: AuthMethodOAuth2, Scope: "openid",
			ExpiresAt: time.Now().Add(time.Hour).Unix(), OriginalIssuedAt: time.Now().Unix(),
		})
		ts, err := ex.RedeemRefreshToken(ctx, "client-id-refresh", kindsAppClientID)
		require.NoError(t, err)
		expect(t, ts.AccessToken, kindsAppClientID)
	})

	t.Run("client credentials", func(t *testing.T) {
		ts, err := ex.LoginClient(ctx, kindsClientID, "s3cret", "")
		require.NoError(t, err)
		// The signing context keeps its azp alongside, but Project has never
		// carried azp; client_id is what reaches the token and the FAT.
		expect(t, ts.AccessToken, kindsClientID)
	})

	t.Run("client credentials for a resource", func(t *testing.T) {
		ts, err := ex.LoginClientResource(ctx, kindsClientID, "s3cret", "", "https://fn-a.example")
		require.NoError(t, err)
		assert.Equal(t, kindsClientID, claimsOf(t, ts.AccessToken)[ClaimClientID])
	})

	t.Run("password grant", func(t *testing.T) {
		ts, err := ex.LoginLocal(ctx, "alice", "pw", "", kindsAppClientID, AuthMethodOAuth2)
		require.NoError(t, err)
		expect(t, ts.AccessToken, kindsAppClientID)
	})

	t.Run("token exchange carries the subject_token's client on", func(t *testing.T) {
		fat, err := fatSigner.Sign(jwt.MapClaims{
			"sub": "alice", ClaimSubjectKind: string(v1alpha1.SubjectKindUser), ClaimClientID: kindsAppClientID,
		})
		require.NoError(t, err)
		ts, err := ex.ExchangeSubjectToken(fat, "https://fn-b.example")
		require.NoError(t, err)
		assert.Equal(t, kindsAppClientID, claimsOf(t, ts.AccessToken)[ClaimClientID])
	})

	// A browser session is issued to no OAuth client: the host's own login
	// form, and the session it refreshes into, carry no client_id.
	t.Run("a browser login names no client", func(t *testing.T) {
		ts, err := ex.LoginLocal(ctx, "alice", "pw", "", "", AuthMethodLocal)
		require.NoError(t, err)
		assert.NotContains(t, claimsOf(t, ts.AccessToken), ClaimClientID)
		assert.NotContains(t, fatOf(t, fatSigner, ts.AccessToken), ClaimClientID)
	})

	t.Run("an oidc browser login names no client", func(t *testing.T) {
		oex := newKindsOIDCExchanger(t, &kindRecordingProvider{}, "")
		oidcTokens, err := oex.ExchangeCode(ctx, "alice")
		require.NoError(t, err)
		ts, err := oex.ExchangeToken(ctx, oidcTokens)
		require.NoError(t, err)
		assert.NotContains(t, claimsOf(t, ts.AccessToken), ClaimClientID)
	})
}

// TestRefreshedSession_KeepsClientID: a rotated session carries the same
// client_id as the one it replaces, across every rotation.
func TestRefreshedSession_KeepsClientID(t *testing.T) {
	ctx := context.Background()
	_, ex, _, _ := newKindsSiteExchanger(t, &kindRecordingProvider{})

	code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
		AuthMethod: AuthMethodOAuth2, ClientID: kindsAppClientID, RedirectURI: kindsRedirectURI,
		Subject: "alice", Exp: time.Now().Add(time.Minute).Unix(), Scope: "openid roles",
	})
	require.NoError(t, err)
	ts, err := ex.RedeemAuthorizationCode(ctx, code, kindsAppClientID, kindsRedirectURI, "")
	require.NoError(t, err)
	original := claimsOf(t, ts.AccessToken)[ClaimClientID]
	require.Equal(t, kindsAppClientID, original)

	for i := range 2 {
		require.NotEmpty(t, ts.RefreshToken, "rotation %d: the session can rotate", i)
		ts, err = ex.RedeemRefreshToken(ctx, ts.RefreshToken, kindsAppClientID)
		require.NoError(t, err)
		assert.Equal(t, original, claimsOf(t, ts.AccessToken)[ClaimClientID], "rotation %d", i)
	}
}

// TestClientIDClaim_NotInjectable: client_id is the mint's alone.
func TestClientIDClaim_NotInjectable(t *testing.T) {
	ctx := context.Background()

	t.Run("it is mint-decided and reserved", func(t *testing.T) {
		assert.Contains(t, sign.MintDecidedClaims(), ClaimClientID)
		assert.Contains(t, sign.ReservedClaims(), ClaimClientID)
		assert.Contains(t, reservedMintClaims, ClaimClientID)
	})

	t.Run("an id_token's client_id never reaches the session", func(t *testing.T) {
		ex := newKindsOIDCExchanger(t, &kindRecordingProvider{}, "")
		oidcTokens, err := ex.ExchangeCode(ctx, "cid:alice|forged-client")
		require.NoError(t, err)
		ts, err := ex.ExchangeToken(ctx, oidcTokens)
		require.NoError(t, err)
		assert.NotContains(t, claimsOf(t, ts.AccessToken), ClaimClientID)

		require.NotEmpty(t, ts.RefreshToken, "precondition: the session can rotate")
		rotated, err := ex.RedeemRefreshToken(ctx, ts.RefreshToken, "")
		require.NoError(t, err)
		assert.NotContains(t, claimsOf(t, rotated.AccessToken), ClaimClientID,
			"the refresh record's IdP snapshot does not carry it either")
	})

	t.Run("a backend claim cannot set it", func(t *testing.T) {
		sc := jwt.MapClaims{"sub": "alice"}
		mergeBackendClaims(sc, jwt.MapClaims{ClaimClientID: "forged-client"})
		assert.NotContains(t, sc, ClaimClientID)
	})

	forger := []dmapper.MappingRule{{SourceExpression: `"forged-client"`, TargetPropPath: ClaimClientID}}

	t.Run("a claimMappings rule is dropped at the mint", func(t *testing.T) {
		mapped := map[string]any{ClaimClientID: "forged-client", "subscription": "gold"}
		sign.DropReservedClaims(mapped)
		assert.NotContains(t, mapped, ClaimClientID)
		assert.Equal(t, "gold", mapped["subscription"])
	})

	t.Run("a claimMappings rule cannot override the minted value", func(t *testing.T) {
		_, ex, _, cs := newKindsSiteExchanger(t, &kindRecordingProvider{})
		mapped, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", mustMapper(t, forger))
		require.NoError(t, err)
		ex.config.Signer = *mapped

		ts, err := ex.LoginClient(ctx, kindsClientID, "s3cret", "")
		require.NoError(t, err)
		assert.Equal(t, kindsClientID, claimsOf(t, ts.AccessToken)[ClaimClientID])

		browser, err := ex.LoginLocal(ctx, "alice", "pw", "", "", AuthMethodLocal)
		require.NoError(t, err)
		assert.NotContains(t, claimsOf(t, browser.AccessToken), ClaimClientID,
			"nor add one to a token issued to no client")
	})

	t.Run("a claimMappings rule cannot change, add or remove a context's client_id", func(t *testing.T) {
		mapper := mustMapper(t, forger)
		ac := AuthContext{"sub": "alice", ClaimClientID: kindsAppClientID}
		EnrichAuthContext(ac, mapper)
		assert.Equal(t, kindsAppClientID, ac[ClaimClientID])

		ac = AuthContext{"sub": "alice"}
		EnrichAuthContext(ac, mapper)
		assert.NotContains(t, ac, ClaimClientID)
	})
}

// TestPATAuthContext_ClientID: an API token (PASETO PAT) is issued to no OAuth
// client, so each key acts as its own: the context built from it -- by the
// host PAT middleware and the proxy PAT bridge alike -- names the client
// "pat:<jti>", and the FAT carries it on. A PAT with no jti names none.
func TestPATAuthContext_ClientID(t *testing.T) {
	ex := newPATKindsExchanger(t)

	ac, err := ex.PATAuthContext(&apitoken.TokenData{
		Subject: "alice", SubjectKind: v1alpha1.SubjectKindUser, JTI: "abc123",
	}, SiteHostPAT)
	require.NoError(t, err)
	assert.Equal(t, "pat:abc123", ac[ClaimClientID])

	ac, err = ex.PATAuthContext(&apitoken.TokenData{Subject: "alice", SubjectKind: v1alpha1.SubjectKindUser}, SiteHostPAT)
	require.NoError(t, err)
	assert.NotContains(t, ac, ClaimClientID)
}

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	"kdex.dev/crds/api/v1alpha1"
)

// An MCP resource PAT (RFC 8707, minted at the token endpoint for an
// authorization_code or refresh_token grant naming an oauth2-protected
// resource) records the OAuth client the grant authenticated, and the FAT
// minted for it names that client. Its jti is sha256(resource:sub:"mcp"), the
// same for every client of one user on one resource, so "pat:<jti>" would
// merge them (#295 review, user ruling).
func TestResourcePAT_NamesTheOriginatingClient(t *testing.T) {
	const (
		resource    = "https://dev.knowdrive.ai/api/v1/mcp"
		redirectURI = "http://localhost/cb"
		user        = "alice@example.com"
	)
	clients := []string{"dcr_aaaa", "dcr_bbbb"}

	keyPairs := keys.GenerateECDSAKeyPair()
	signer, err := sign.NewSigner("aud", time.Hour, "iss", &keyPairs.ActiveKey().Private, keyPairs.ActiveKey().KeyId, nil)
	require.NoError(t, err)
	cm, err := cache.NewCacheManager("", "resource-pat-client", nil)
	require.NoError(t, err)
	tm, err := apitoken.NewTokenManager("test-issuer", apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}))
	require.NoError(t, err)

	authClients := map[string]AuthClient{}
	for _, id := range clients {
		authClients[id] = AuthClient{ClientID: id, ClientSecret: id + "-secret", RedirectURIs: []string{redirectURI}}
	}
	cfg := Config{
		ActivePair: keyPairs.ActiveKey(), KeyPairs: keyPairs, Clients: authClients,
		Signer: *signer, TokenTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenManager: tm,
	}
	sp := &mockScopeProvider{
		resolveIdentity: func(string, string) (jwt.MapClaims, error) { return nil, fmt.Errorf("unused") },
		resolveRolesAndEntitlements: func(string) ([]string, []string, error) {
			return []string{"role1"}, []string{"entitlement1"}, nil
		},
	}
	ex, err := NewExchanger(context.Background(), cfg, cm, sp, nil)
	require.NoError(t, err)
	require.True(t, ex.IsRefreshTokenEnabled())

	oauth2 := &OAuth2{AuthExchanger: ex, ResourceAudiences: map[string]bool{resource: true}, AccessTokenTTL: time.Hour}
	post := func(t *testing.T, form url.Values) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		oauth2.OAuth2TokenHandler(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp
	}
	fatSigner, err := sign.NewSigner(resource, time.Hour, "iss", &keyPairs.ActiveKey().Private, keyPairs.ActiveKey().KeyId, nil)
	require.NoError(t, err)
	// bridged decodes a resource PAT as the proxy bridge does and returns it
	// with the FAT projected from its context.
	bridged := func(t *testing.T, pat string) (*apitoken.TokenData, jwt.MapClaims) {
		t.Helper()
		data, err := tm.ValidateToken(context.Background(), pat, resource)
		require.NoError(t, err)
		ac, err := ex.PATAuthContext(data, SiteProxyPAT)
		require.NoError(t, err)
		fat, err := fatSigner.Project(jwt.MapClaims(ac))
		require.NoError(t, err)
		return data, fat
	}

	jtis := map[string]bool{}
	for _, clientID := range clients {
		t.Run(clientID, func(t *testing.T) {
			code, err := ex.CreateAuthorizationCode(context.Background(), AuthorizationCodeClaims{
				Subject: user, ClientID: clientID, Scope: "openid", RedirectURI: redirectURI,
				AuthMethod: AuthMethodOAuth2, Exp: time.Now().Add(time.Minute).Unix(),
			})
			require.NoError(t, err)
			resp := post(t, url.Values{
				"grant_type": {"authorization_code"}, "client_id": {clientID}, "client_secret": {clientID + "-secret"},
				"code": {code}, "redirect_uri": {redirectURI}, "resource": {resource},
			})
			data, fat := bridged(t, resp["access_token"].(string))
			assert.Equal(t, clientID, data.ClientID, "the PAT records its client")
			assert.Equal(t, clientID, fat[ClaimClientID], "the bridged FAT names its client")
			jtis[data.JTI] = true

			// A refreshed MCP session keeps its client.
			refreshed := post(t, url.Values{
				"grant_type": {"refresh_token"}, "client_id": {clientID}, "client_secret": {clientID + "-secret"},
				"refresh_token": {resp["refresh_token"].(string)}, "resource": {resource},
			})
			_, fat = bridged(t, refreshed["access_token"].(string))
			assert.Equal(t, clientID, fat[ClaimClientID], "the refreshed session's FAT names the same client")
		})
	}
	assert.Len(t, jtis, 1, "precondition: both clients' PATs share one jti, so the jti cannot tell them apart")

	t.Run("a user-minted API key is its own client", func(t *testing.T) {
		pat, err := tm.MintStatelessKey(resource, user, v1alpha1.SubjectKindUser, "laptop", "", time.Hour)
		require.NoError(t, err)
		data, fat := bridged(t, pat)
		assert.Empty(t, data.ClientID)
		assert.Equal(t, "pat:"+apitoken.GenerateJTI(resource, user, "laptop"), fat[ClaimClientID])
	})
}

// TestRefreshSessionGrants_CacheIsPerClient: the session-grant cache holds a
// projection, which a claimMapping may derive from client_id, so one client's
// cached grants must never be overlaid onto another client's session, nor
// onto a browser session's (#295).
func TestRefreshSessionGrants_CacheIsPerClient(t *testing.T) {
	cfg, _ := buildGrantTestConfig(t)
	mapped, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cfg.ActivePair.Private, "test-kid", mustMapper(t,
		[]dmapper.MappingRule{{
			SourceExpression: `self.entitlements + (has(self.client_id) ? ["client:" + self.client_id + ":read"] : [])`,
			TargetPropPath:   "entitlements",
		}}))
	require.NoError(t, err)
	cfg.Signer = *mapped
	cm, err := cache.NewCacheManager("", "grant-per-client", nil)
	require.NoError(t, err)
	ex, err := NewExchanger(context.Background(), *cfg, cm, &changingGrantProvider{}, nil)
	require.NoError(t, err)

	session := func(clientID string) AuthContext {
		ac := AuthContext{"sub": "alice", ClaimSubjectKind: "User", "scope": "openid entitlements", "entitlements": []any{}}
		if clientID != "" {
			ac[ClaimClientID] = clientID
		}
		return ac
	}
	// Each in the same generation, so a client-blind key would serve the
	// first one's projection to the rest.
	for _, tc := range []struct{ clientID, want string }{
		{"dcr_aaaa", "client:dcr_aaaa:read"},
		{"dcr_bbbb", "client:dcr_bbbb:read"},
		{"", ""},
	} {
		ac := session(tc.clientID)
		cfg.refreshSessionGrants(context.Background(), ac, ex)
		ents, err := ac.GetEntitlements()
		require.NoError(t, err)
		if tc.want == "" {
			assert.Empty(t, ents, "a browser session gets no client's grants")
		} else {
			assert.Equal(t, []string{tc.want}, ents, "client %s", tc.clientID)
		}
		got, _ := ac[ClaimClientID].(string)
		assert.Equal(t, tc.clientID, got, "the session keeps its own client")
	}
}

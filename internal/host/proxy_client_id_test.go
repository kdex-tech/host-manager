package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// The FAT names the client its caller's credential was issued to, in the RFC
// 9068 client_id claim; a backend partitions per-client state by it, so no
// function claimMappings rule may write it. See kdex-tech/host-manager#295.

// TestProxyFAT_BridgedPATCarriesClientID: a bridged API token acts as its own
// client, "pat:<jti>", and a FAT exchanged from that FAT carries it on.
func TestProxyFAT_BridgedPATCarriesClientID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	exCfg := kindsClientConfig()
	exCfg.ActivePair = &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: crypto.Signer(priv)}
	exCfg.Issuer = "https://api-host.example.com"
	exCfg.Audience = apitokenBridgeHostAudience
	exCfg.TokenTTL = time.Hour

	idp := kindsRoleProvider(t)
	fn := apiKeySecuredFunction("/v1/api", true)
	fn.Spec.ClaimMappings = []dmapper.MappingRule{{SourceExpression: `"forged-client"`, TargetPropPath: auth.ClaimClientID}}
	handler, tm, fatHeader, _ := apitokenBridgeFixtureFor(t, fn, idp, exCfg, nil)
	pat, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "alice", kdexv1alpha1.SubjectKindUser, "laptop", "s", time.Hour)
	require.NoError(t, err)
	want := "pat:" + apitoken.GenerateJTI(apitokenBridgeHostAudience, "alice", "laptop")

	req := httptest.NewRequest(http.MethodGet, "/v1/api", nil)
	req.Header.Set("X-API-TOKEN", pat)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, want, decodeFAT(t, *fatHeader)[auth.ClaimClientID],
		"the bridged PAT's FAT names the key as its client, whatever a function rule says")

	ex, err := auth.NewExchanger(t.Context(), exCfg, nil, idp, nil)
	require.NoError(t, err)
	ts, err := ex.ExchangeSubjectToken(strings.TrimPrefix(*fatHeader, "Bearer "), "https://fn-b.example")
	require.NoError(t, err)
	assert.Equal(t, want, decodeFAT(t, "Bearer "+ts.AccessToken)[auth.ClaimClientID],
		"the exchanged token carries the client on")
}

// TestProxyFAT_SessionCarriesClientID: a JWT caller's context (here one the
// middleware built from a token issued to client dcr_abc) projects its
// client_id into the FAT, and a function rule cannot override it.
func TestProxyFAT_SessionCarriesClientID(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	fn.Spec.ClaimMappings = []dmapper.MappingRule{{SourceExpression: `"forged-client"`, TargetPropPath: auth.ClaimClientID}}
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, _, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)

	ctx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub": "alice", auth.ClaimClientID: "dcr_abc", "entitlements": []any{"functions:read"},
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/api", nil).WithContext(ctx)
	handler.ServeHTTP(httptest.NewRecorder(), req)
	assert.Equal(t, "dcr_abc", decodeFAT(t, *fatHeader)[auth.ClaimClientID])
}

// capabilityFATClientID is the client_id of the FAT a function, whose rule
// tries to write a forged client, is called with under the capability context
// ac (the gate's claims of a bearer capability, or a transfer redemption's).
func capabilityFATClientID(t *testing.T, ac auth.AuthContext) any {
	t.Helper()
	fn := apiKeySecuredFunction("/v1/api", true)
	fn.Spec.ClaimMappings = []dmapper.MappingRule{{SourceExpression: `"forged-client"`, TargetPropPath: auth.ClaimClientID}}
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	handler, _, fatHeader, _ := apitokenBridgeFixture(t, fn, idp)
	req := httptest.NewRequest(http.MethodGet, "/v1/api", nil).WithContext(auth.SetAuthContext(t.Context(), ac))
	handler.ServeHTTP(httptest.NewRecorder(), req)
	return decodeFAT(t, *fatHeader)[auth.ClaimClientID]
}

// TestCapabilityToken_CarriesCapClientID: a bearer capability is issued to no
// OAuth client, so it acts as its own, "cap:<jti>" -- never one a backend
// would take from the caller -- and the FAT minted for it carries that,
// whatever a function rule says.
func TestCapabilityToken_CarriesCapClientID(t *testing.T) {
	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
	ac := auth.AuthContext{
		"sub": "alice", "entitlements": []any{capKindEntitlement}, auth.ClaimSubjectKind: "User",
		auth.ClaimClientID: "dcr_minter",
	}
	r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath,
		mintReq(t, MintTokenRequest{Entitlements: []string{capKindEntitlement}}))
	r = r.WithContext(auth.SetAuthContext(r.Context(), ac))
	rw := httptest.NewRecorder()
	hh.capabilityMintHandler(rw, r)
	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
	var res MintTokenResult
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &res))

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(res.Token, claims)
	require.NoError(t, err)
	jti, _ := claims["jti"].(string)
	require.NotEmpty(t, jti)
	want := "cap:" + jti
	assert.Equal(t, want, claims[auth.ClaimClientID], "the capability names itself as its client")
	assert.Equal(t, want, capabilityFATClientID(t, auth.AuthContext(claims)),
		"the capability's FAT names it, whatever a function rule says")
}

// TestTransferLink_CarriesCapClientID: a /-/transfer/ redemption is served
// under a context naming the link's capability, "cap:<jti>", as its client,
// and the FAT minted under it carries that, whatever a function rule says.
func TestTransferLink_CarriesCapClientID(t *testing.T) {
	hh := newTestHostHandlerForProxy(t, testURLAuthConfig(t))
	mux := http.NewServeMux()
	var saw auth.AuthContext
	mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
		saw, _ = auth.GetAuthContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	hh.Mux = mux
	hh.transferHandler(mux, map[string]ko.PathInfo{})

	res, err := hh.mintCapabilityToken(t.Context(), "alice", kdexv1alpha1.SubjectKindUser, []string{capKindEntitlement},
		MintTokenRequest{
			Entitlements: []string{capKindEntitlement},
			Delivery:     deliveryURL,
			Target:       &TransferTarget{Method: http.MethodGet, Path: "/api/v1/files/abc/content"},
		}, "https://dev.example")
	require.NoError(t, err)
	path := res.URL[strings.Index(res.URL, "/-/transfer/"):]
	rec, ok := hh.loadTransferRecord(t.Context(), strings.TrimPrefix(path, "/-/transfer/"))
	require.True(t, ok)
	require.NotEmpty(t, rec.JTI)

	redeem := httptest.NewRecorder()
	mux.ServeHTTP(redeem, httptest.NewRequest(http.MethodGet, path, nil))
	require.Equal(t, http.StatusOK, redeem.Code, redeem.Body.String())
	want := "cap:" + rec.JTI
	assert.Equal(t, want, saw[auth.ClaimClientID], "the redemption names the link as its client")
	assert.Equal(t, want, capabilityFATClientID(t, saw),
		"the link's FAT names it, whatever a function rule says")
}

package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/keys"
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

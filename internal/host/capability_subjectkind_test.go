package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A capability (a mint_token bearer token, or a /-/transfer/ link) carries
// the kind of the credential that minted it (ContextSubjectKind), as every
// other credential the host issues does, so nothing classifies it by name
// later. See kdex-tech/host-manager#255.

const capKindEntitlement = "pages:/:read"

// capKindCallers are the minting contexts: a carried kind of each kind, and
// a kind-less client_credentials context, whose kind ContextSubjectKind
// derives from its grant rather than its name (LEGACY(#268)).
func capKindCallers() map[string]struct {
	ac   auth.AuthContext
	want kdexv1alpha1.SubjectKind
} {
	ents := []any{capKindEntitlement}
	return map[string]struct {
		ac   auth.AuthContext
		want kdexv1alpha1.SubjectKind
	}{
		"a client": {auth.AuthContext{
			"sub": "svc", "entitlements": ents, auth.ClaimSubjectKind: "Client",
		}, kdexv1alpha1.SubjectKindClient},
		"a user": {auth.AuthContext{
			"sub": "alice", "entitlements": ents, auth.ClaimSubjectKind: "User",
		}, kdexv1alpha1.SubjectKindUser},
		"a kind-less client_credentials context": {auth.AuthContext{ // LEGACY(#268)
			"sub": "svc", "entitlements": ents, "grant_type": auth.GRANT_TYPE_CLIENT_CREDENTIALS,
		}, kdexv1alpha1.SubjectKindClient},
	}
}

// capTokenKind is the knd claim of a capability token.
func capTokenKind(t *testing.T, token string) any {
	t.Helper()
	require.NotEmpty(t, token, "no token was minted")
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	return claims[auth.ClaimSubjectKind]
}

func TestCapabilityToken_CarriesCallerKind(t *testing.T) {
	for name, tc := range capKindCallers() {
		t.Run("REST: "+name, func(t *testing.T) {
			hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
			r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath,
				mintReq(t, MintTokenRequest{Entitlements: []string{capKindEntitlement}}))
			r = r.WithContext(auth.SetAuthContext(r.Context(), tc.ac))
			rw := httptest.NewRecorder()
			hh.capabilityMintHandler(rw, r)
			require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

			var res MintTokenResult
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &res))
			assert.Equal(t, string(tc.want), capTokenKind(t, res.Token))
		})

		t.Run("MCP: "+name, func(t *testing.T) {
			hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)
			fn := newServiceBackedMCPFunction(t, upstream.URL)
			hh.functions = []kdexv1alpha1.KDexFunction{*fn}

			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mint_token","arguments":{"entitlements":["` + capKindEntitlement + `"]}}}`
			r := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(auth.SetAuthContext(r.Context(), tc.ac))
			rr := httptest.NewRecorder()
			hh.reverseProxyHandler(fn, mintProxyIssuer).ServeHTTP(rr, r)
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

			var resp struct {
				Result struct {
					IsError           bool            `json:"isError"`
					StructuredContent MintTokenResult `json:"structuredContent"`
				} `json:"result"`
			}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
			require.False(t, resp.Result.IsError, rr.Body.String())
			assert.Equal(t, string(tc.want), capTokenKind(t, resp.Result.StructuredContent.Token))
		})
	}
}

// TestTransferLink_CarriesCallerKind: redeeming a /-/transfer/ link injects
// the minting caller's kind with its sub, into the context the bound target
// is served under.
func TestTransferLink_CarriesCallerKind(t *testing.T) {
	for name, tc := range capKindCallers() {
		t.Run(name, func(t *testing.T) {
			hh := newTestHostHandlerForProxy(t, testURLAuthConfig(t))
			mux := http.NewServeMux()
			var saw auth.AuthContext
			mux.HandleFunc("GET /api/v1/files/", func(w http.ResponseWriter, r *http.Request) {
				saw, _ = auth.GetAuthContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			hh.Mux = mux
			hh.transferHandler(mux, map[string]ko.PathInfo{})

			r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath, mintReq(t, MintTokenRequest{
				Entitlements: []string{capKindEntitlement},
				Delivery:     deliveryURL,
				Target:       &TransferTarget{Method: http.MethodGet, Path: "/api/v1/files/abc/content"},
			}))
			r = r.WithContext(auth.SetAuthContext(r.Context(), tc.ac))
			rw := httptest.NewRecorder()
			hh.capabilityMintHandler(rw, r)
			require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())
			var res MintTokenResult
			require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &res))

			redeem := httptest.NewRecorder()
			mux.ServeHTTP(redeem, httptest.NewRequest(http.MethodGet, res.URL[strings.Index(res.URL, "/-/transfer/"):], nil))
			require.Equal(t, http.StatusOK, redeem.Code, redeem.Body.String())
			require.NotNil(t, saw, "the bound target saw no auth context")
			assert.Equal(t, tc.ac["sub"], saw["sub"])
			assert.Equal(t, string(tc.want), saw[auth.ClaimSubjectKind])
		})
	}
}

package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestIsWhoamiCall_MatchesOnlyItsOwnTool mirrors isMintTokenCall's contract:
// a single JSON-RPC tools/call for this tool is intercepted; anything else
// passes through to the backend untouched.
func TestIsWhoamiCall_MatchesOnlyItsOwnTool(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"whoami call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}`, true},
		{"different tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"mint_token"}}`, false},
		{"different method", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, false},
		{"batch array is not intercepted", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami"}}]`, false},
		{"not json", `whoami please`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, matched := isWhoamiCall([]byte(tc.body))
			assert.Equal(t, tc.want, matched)
		})
	}
}

// TestWhoamiFromAuthContext_ReportsTheCredential is the core contract: whoami
// describes the authority the PRESENTED credential actually carries, not the
// person behind it.
//
// That is what makes it safe to expose. A minted capability token is attenuated
// on purpose; re-resolving the subject's full entitlements here would disclose
// the shape of an authority the token was deliberately not granted.
func TestWhoamiFromAuthContext_ReportsTheCredential(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":                "rayauge@doublebite.com",
		"email":              "rayauge@doublebite.com",
		"name":               "Raymond Augé",
		"given_name":         "Raymond",
		"family_name":        "Augé",
		"preferred_username": "rayauge",
		"entitlements":       []string{"vector_stores:vs_abc:read"},
	})

	require.NoError(t, err)
	assert.Equal(t, "rayauge@doublebite.com", res.Identity)
	assert.Equal(t, "Raymond Augé", res.Name)
	assert.Equal(t, "Raymond", res.GivenName)
	assert.Equal(t, "Augé", res.FamilyName)
	assert.Equal(t, "rayauge", res.PreferredUsername)
	assert.Equal(t, []string{"vector_stores:vs_abc:read"}, res.Entitlements)
}

// TestWhoamiFromAuthContext_OmitsAbsentProfileFields pins the "if present"
// rule, which is not cosmetic: name/given_name/family_name/email are
// scope-gated by confineByScope, so an OAuth2 caller whose token lacks
// profile/email simply does not carry them. Reporting them anyway would mean
// re-resolving server-side and handing back profile data the credential was
// deliberately not granted.
func TestWhoamiFromAuthContext_OmitsAbsentProfileFields(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":          "svc-account",
		"entitlements": []string{"functions:/api/v1/mcp:read"},
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(res)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))

	for _, absent := range []string{"name", "given_name", "family_name", "preferred_username"} {
		assert.NotContains(t, got, absent,
			"a profile field the credential does not carry must be omitted, not emitted empty")
	}
	assert.Contains(t, got, "entitlements")
}

// TestWhoamiFromAuthContext_IdentityFallsBackToSubject: identity is the email,
// but email is scope-gated. Falling back to sub keeps the tool useful for a
// caller whose token carries no email claim rather than reporting no identity
// at all.
func TestWhoamiFromAuthContext_IdentityFallsBackToSubject(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":          "internal-test",
		"entitlements": []string{"functions:/api/v1/mcp:read"},
	})

	require.NoError(t, err)
	assert.Equal(t, "internal-test", res.Identity,
		"with no email claim the subject is the best available identity")
}

// TestWhoamiFromAuthContext_RequiresAnAuthenticatedCaller mirrors
// mintCapabilityToken: an anonymous caller gets an error, not an empty record
// that looks like a successful answer about nobody.
func TestWhoamiFromAuthContext_RequiresAnAuthenticatedCaller(t *testing.T) {
	_, err := whoamiFromAuthContext(auth.AuthContext{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "authenticated")
}

// TestWhoamiFromAuthContext_EmptyEntitlementsSerializeAsAnArray guards the
// consumer contract: an authenticated caller holding nothing must produce
// `"entitlements": []`, never `null`, so a client can iterate without a nil
// check.
func TestWhoamiFromAuthContext_EmptyEntitlementsSerializeAsAnArray(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{"sub": "alice"})
	require.NoError(t, err)

	encoded, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), `"entitlements":[]`)
}

// TestReverseProxy_InterceptsWhoamiCall proves whoami is answered by the
// authorization server and NEVER forwarded upstream — the same contract
// mint_token has. The backend has no idea who the caller is; only the AS does.
func TestReverseProxy_InterceptsWhoamiCall(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	hh := newTestHostHandlerForProxy(t, testAuthConfigForMint(t))
	fn := newServiceBackedMCPFunction(t, upstream.URL)
	hh.functions = []kdexv1alpha1.KDexFunction{*fn}
	handler := hh.reverseProxyHandler(fn, mintProxyIssuer)

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"whoami"}}`
	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "email": "alice@example.test", "name": "Alice A",
		"entitlements": []any{"pages:/:read"},
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.False(t, upstreamHit, "whoami must be answered locally, never forwarded to the backend")
	require.Equal(t, http.StatusOK, rr.Code)

	var resp jsonRPCResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	require.NotNil(t, resp.Result)

	// The structured payload must carry the caller's own identity.
	raw, err := json.Marshal(resp.Result)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "alice@example.test")
}

// TestSpliceIncludesWhoamiDescriptor: whoami has to be discoverable, or an
// agent never learns it exists. It rides the same tools/list splice as
// mint_token.
func TestSpliceIncludesWhoamiDescriptor(t *testing.T) {
	in := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"existing"}]}}`)

	out, ok := spliceMintTokenDescriptor(in, "https://dev.example/-/openapi")
	require.True(t, ok)

	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(out, &env))

	names := make([]string, 0, len(env.Result.Tools))
	for _, tool := range env.Result.Tools {
		names = append(names, tool.Name)
	}
	assert.Contains(t, names, "existing", "the backend's own tools must survive")
	assert.Contains(t, names, "mint_token")
	assert.Contains(t, names, "whoami")
}

// TestMergeResolvedClaims_FleshesOutTheContext pins how whoami fills profile
// fields. They are scope-gated (confineByScope strips name/given_name/
// family_name/email when the token lacks profile/email), so reading only what
// the credential carries would leave whoami blank for perfectly valid callers.
//
// Instead the subject's backend claims are resolved through the NON-LOGIN
// Lookup path — Exchanger.ResolveSubjectClaims, which sits behind the 60s
// subject-resolve cache, the same password-less resolution the PAT bridge uses
// (#138).
func TestMergeResolvedClaims_FleshesOutTheContext(t *testing.T) {
	ac := mergeResolvedClaims(
		auth.AuthContext{"sub": "alice", "entitlements": []string{"pages:/:read"}},
		jwt.MapClaims{"email": "alice@example.test", "name": "Alice A", "given_name": "Alice"},
	)

	res, err := whoamiFromAuthContext(ac)
	require.NoError(t, err)

	assert.Equal(t, "alice@example.test", res.Identity)
	assert.Equal(t, "Alice A", res.Name)
	assert.Equal(t, "Alice", res.GivenName)
	assert.Equal(t, []string{"pages:/:read"}, res.Entitlements,
		"entitlements stay CREDENTIAL-scoped; only profile is resolved")
}

// TestMergeResolvedClaims_TokenClaimsWin: the merge is non-destructive, exactly
// as the PAT bridge does it. A claim the credential actually carries is the
// authoritative one — a resolved value must never overwrite it.
func TestMergeResolvedClaims_TokenClaimsWin(t *testing.T) {
	ac := mergeResolvedClaims(
		auth.AuthContext{"sub": "alice", "email": "from-token@example.test"},
		jwt.MapClaims{"email": "from-lookup@example.test"},
	)

	res, err := whoamiFromAuthContext(ac)
	require.NoError(t, err)
	assert.Equal(t, "from-token@example.test", res.Identity,
		"a claim the credential carries must not be overwritten by the lookup")
}

// TestMergeResolvedClaims_NilResolutionIsSafe: ResolveSubjectClaims returns nil
// when no lookup supplies backend claims (test stubs, providers without the
// optional capability). That must degrade to the credential's own view.
func TestMergeResolvedClaims_NilResolutionIsSafe(t *testing.T) {
	ac := mergeResolvedClaims(auth.AuthContext{"sub": "alice"}, nil)

	res, err := whoamiFromAuthContext(ac)
	require.NoError(t, err)
	assert.Equal(t, "alice", res.Identity)
}

package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
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
			req, ok := parseSingleJSONRPC([]byte(tc.body))
			matched := false
			if ok {
				_, matched = isWhoamiCall(req)
			}
			assert.Equal(t, tc.want, matched)
		})
	}
}

// TestWhoamiFromAuthContext_ProjectsTheContext covers the identity/profile
// projection. Entitlements at this stage are what the context CARRIES; the
// effective set is applied separately by applyEffectiveEntitlements.
func TestWhoamiFromAuthContext_ProjectsTheContext(t *testing.T) {
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

	out, ok := spliceASToolDescriptors(in, "https://dev.example/-/openapi")
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

// TestWhoamiFromAuthContext_HonoursScopeForProfileFields pins the privacy
// contract: profile fields are reported ONLY when the presented credential
// actually carries them.
//
// confineByScope deletes name/given_name/family_name/email at signing time when
// the client was not granted profile/email. Re-resolving them from the identity
// backend would hand a third-party client personal data the user deliberately
// withheld when authorizing it — routing around the consent mechanism rather
// than honouring it.
//
// Entitlements are exempt and stay wide: they are the caller's own authority,
// not personal data, and reporting them is what the tool exists for.
func TestWhoamiFromAuthContext_HonoursScopeForProfileFields(t *testing.T) {
	// A client authorized with "openid entitlements" only: no profile, no email.
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":          "alice@example.test",
		"scope":        "openid entitlements",
		"entitlements": []string{"pages:/:read"},
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(res)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))

	for _, withheld := range []string{"name", "given_name", "family_name", "preferred_username"} {
		assert.NotContains(t, got, withheld,
			"a profile field the credential does not carry must not be resolved behind the scope")
	}
	assert.Equal(t, []any{"pages:/:read"}, got["entitlements"],
		"entitlements are exempt from the scope rule and must still be reported")
}

// TestWhoamiFromAuthContext_ReportsProfileTheCredentialCarries is the other
// half: when the claims ARE present — a scope that granted them, or a PAT whose
// proxy bridge already enriched the context — they must be reported.
func TestWhoamiFromAuthContext_ReportsProfileTheCredentialCarries(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":                "alice@example.test",
		"email":              "alice@example.test",
		"name":               "Alice Alpha",
		"given_name":         "Alice",
		"family_name":        "Alpha",
		"preferred_username": "alice",
		"scope":              "openid profile email",
		"entitlements":       []string{"pages:/:read"},
	})
	require.NoError(t, err)

	assert.Equal(t, "Alice Alpha", res.Name)
	assert.Equal(t, "Alice", res.GivenName)
	assert.Equal(t, "Alpha", res.FamilyName)
	assert.Equal(t, "alice", res.PreferredUsername)
}

// TestWhoamiResult_IdentityAndEntitlementsAreMandatory: whatever the scope, the
// caller must always learn WHO the server thinks they are and WHAT they may do.
// Those two fields are the tool's entire purpose, so neither may be omitted —
// identity falls back to the subject, which every credential carries.
func TestWhoamiResult_IdentityAndEntitlementsAreMandatory(t *testing.T) {
	res, err := whoamiFromAuthContext(auth.AuthContext{
		"sub":   "svc-account",
		"scope": "openid",
	})
	require.NoError(t, err)

	encoded, err := json.Marshal(res)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))

	require.Contains(t, got, "identity", "identity must always be present")
	assert.Equal(t, "svc-account", got["identity"],
		"with no email claim the subject is the identity; the credential already carries it")
	require.Contains(t, got, "entitlements", "entitlements must always be present")
	assert.Equal(t, []any{}, got["entitlements"], "an empty set serializes as [], never null or absent")
}

// TestEffectiveEntitlements_UnionsCarriedWithResolved is the core contract, and
// the fix for a defect the quad review caught.
//
// The two inputs are DIFFERENT SETS, neither a superset of the other:
//
//   - CARRIED is the request's auth context, which on the proxy path has already
//     been through EnrichAuthContext (proxy.go:547, before this interception at
//     :633). The knowdrive dev host's claimMappings union `self.vs_entitlements`
//     — the per-vector-store grants resolved by the credential-check Lookup —
//     into it. mint_token reads exactly this set as `held`.
//   - RESOLVED is ResolveInternalRolesAndEntitlements, i.e. KDexRoleBinding
//     grants only. It never contains the vs_entitlements.
//
// Replacing carried with resolved therefore DROPPED precisely the
// per-vector-store entitlements an agent needs, and reported a set SMALLER than
// mint_token would accept — sending the agent back into the guess-and-retry
// loop whoami exists to end.
func TestEffectiveEntitlements_UnionsCarriedWithResolved(t *testing.T) {
	res := applyEffectiveEntitlements(
		// Carried: enriched, includes a vs_entitlements grant.
		WhoamiResult{Entitlements: []string{
			"functions:/api/v1/mcp:read",
			"vector_stores:vs_abc:write",
		}},
		// Resolved: role bindings only — no vs_entitlements.
		[]string{"functions:/api/v1/mcp:read", "pages:/:read"},
	)

	assert.ElementsMatch(t, []string{
		"functions:/api/v1/mcp:read",
		"vector_stores:vs_abc:write",
		"pages:/:read",
	}, res.Entitlements,
		"neither input is a superset: the claimMappings-enriched grants and the role-derived "+
			"grants must BOTH be reported")
}

// TestEffectiveEntitlements_NeverDropsACarriedGrant is the regression guard for
// the specific failure above, stated as an invariant: whatever the credential
// carries is exercisable right now, so it can never be absent from the report.
func TestEffectiveEntitlements_NeverDropsACarriedGrant(t *testing.T) {
	carried := []string{"vector_stores:vs_only_in_context:read"}

	res := applyEffectiveEntitlements(
		WhoamiResult{Entitlements: carried},
		[]string{"pages:/:read"},
	)

	assert.Contains(t, res.Entitlements, "vector_stores:vs_only_in_context:read",
		"a grant the credential demonstrably carries must never be dropped from the report")
}

// TestEffectiveEntitlements_AttenuatedTokenStillReportsTheUser: an attenuated
// capability token is no exception. It cannot EXERCISE the wider set, but
// whoami answers "what can I do", not "what can this token do" — and it hands
// out no authority by answering.
func TestEffectiveEntitlements_AttenuatedTokenStillReportsTheUser(t *testing.T) {
	res := applyEffectiveEntitlements(
		WhoamiResult{Entitlements: []string{"vector_stores:vs_abc:read"}},
		[]string{"vector_stores:vs_abc:read", "vector_stores:vs_abc:write", "pages:/:read"},
	)

	assert.Len(t, res.Entitlements, 3,
		"an attenuated token must not narrow the REPORT of what its user can do")
}

// TestEffectiveEntitlements_FlagsWhatThisTokenCannotExercise: because the
// report is now wider than the credential, a caller could reasonably try
// something the gate will deny. The flag says so, and the hint explains it.
func TestEffectiveEntitlements_FlagsWhatThisTokenCannotExercise(t *testing.T) {
	res := applyEffectiveEntitlements(
		WhoamiResult{Entitlements: []string{"pages:/:read"}},
		[]string{"pages:/:read", "vector_stores:vs_abc:write"},
	)

	assert.True(t, res.EntitlementsWithheld,
		"this credential carries less than the user holds; a caller must be able to see that")
	assert.NotEmpty(t, res.Hint)
}

// TestEffectiveEntitlements_NoFlagWhenTheTokenCarriesEverything: the common
// healthy case — a PAT whose bridge already resolved the full set. Nothing to
// warn about, so no flag and no hint noise. Carried-but-not-resolved grants
// (the vs_entitlements case) must NOT trip the flag either: they are
// exercisable, so nothing is being withheld.
func TestEffectiveEntitlements_NoFlagWhenTheTokenCarriesEverything(t *testing.T) {
	res := applyEffectiveEntitlements(
		WhoamiResult{Entitlements: []string{
			"pages:/:read", "vector_stores:vs_abc:read", "vector_stores:vs_extra:write",
		}},
		[]string{"vector_stores:vs_abc:read", "pages:/:read"},
	)

	assert.False(t, res.EntitlementsWithheld,
		"a grant present in the credential but absent from the role set is exercisable, not withheld")
	assert.Empty(t, res.Hint)
}

// TestEffectiveEntitlements_UnresolvableFallsBackToCarried: ResolveInternal-
// RolesAndEntitlements returns nothing for a subject with no bindings, and
// stub providers return nothing at all. Neither may erase what the credential
// demonstrably carries.
func TestEffectiveEntitlements_UnresolvableFallsBackToCarried(t *testing.T) {
	res := applyEffectiveEntitlements(
		WhoamiResult{Entitlements: []string{"pages:/:read"}},
		nil,
	)

	assert.Equal(t, []string{"pages:/:read"}, res.Entitlements)
	assert.False(t, res.EntitlementsWithheld)
}

// TestReverseProxy_WhoamiWiresEffectiveEntitlements is the WIRING guard.
//
// applyEffectiveEntitlements has unit tests; its call site had none.
// TestReverseProxy_InterceptsWhoamiCall cannot serve as one — it builds the
// handler with a zero-value stubInternalIdentityProvider, so `resolved` comes
// back empty and applyEffectiveEntitlements short-circuits before doing
// anything. Nothing proved entitlements_withheld or hint ever reach the wire.
//
// That is the same "correct but never called" shape TestNew_AppliesTheClamp
// rejects for Timeouts.Normalized, and it was found by the quad review.
func TestReverseProxy_WhoamiWiresEffectiveEntitlements(t *testing.T) {
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cm, err := cache.NewCacheManager("", "whoami-wiring-test", nil)
	require.NoError(t, err)

	// A provider that actually resolves grants, so `resolved` is non-empty.
	idp := stubInternalIdentityProvider{
		roles: []string{"reader"},
		ents:  []string{"pages:/:read", "vector_stores:vs_role:read"},
	}
	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cm, idp)
	require.NoError(t, err)

	cfg := testAuthConfigForMint(t)
	fn := newServiceBackedMCPFunction(t, upstream.URL)
	hh := &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		cacheManager:  cm,
		authChecker:   &entitlementGateChecker{},
		host:          &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{mintProxyDomain}}},
		functions:     []kdexv1alpha1.KDexFunction{*fn},
		authConfig:    cfg,
		authExchanger: ex,
	}
	handler := hh.reverseProxyHandler(fn, mintProxyIssuer)

	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"whoami"}}`
	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Carries ONLY a vector-store grant, as a claimMappings-enriched context
	// would; the role set carries different ones.
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice", "email": "alice@example.test",
		"entitlements": []any{"vector_stores:vs_from_context:write"},
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Result struct {
			StructuredContent WhoamiResult `json:"structuredContent"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	got := resp.Result.StructuredContent

	assert.Contains(t, got.Entitlements, "vector_stores:vs_from_context:write",
		"the carried (claimMappings-enriched) grant must survive to the wire")
	assert.Contains(t, got.Entitlements, "pages:/:read",
		"the role-resolved grants must reach the wire — proving the call site runs at all")
	assert.True(t, got.EntitlementsWithheld,
		"the role set holds grants this credential does not carry; the flag must reach the wire")
	assert.NotEmpty(t, got.Hint, "the hint must reach the wire alongside the flag")
}

// resolvingIdentityProvider resolves backend profile claims password-lessly,
// which is what ResolveSubjectClaims reaches when the host has a resolve
// endpoint wired. The stub used elsewhere does not implement ResolveClaims at
// all, so it can never exercise this path.
type resolvingIdentityProvider struct{ stubInternalIdentityProvider }

func (resolvingIdentityProvider) ResolveClaims(string) jwt.MapClaims {
	return jwt.MapClaims{
		"email":       "alice@example.test",
		"name":        "Alice Alpha",
		"given_name":  "Alice",
		"family_name": "Alpha",
	}
}

// TestReverseProxy_WhoamiDoesNotResolvePIIBehindTheScope is the handler-level
// privacy guard, and the one that matters: whoamiFromAuthContext is pure over
// the context and was never the leak — writeWhoamiRPC's own resolution was.
//
// A client authorized with "openid entitlements" has had its profile/email
// claims deleted by confineByScope. Resolving them back from the identity
// backend hands that client personal data the user withheld when authorizing
// it, defeating the consent mechanism rather than honouring it.
func TestReverseProxy_WhoamiDoesNotResolvePIIBehindTheScope(t *testing.T) {
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cm, err := cache.NewCacheManager("", "whoami-pii-test", nil)
	require.NoError(t, err)
	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cm, resolvingIdentityProvider{
		stubInternalIdentityProvider{roles: []string{"reader"}, ents: []string{"pages:/:read"}},
	})
	require.NoError(t, err)

	fn := newServiceBackedMCPFunction(t, upstream.URL)
	hh := &HostHandler{
		log: logr.Discard(), scheme: "https", cacheManager: cm,
		authChecker:   &entitlementGateChecker{},
		host:          &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{mintProxyDomain}}},
		functions:     []kdexv1alpha1.KDexFunction{*fn},
		authConfig:    testAuthConfigForMint(t),
		authExchanger: ex,
	}

	body := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"whoami"}}`
	req := httptest.NewRequest(http.MethodPost, mintProxyBasePath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Scope-limited: no profile, no email. The backend COULD resolve them.
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "alice@example.test", "scope": "openid entitlements",
		"entitlements": []any{"pages:/:read"},
	}))
	rec := httptest.NewRecorder()
	hh.reverseProxyHandler(fn, mintProxyIssuer).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Result struct {
			StructuredContent WhoamiResult `json:"structuredContent"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	got := resp.Result.StructuredContent

	assert.Empty(t, got.Name, "a withheld profile claim must not be resolved from the backend")
	assert.Empty(t, got.GivenName)
	assert.Empty(t, got.FamilyName)
	assert.NotEmpty(t, got.Entitlements, "entitlements are exempt and must still be reported")
	assert.Equal(t, "alice@example.test", got.Identity, "identity is mandatory")
}

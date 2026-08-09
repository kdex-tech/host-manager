package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	patHostAudience = "https://host.example"
	patFunctionAud  = "https://fn-knowdb-mcp.example/api/v1/mcp"
)

// patHostIdentityProvider resolves a fixed role/entitlement set so the test can
// assert the PAT's identity was actually inflated, not merely accepted.
type patHostIdentityProvider struct{}

func (patHostIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}
func (patHostIdentityProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return []string{"reader"}, []string{"vector_stores:vs_abc:read"}, nil
}

// newHostPATFixture builds the middleware under test plus a TokenManager that
// can mint PATs for any audience, and returns the auth context the downstream
// handler observed (nil when the request stayed anonymous).
func newPATTestConfig(t *testing.T, cacheName string) (Config, *Exchanger, *apitoken.TokenManager) {
	t.Helper()

	cm, err := cache.NewCacheManager("", cacheName, nil)
	require.NoError(t, err)

	tm, err := apitoken.NewTokenManager(
		"test-issuer",
		apitoken.GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}),
	)
	require.NoError(t, err)

	cfg := Config{
		Issuer:       "test-issuer",
		Audience:     patHostAudience,
		CookieName:   "auth_token",
		TokenManager: tm,
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, patHostIdentityProvider{})
	require.NoError(t, err)

	return cfg, ex, tm
}

func newHostPATFixture(t *testing.T) (http.Handler, *apitoken.TokenManager, *AuthContext) {
	t.Helper()
	cfg, ex, tm := newPATTestConfig(t, "pat-host-test")

	var seen AuthContext
	observed := &seen

	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ac, ok := GetAuthContext(r.Context()); ok {
			*observed = ac
		}
		w.WriteHeader(http.StatusOK)
	})

	// Production composition for an OPTED-IN route: the global middleware runs
	// first (and passes the PAT through), then the opt-in wrapper fills the gap.
	h := cfg.WithAPITokenIdentity(ex)(cfg.WithAuthentication(ex)(sink))

	return h, tm, observed
}

// newGlobalOnlyPATFixture is the composition every NON-opted-in route gets:
// WithAuthentication alone, with no API-token opt-in.
func newGlobalOnlyPATFixture(t *testing.T) (http.Handler, *apitoken.TokenManager, *AuthContext) {
	t.Helper()
	cfg, ex, tm := newPATTestConfig(t, "pat-global-test")

	var seen AuthContext
	observed := &seen
	sink := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ac, ok := GetAuthContext(r.Context()); ok {
			*observed = ac
		}
		w.WriteHeader(http.StatusOK)
	})

	return cfg.WithAuthentication(ex)(sink), tm, observed
}

// TestWithAuthentication_HostAudiencePATStaysAnonymous is the guard for the
// blast-radius half of the kdex-tech/host-manager#175 review.
//
// WithAuthentication wraps the ENTIRE mux, so anything it authenticates becomes
// an identity everywhere — including /-/oauth/authorize, which gates purely on
// the presence of an auth context and would hand a PAT holder an authorization
// code redeemable for a JWT and a rotating refresh token (escaping the PAT's own
// jti revocation), and /-/apitokens/mint, which mints for a caller-supplied
// subject.
//
// It also displaced the proxy PAT bridge, whose PATBridgeClaim marker aa73843
// depends on. A PAT must therefore stay anonymous here; routes that want the
// identity opt in via WithAPITokenIdentity.
func TestWithAuthentication_HostAudiencePATStaysAnonymous(t *testing.T) {
	h, tm, observed := newGlobalOnlyPATFixture(t)

	pat, err := tm.MintStatelessKey(patHostAudience, "alice@example.com", "read", "", time.Hour)
	require.NoError(t, err)

	rec := doPATRequest(t, h, pat)

	assert.Equal(t, http.StatusOK, rec.Code, "a PAT must pass through, not 401")
	assert.Nil(t, *observed,
		"the global middleware must NOT turn a PAT into an identity: it would reach "+
			"/-/oauth/authorize and /-/apitokens/mint, and would displace the proxy PAT bridge")
}

func doPATRequest(t *testing.T, h http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/-/check", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestWithAPITokenIdentity_HostAudiencePATBecomesAnIdentity pins the ruling for
// kdex-tech/host-manager#175 on an OPTED-IN route: a PAT carrying the HOST's own
// audience is a valid identity there.
//
// Before #175, every PAT was passed through anonymously and only the function
// proxy bridge ever authenticated one — so an API-key caller reaching a
// non-proxied endpoint like /-/check was indistinguishable from an anonymous
// one, and /-/check reported it held nothing.
func TestWithAPITokenIdentity_HostAudiencePATBecomesAnIdentity(t *testing.T) {
	h, tm, observed := newHostPATFixture(t)

	pat, err := tm.MintStatelessKey(patHostAudience, "alice@example.com", "read", "", time.Hour)
	require.NoError(t, err)

	rec := doPATRequest(t, h, pat)
	require.Equal(t, http.StatusOK, rec.Code)

	require.NotNil(t, *observed, "a host-audience PAT must reach the handler as an identity, not anonymously")
	assert.Equal(t, "alice@example.com", (*observed)["sub"])

	ents, err := observed.GetEntitlements()
	require.NoError(t, err)
	assert.Contains(t, ents, "vector_stores:vs_abc:read",
		"the PAT subject's entitlements must be resolved onto the context, or the identity gate still reads an empty bearer bucket")
}

// TestWithAuthentication_FunctionBoundPATStaysAnonymous is the security-critical
// half of the ruling, and the reason the audience is checked rather than the
// token merely being parsed.
//
// A resource-bound PAT names a specific function URL in its audience — that
// binding is exactly what aa73843 established (resource binding is a property of
// the TOKEN, not of the endpoint). Accepting one at a host-level endpoint would
// let a token minted for one function act as a general host identity: a
// confused-deputy escalation. It must continue to pass through anonymously so
// the function proxy bridge can validate it against the target's own audience.
func TestWithAPITokenIdentity_FunctionBoundPATStaysAnonymous(t *testing.T) {
	h, tm, observed := newHostPATFixture(t)

	pat, err := tm.MintStatelessKey(patFunctionAud, "alice@example.com", "read", "", time.Hour)
	require.NoError(t, err)

	rec := doPATRequest(t, h, pat)

	assert.Equal(t, http.StatusOK, rec.Code,
		"a function-bound PAT must not be rejected outright — the proxy bridge still needs to see it")
	assert.Nil(t, *observed,
		"a PAT bound to a FUNCTION audience must NOT become a host identity; accepting it here is a confused-deputy escalation")
}

// TestWithAuthentication_UnusablePATStaysAnonymous covers the remaining ways a
// PAT can fail to be a host identity. None may 401: the request has to stay
// anonymous so the proxy bridge and the gate decide, which is the pre-existing
// contract this change must not alter.
func TestWithAPITokenIdentity_UnusablePATStaysAnonymous(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token func(tm *apitoken.TokenManager) string
	}{
		{
			name:  "malformed",
			token: func(*apitoken.TokenManager) string { return "v4.public.not-a-real-token" },
		},
		{
			name: "expired host-audience token",
			token: func(tm *apitoken.TokenManager) string {
				tok, err := tm.MintStatelessKey(patHostAudience, "alice@example.com", "read", "", -time.Hour)
				require.NoError(t, err)
				return tok
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, tm, observed := newHostPATFixture(t)

			rec := doPATRequest(t, h, tc.token(tm))

			assert.Equal(t, http.StatusOK, rec.Code, "an unusable PAT must not 401; it stays anonymous")
			assert.Nil(t, *observed, "an unusable PAT must not produce an identity")
		})
	}
}

// TestWithAuthentication_PATCannotReachAuthorizeIdentity is the end-to-end
// statement of why the identity is opt-in rather than global.
//
// /-/oauth/authorize gates on nothing but the PRESENCE of an auth context. When
// WithAuthentication authenticated PATs for the whole mux, a developer key
// presented there produced a 302 carrying an authorization code — redeemable at
// /-/token for a JWT and a rotating refresh token. That derived session escapes
// the PAT's own jti revocation entirely (apitoken.ValidateToken checks the
// revocation cache; a refresh lineage does not), ignores the PAT's scope, and
// makes /-/apitokens/mint — which mints for a CALLER-SUPPLIED subject —
// reachable from an API key.
//
// The property that prevents all of it is simply: the global middleware leaves a
// PAT anonymous, so any handler gated on GetAuthContext sees nobody.
func TestWithAuthentication_PATCannotReachAuthorizeIdentity(t *testing.T) {
	h, tm, observed := newGlobalOnlyPATFixture(t)

	for _, tc := range []struct {
		name string
		aud  string
	}{
		{"host-audience developer key", patHostAudience},
		{"function-bound key", patFunctionAud},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*observed = nil
			pat, err := tm.MintStatelessKey(tc.aud, "alice@example.com", "read", "", time.Hour)
			require.NoError(t, err)

			doPATRequest(t, h, pat)

			assert.Nil(t, *observed,
				"no PAT may present as an identity to a handler that only gates on GetAuthContext")
		})
	}
}

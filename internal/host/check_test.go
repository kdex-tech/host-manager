package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHostHandler_CheckHandler(t *testing.T) {
	cacheManager, _ := cache.NewCacheManager("", "foo", nil)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)

	// Mock authChecker
	mockAC := &checkAuthChecker{
		parsedEntitlements: entitlements.ParsedEntitlements{},
	}
	hh.authChecker = mockAC

	tests := []struct {
		name           string
		checks         []string
		allowedChecks  map[string]bool
		expectedPassed []string
	}{
		{
			name: "basic check - all allowed",
			checks: []string{
				"pages:/foo:read",
				"functions:/bar:post",
			},
			allowedChecks: map[string]bool{
				"pages:/foo:read":     true,
				"functions:/bar:post": true,
			},
			expectedPassed: []string{
				"pages:/foo:read",
				"functions:/bar:post",
			},
		},
		{
			name: "some allowed",
			checks: []string{
				"pages:/foo:read",
				"functions:/bar:post",
			},
			allowedChecks: map[string]bool{
				"pages:/foo:read": true,
			},
			expectedPassed: []string{
				"pages:/foo:read",
			},
		},
		{
			name: "none allowed",
			checks: []string{
				"pages:/foo:read",
				"functions:/bar:post",
			},
			allowedChecks:  map[string]bool{},
			expectedPassed: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAC.allowed = tt.allowedChecks

			reqBody, _ := json.Marshal(CheckRequest{Checks: tt.checks})
			req := httptest.NewRequest("POST", "/-/check", bytes.NewBuffer(reqBody))
			w := httptest.NewRecorder()

			// Inject mock auth context
			ctx := auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "test-user"})
			req = req.WithContext(ctx)

			hh.CheckHandler(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			var resp CheckResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedPassed, resp.Passed)
		})
	}
}

// TestCheck_TestsChecksAgainstUserEntitlementsOnly pins the contract of /-/check:
// it is a batch entitlement-membership test. Each check string passes iff the
// caller holds a grant satisfying that exact <resource>:<resourceName>:<verb>,
// using ordinary entitlement matching (wildcards, verb-specificity). It does NOT
// consult a page's or function's resource-declared security -- the gate still
// enforces that on the real request. A registered function handler whose DELETE
// op declares users:*:admin (a scope the caller lacks) proves the declared
// requirement is irrelevant here: the caller passes on the function grant alone.
func TestCheck_TestsChecksAgainstUserEntitlementsOnly(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "foo", nil)
	require.NoError(t, err)

	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)

	realChecker := auth.NewAuthorizationChecker(nil, logr.Discard())
	hh.authChecker = realChecker

	const fnBase = "/api/v1/vector_stores"

	// A function whose DELETE op declares users:*:admin -- a requirement the
	// caller does NOT hold. /-/check must ignore it.
	hh.functionHandlers = map[string]*KDexFunctionHandler{
		fnBase: {
			parsedRequirements: map[string]entitlements.ParsedRequirements{
				"DELETE " + fnBase: realChecker.ParseRequirements(
					[]kdexv1alpha1.SecurityRequirement{
						{"bearer": {"users:*:admin"}},
					},
				),
			},
		},
	}

	held := []string{
		"pages:/home:read",                 // exact grant
		"functions:" + fnBase + ":delete",  // function grant (DELETE op requires users:*:admin, ignored here)
		"reports::read",                    // wildcard grant -> satisfies reports:/q3:read
	}

	checks := []string{
		"pages:/home:read",                // held exactly                 -> pass
		"functions:" + fnBase + ":delete", // held; declared req ignored    -> pass
		"reports:/q3:read",                // satisfied by wildcard grant   -> pass
		"pages:/secret:read",              // not held                      -> no pass
		"users:*:admin",                   // not held                      -> no pass
	}
	want := []string{
		"pages:/home:read",
		"functions:" + fnBase + ":delete",
		"reports:/q3:read",
	}

	reqBody, err := json.Marshal(CheckRequest{Checks: checks})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/-/check", bytes.NewBuffer(reqBody))
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub":          "alice",
		"entitlements": held,
	}))
	w := httptest.NewRecorder()

	hh.CheckHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp CheckResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	assert.ElementsMatch(t, want, resp.Passed)
}

type checkAuthChecker struct {
	allowed            map[string]bool
	parsedEntitlements entitlements.ParsedEntitlements
}

func (m *checkAuthChecker) CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error) {
	return nil, nil
}

func (m *checkAuthChecker) CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
	return false, nil
}

func (m *checkAuthChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return m.parsedEntitlements
}

func (m *checkAuthChecker) ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	return entitlements.ParsedRequirements{}
}

func (m *checkAuthChecker) BindRequirements(reqs entitlements.ParsedRequirements, _ entitlements.Binding) (entitlements.ParsedRequirements, error) {
	return reqs, nil
}

func (m *checkAuthChecker) VerifyResourceParsedEntitlements(resource, resourceName string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, verbs ...string) (bool, error) {
	verb := "read"
	if len(verbs) > 0 {
		verb = verbs[0]
	}
	key := resource + ":" + resourceName + ":" + verb
	return m.allowed[key], nil
}

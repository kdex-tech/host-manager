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

// TestCheck_ExcludesInstanceScopedRequirements pins the instance-free contract
// of /-/check. A DELETE op declares vector_stores:{vector_store_id}:own, and the
// caller holds the function grant plus ONE specific store. The check string
// names a function and a verb but no store, so the instance-scoped requirement
// is not applicable to the question asked and must be excluded -- the caller
// passes on the function gate.
//
// Without the fix the unbound {vector_store_id} verifies as an ordinary
// literal, the specific holder fails to match it, and the endpoint wrongly
// reports "not passed" for a request the caller would actually be allowed to
// make -- hiding UI they can legitimately use. The gate (proxy.go) still
// enforces the instance check on the real request, where a binding exists.
func TestCheck_ExcludesInstanceScopedRequirements(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "foo", nil)
	require.NoError(t, err)

	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)

	// A REAL checker rather than checkAuthChecker: this test turns on the
	// library's actual bind AND verify semantics -- ErrUnboundPlaceholder for
	// an unbound {param}, and a specific holder failing to match a placeholder
	// left as a literal. checkAuthChecker answers VerifyResourceParsedEntitlements
	// from a fixture map and ignores the requirements entirely, so it cannot
	// exhibit either behaviour. *auth.AuthorizationChecker satisfies the
	// authChecker interface directly.
	realChecker := auth.NewAuthorizationChecker(nil, logr.Discard())
	hh.authChecker = realChecker

	const basePath = "/api/v1/vector_stores"
	const check = "functions:" + basePath + ":delete"

	// `delete` is the only entitlement verb whose uppercased form spells an HTTP
	// method, so it is the only verb that reaches check.go's parsedRequirements
	// lookup at all (check.go keys by ToUpper(verb), proxy.go by HTTP method).
	hh.functionHandlers = map[string]*KDexFunctionHandler{
		basePath: {
			parsedRequirements: map[string]entitlements.ParsedRequirements{
				"DELETE " + basePath: realChecker.ParseRequirements(
					[]kdexv1alpha1.SecurityRequirement{
						{"bearer": {"vector_stores:{vector_store_id}:own"}},
					},
				),
			},
		},
	}

	// The function grant plus ONE specific store -- not a wildcard.
	held := []string{check, "vector_stores:vs_alice:own"}

	reqBody, err := json.Marshal(CheckRequest{Checks: []string{check}})
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

	assert.Contains(t, resp.Passed, "functions:/api/v1/vector_stores:delete")
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

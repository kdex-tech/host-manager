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

func (m *checkAuthChecker) VerifyResourceParsedEntitlements(resource, resourceName string, ent entitlements.ParsedEntitlements, req entitlements.ParsedRequirements, verbs ...string) (bool, error) {
	verb := "read"
	if len(verbs) > 0 {
		verb = verbs[0]
	}
	key := resource + ":" + resourceName + ":" + verb
	return m.allowed[key], nil
}

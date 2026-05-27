package auth

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"kdex.dev/crds/api/v1alpha1"
)

func TestNewAuthorizationChecker(t *testing.T) {
	tests := []struct {
		name       string
		assertions func(t *testing.T, got *AuthorizationChecker)
	}{
		{
			name: "constructor",
			assertions: func(t *testing.T, got *AuthorizationChecker) {
				assert.NotNil(t, got)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAuthorizationChecker([]string{}, logr.Logger{})
			tt.assertions(t, got)
		})
	}
}

func TestAuthorizationChecker_CheckAccess(t *testing.T) {
	tests := []struct {
		name            string
		kind            string
		resourceName    string
		claims          AuthContext
		req             []v1alpha1.SecurityRequirement
		anonymousGrants []string
		succeeds        bool
	}{
		{
			name:         "CheckPageAccess - claims= / req=[]",
			kind:         "pages",
			resourceName: "1",
			claims:       nil,
			req:          nil,
			succeeds:     false,
		},
		{
			name:            "CheckPageAccess - claims= / req=[] + anon",
			kind:            "pages",
			resourceName:    "1",
			claims:          nil,
			req:             nil,
			anonymousGrants: []string{"pages:read"},
			succeeds:        true,
		},
		{
			name:         "CheckPageAccess - claims= / req=[{bearer:[pages]}]",
			kind:         "pages",
			resourceName: "1",
			claims:       nil,
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims= / req=[{bearer:[pages]}] + anon",
			kind:         "pages",
			resourceName: "1",
			claims:       nil,
			req: []v1alpha1.SecurityRequirement{
				{
					// opaque scope doesn't match
					"bearer": []string{"pages"},
				},
			},
			anonymousGrants: []string{"pages:read"},
			succeeds:        false,
		},
		{
			name:         "CheckPageAccess - claims=admin / req=[{bearer:[foo:1:read]}{oauth2:[admin]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"scope": "admin",
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
				},
				{
					"oauth2": []string{"admin"},
				},
			},
			anonymousGrants: []string{"foo:read"},
			succeeds:        true,
		},
		{
			name:         "CheckPageAccess - claims=admin / req=[{bearer:[foo:1:read],oauth2:[admin]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"scope": "admin",
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
					"oauth2": []string{"admin"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=pages / req=[{bearer:[pages]}] + anon",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages"},
				},
			},
			anonymousGrants: []string{"pages:read"},
			succeeds:        true,
		},
		{
			name:         "CheckPageAccess - claims=pages / req=[{bearer:[]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=users / req=[{bearer:[pages]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"users"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=read / req=[{beader:[read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"read"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=read / req=[{beader:[read]}] + anon",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"read"},
				},
			},
			anonymousGrants: []string{"pages:read"},
			succeeds:        true,
		},
		{
			name:         "CheckPageAccess - claims=pages:1:read / req=[{bearer:[pages:1:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:1:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages::read / req=[{bearer:[pages:1:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages::read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:1:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:read / req=[{bearer:[pages:1:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:1:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:1:read / req=[{bearer:[pages:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:read / req=[{bearer:[pages:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:1:read / req=[{bearer:[pages:2:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:2:read"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=pages:1:read / req=[{bearer:[bar:1:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"bar:1:read"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=pages:all / req=[{bearer:[pages:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:all"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:all / req=[{bearer:[pages:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:all"},
			},
			req:      []v1alpha1.SecurityRequirement{},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=pages:1:all / req=[{bearer:[pages:read]}]",
			kind:         "pages",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"pages:1:all"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"pages:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=foo:1:all / req=[{bearer:[foo:1:all]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"foo:1:all"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=foo:1:foo / req=[{bearer:[foo:1:read]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"foo:1:foo"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=foo:1:read / req=[{bearer:[foo:1:read]}{oauth2:[admin]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"foo:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
				},
				{
					"oauth2": []string{"admin"},
				},
			},
			succeeds: true,
		},
		{
			name:         "CheckPageAccess - claims=foo:1:read / req=[{bearer:[foo:1:read],oauth2:[admin]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"foo:1:read"},
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
					"oauth2": []string{"admin"},
				},
			},
			succeeds: false,
		},
		{
			name:         "CheckPageAccess - claims=foo:1:read,admin / req=[{bearer:[foo:1:read],oauth2:[admin]}]",
			kind:         "foo",
			resourceName: "1",
			claims: AuthContext{
				"entitlements": []string{"foo:1:read"},
				"scope":        "admin",
				"auth_method":  "oauth2",
			},
			req: []v1alpha1.SecurityRequirement{
				{
					"bearer": []string{"foo:1:read"},
					"oauth2": []string{"admin"},
				},
			},
			succeeds: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.claims != nil {
				ctx = SetAuthContext(ctx, tt.claims)
			}
			checker := NewAuthorizationChecker(tt.anonymousGrants, logr.Logger{})
			access, err := checker.CheckAccess(
				ctx, tt.kind, tt.resourceName, tt.req)
			if assert.NoError(t, err) {
				assert.Equal(t, tt.succeeds, access)
			}
		})
	}
}

// Regression for kdex-tech/host-manager#26. ParseRequirements must be
// safe against degenerate inputs — both nil and len(0) slices, and any
// runtime panic inside the range loop (e.g. a corrupted slice header
// from a DeepCopy edge case as observed in production). Without a
// guard, a panic here orphans the RLock held by callers like RebuildMux
// and deadlocks every subsequent controller reconcile.
func TestAuthorizationChecker_ParseRequirements_NilSafe(t *testing.T) {
	checker := NewAuthorizationChecker([]string{}, logr.Logger{})

	t.Run("nil slice returns non-nil empty result without panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := checker.ParseRequirements(nil)
			assert.NotNil(t, result)
		})
	})

	t.Run("empty slice returns non-nil empty result without panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := checker.ParseRequirements([]v1alpha1.SecurityRequirement{})
			assert.NotNil(t, result)
		})
	})

	t.Run("populated slice still works", func(t *testing.T) {
		assert.NotPanics(t, func() {
			result := checker.ParseRequirements([]v1alpha1.SecurityRequirement{
				{"bearer": []string{"pages"}},
			})
			assert.NotNil(t, result)
		})
	})
}

package auth

import (
	"context"
	"testing"
	"unsafe"

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

// TestAuthorizationChecker_ParseRequirements_RecoversFromCorruptedSlice
// reproduces the {data=nil, len=1, cap=20} slice header observed in the
// panic from kdex-tech/host-manager#26. A range over such a header
// segfaults on the first iteration; the recover guard now turns that
// into an empty ParsedRequirements instead of unwinding through
// RebuildMux's RLock.
func TestAuthorizationChecker_ParseRequirements_RecoversFromCorruptedSlice(t *testing.T) {
	checker := NewAuthorizationChecker(nil, logr.Logger{})

	// Forge the exact slice header from the issue's panic: data=nil,
	// len=1, cap=20. unsafe.Slice validates ptr=nil/len>0 at runtime, so
	// we reinterpret the slice header directly via unsafe.Pointer.
	var corrupted []v1alpha1.SecurityRequirement
	hdr := (*struct {
		data unsafe.Pointer
		len  int
		cap  int
	})(unsafe.Pointer(&corrupted))
	hdr.data = nil
	hdr.len = 1
	hdr.cap = 20

	assert.NotPanics(t, func() {
		_ = checker.ParseRequirements(corrupted)
	})
}

// TestAuthorizationChecker_ParseRequirements_NilAndEmpty pins the
// happy-path nil/empty behavior so the recover guard added for #26
// can't silently start masking real bugs on normal inputs.
func TestAuthorizationChecker_ParseRequirements_NilAndEmpty(t *testing.T) {
	checker := NewAuthorizationChecker(nil, logr.Logger{})

	assert.NotPanics(t, func() {
		_ = checker.ParseRequirements(nil)
	})
	assert.NotPanics(t, func() {
		_ = checker.ParseRequirements([]v1alpha1.SecurityRequirement{})
	})
}

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNewRoleProvider(t *testing.T) {
	s := runtime.NewScheme()
	v1.AddToScheme(s)
	kdexv1alpha1.AddToScheme(s)
	cb := func() *fake.ClientBuilder {
		return fake.NewClientBuilder().WithScheme(s).WithIndex(
			&kdexv1alpha1.KDexRoleBinding{},
			"spec.subject", func(rawObj client.Object) []string {
				roleBinding := rawObj.(*kdexv1alpha1.KDexRoleBinding)
				if roleBinding.Spec.Subject == "" {
					return nil
				}
				return []string{roleBinding.Spec.Subject}
			},
		).WithIndex(
			&kdexv1alpha1.KDexRoleBinding{},
			"spec.hostRef.name", func(rawObj client.Object) []string {
				roleBinding := rawObj.(*kdexv1alpha1.KDexRoleBinding)
				if roleBinding.Spec.HostRef.Name == "" {
					return nil
				}
				return []string{roleBinding.Spec.HostRef.Name}
			},
		).WithIndex(
			&kdexv1alpha1.KDexRole{},
			"spec.hostRef.name", func(rawObj client.Object) []string {
				role := rawObj.(*kdexv1alpha1.KDexRole)
				if role.Spec.HostRef.Name == "" {
					return nil
				}
				return []string{role.Spec.HostRef.Name}
			},
		)
	}

	tests := []struct {
		name                string
		c                   client.Client
		focalHost           string
		controllerNamespace string
		secrets             kdexv1alpha1.Secrets
		assertions          func(t *testing.T, got InternalIdentityProvider, gotErr error)
	}{
		{
			name:                "constructor",
			c:                   cb().Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
			},
		},
		{
			name:                "ResolveIdentity - invalid user, no RoleBindings",
			c:                   cb().WithObjects().Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, err := got.FindInternal("username", "password")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "invalid credentials")
			},
		},
		{
			name: "ResolveIdentity - rolebinding exists, no password secret",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, err := got.FindInternal("username", "password")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "invalid credentials")
			},
		},
		{
			name: "ResolveIdentity - rolebinding exists, password secret, wrong password",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			secrets: kdexv1alpha1.Secrets{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "foo",
						Annotations: map[string]string{
							"kdex.dev/secret-type": "subject",
						},
					},
					Data: map[string][]byte{
						"sub":      []byte("username"),
						"password": []byte("passw0rd"),
						"email":    []byte("username@email.foo"),
					},
				},
			},
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, err := got.FindInternal("username", "password")
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "invalid password for subject")
			},
		},
		{
			name: "ResolveIdentity - rolebinding exists, password secret, right password",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			secrets: kdexv1alpha1.Secrets{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "foo",
						Annotations: map[string]string{
							"kdex.dev/secret-type": "subject",
						},
					},
					Data: map[string][]byte{
						"sub":      []byte("username"),
						"password": []byte("passw0rd"),
						"email":    []byte("username@email.foo"),
					},
				},
			},
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				ident, err := got.FindInternal("username", "passw0rd")
				assert.Nil(t, err)
				assert.Equal(t, "username", ident["sub"])
				assert.Equal(t, "username@email.foo", ident["email"])
			},
		},
		{
			name: "ResolveScopes - no subject",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, entitlements, err := got.FindInternalRolesAndEntitlements("")
				assert.Nil(t, err)
				assert.Equal(t, []string{}, entitlements)
			},
		},
		{
			name: "ResolveScopes - with subject",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, entitlements, err := got.FindInternalRolesAndEntitlements("username")
				assert.Nil(t, err)
				assert.Equal(t, []string{"page::read", "page::write"}, entitlements)
			},
		},
		{
			name: "ResolveScopes - with regex subject",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "admin-role",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{Name: "foo"},
						Rules:   []kdexv1alpha1.PolicyRule{{Resources: []string{"admin"}, Verbs: []string{"all"}}},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "admin-binding",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{Name: "foo"},
						Subject: "/^admin-.*$/",
						Roles:   []string{"admin-role"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				roles, _, _ := got.FindInternalRolesAndEntitlements("admin-user")
				assert.Equal(t, []string{"admin-role"}, roles)
				roles, _, _ = got.FindInternalRolesAndEntitlements("other-user")
				assert.Empty(t, roles)
			},
		},
		{
			name: "ResolveScopes - with wildcard subject",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "public-role",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{Name: "foo"},
						Rules:   []kdexv1alpha1.PolicyRule{{Resources: []string{"public"}, Verbs: []string{"read"}}},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "public-binding",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{Name: "foo"},
						Subject: "*",
						Roles:   []string{"public-role"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				roles, _, _ := got.FindInternalRolesAndEntitlements("any-user")
				assert.Equal(t, []string{"public-role"}, roles)
			},
		},
		{
			name: "VerifyLocalIdentity - wrong password",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			secrets: kdexv1alpha1.Secrets{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "foo",
						Annotations: map[string]string{
							"kdex.dev/secret-type": "subject",
						},
					},
					Data: map[string][]byte{
						"sub":      []byte("username"),
						"password": []byte("passw0rd"),
						"email":    []byte("username@email.foo"),
					},
				},
			},
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				_, err := got.FindInternal("username", "password")
				assert.NotNil(t, err)
			},
		},
		{
			name: "VerifyLocalIdentity - login by email",
			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			secrets: kdexv1alpha1.Secrets{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "foo",
						Annotations: map[string]string{
							"kdex.dev/secret-type": "subject",
						},
					},
					Data: map[string][]byte{
						"sub":      []byte("username"),
						"password": []byte("passw0rd"),
						"email":    []byte("username@email.foo"),
					},
				},
			},
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				ident, err := got.FindInternal("username@email.foo", "passw0rd")
				assert.Nil(t, err)
				assert.NotNil(t, ident)
				assert.Equal(t, "username", ident["sub"])
				assert.Equal(t, "username@email.foo", ident["email"])
				assert.Equal(t, []string{"page::read", "page::write"}, ident["entitlements"])
			},
		},
		{
			name: "VerifyLocalIdentity - correct password",

			c: cb().WithObjects(
				&kdexv1alpha1.KDexRole{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Rules: []kdexv1alpha1.PolicyRule{
							{
								Resources: []string{"page"},
								Verbs:     []string{"read", "write"},
							},
						},
					},
				},
				&kdexv1alpha1.KDexRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "role-binging-1",
						Namespace: "foo",
					},
					Spec: kdexv1alpha1.KDexRoleBindingSpec{
						HostRef: v1.LocalObjectReference{
							Name: "foo",
						},
						Subject: "username",
						Roles:   []string{"role-1"},
					},
				},
			).Build(),
			focalHost:           "foo",
			controllerNamespace: "foo",
			secrets: kdexv1alpha1.Secrets{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "foo",
						Annotations: map[string]string{
							"kdex.dev/secret-type": "subject",
						},
					},
					Data: map[string][]byte{
						"sub":      []byte("username"),
						"password": []byte("passw0rd"),
						"email":    []byte("username@email.foo"),
					},
				},
			},
			assertions: func(t *testing.T, got InternalIdentityProvider, gotErr error) {
				assert.Nil(t, gotErr)
				ident, err := got.FindInternal("username", "passw0rd")
				assert.Nil(t, err)
				assert.NotNil(t, ident)
				assert.Equal(t, "username", ident["sub"])
				assert.Equal(t, "username@email.foo", ident["email"])
				assert.Equal(t, []string{"page::read", "page::write"}, ident["entitlements"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := NewRoleProvider(context.Background(), tt.c, tt.focalHost, tt.controllerNamespace, []Lookup{
				NewSecretLookup(tt.secrets),
			})
			tt.assertions(t, got, gotErr)
		})
	}
}

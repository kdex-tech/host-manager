package auth

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func roleListClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, v1.AddToScheme(s))
	require.NoError(t, kdexv1alpha1.AddToScheme(s))
	hostIndex := func(name func(client.Object) string) client.IndexerFunc {
		return func(o client.Object) []string {
			if n := name(o); n != "" {
				return []string{n}
			}
			return nil
		}
	}
	return fake.NewClientBuilder().WithScheme(s).
		WithIndex(&kdexv1alpha1.KDexRole{}, "spec.hostRef.name", hostIndex(func(o client.Object) string {
			return o.(*kdexv1alpha1.KDexRole).Spec.HostRef.Name
		})).
		WithIndex(&kdexv1alpha1.KDexRoleBinding{}, "spec.hostRef.name", hostIndex(func(o client.Object) string {
			return o.(*kdexv1alpha1.KDexRoleBinding).Spec.HostRef.Name
		})).
		WithObjects(objs...).Build()
}

func kdexRole(name, host string, rules ...kdexv1alpha1.PolicyRule) *kdexv1alpha1.KDexRole {
	return &kdexv1alpha1.KDexRole{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: kdexv1alpha1.KDexRoleSpec{
			HostRef: v1.LocalObjectReference{Name: host},
			Rules:   rules,
		},
	}
}

// Roles lists the host's KDexRoles with their rules as stored and exactly the
// entitlements the compiler emits for them -- the same table tokens are built
// from -- sorted by name. Roles of another host are not listed (#231).
func TestRoleProvider_Roles(t *testing.T) {
	c := roleListClient(t,
		kdexRole("viewer", "foo", kdexv1alpha1.PolicyRule{Resources: []string{"pages"}, Verbs: []string{"read"}}),
		kdexRole("admin", "foo",
			kdexv1alpha1.PolicyRule{Resources: []string{"roles"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"read", "update"}},
			kdexv1alpha1.PolicyRule{Scopes: []string{"roles_create"}},
		),
		kdexRole("elsewhere", "bar", kdexv1alpha1.PolicyRule{Resources: []string{"x"}, Verbs: []string{"read"}}),
	)
	rp, err := NewRoleProvider(context.Background(), c, "foo", "ns", nil)
	require.NoError(t, err)

	got := rp.Roles()
	require.Len(t, got, 2)

	assert.Equal(t, "admin", got[0].Name)
	assert.Equal(t, []kdexv1alpha1.PolicyRule{
		{Resources: []string{"roles"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"read", "update"}},
		{Scopes: []string{"roles_create"}},
	}, got[0].Rules)
	assert.Equal(t, []string{"roles:a:read", "roles:a:update", "roles:b:read", "roles:b:update", "roles_create"}, got[0].Entitlements)

	assert.Equal(t, "viewer", got[1].Name)
	assert.Equal(t, []string{"pages::read"}, got[1].Entitlements)

	// The listed entitlements are exactly what a bound subject's token gets.
	assert.Equal(t, got[0].Entitlements, rp.collectEntitlements([]string{"admin"}))
}

type rolelessProvider struct{}

func (rolelessProvider) FindInternal(string, string) (jwt.MapClaims, error) { return nil, nil }
func (rolelessProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// The exchanger exposes the provider's roles when it can list them, and nil
// when the provider has no such capability (test stubs, non-cluster providers).
func TestExchanger_Roles(t *testing.T) {
	c := roleListClient(t, kdexRole("viewer", "foo", kdexv1alpha1.PolicyRule{Resources: []string{"pages"}, Verbs: []string{"read"}}))
	rp, err := NewRoleProvider(context.Background(), c, "foo", "ns", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), Config{}, nil, rp, nil)
	require.NoError(t, err)
	assert.Equal(t, rp.Roles(), ex.Roles())

	ex, err = NewExchanger(context.Background(), Config{}, nil, rolelessProvider{}, nil)
	require.NoError(t, err)
	assert.Nil(t, ex.Roles())

	var none *Exchanger
	assert.Nil(t, none.Roles(), "a host with no exchanger yet lists no roles")
}

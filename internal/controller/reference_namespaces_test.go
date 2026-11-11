package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// withReferenceNamespaces sets the process-wide allowlist for one test.
func withReferenceNamespaces(t *testing.T, namespaces ...string) {
	t.Helper()
	SetReferenceNamespaces(namespaces)
	t.Cleanup(func() { SetReferenceNamespaces(nil) })
}

func TestParseReferenceNamespaces(t *testing.T) {
	assert.Nil(t, ParseReferenceNamespaces(""))
	assert.Equal(t, []string{"a", "b"}, ParseReferenceNamespaces(" a, ,b,a "))
}

func TestCacheNamespaces_AlwaysIncludesTheHostNamespace(t *testing.T) {
	assert.Equal(t, []string{"dev"}, CacheNamespaces("dev", nil))
	assert.Equal(t, []string{"dev", "shared"}, CacheNamespaces("dev", []string{"dev", "shared"}))
}

// An empty referenceNamespaces means the host's own namespace only.
func TestCheckReferenceNamespace(t *testing.T) {
	withReferenceNamespaces(t, "shared")
	assert.NoError(t, checkReferenceNamespace("dev", ""), "no namespace is the referrer's own")
	assert.NoError(t, checkReferenceNamespace("dev", "dev"))
	assert.NoError(t, checkReferenceNamespace("dev", "shared"))
	err := checkReferenceNamespace("dev", "other")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec.referenceNamespaces")

	SetReferenceNamespaces(nil)
	assert.Error(t, checkReferenceNamespace("dev", "shared"), "the default is the host's own namespace only")
}

// A reference to a namespace the host does not list is refused before any
// read, and the referrer goes Degraded naming the field to change (#290).
func TestResolveKDexObjectReference_RefusesUnlistedNamespace(t *testing.T) {
	withReferenceNamespaces(t)
	scheme := functionTestScheme(t)
	theme := &kdexv1alpha1.KDexTheme{ObjectMeta: metav1.ObjectMeta{Name: "t", Namespace: "other"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(theme).Build()

	page := &kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "dev"}}
	var conditions []metav1.Condition
	obj, shouldReturn, _, err := ResolveKDexObjectReference(context.Background(), c, page, &conditions,
		&kdexv1alpha1.KDexObjectReference{Kind: "KDexTheme", Name: "t", Namespace: "other"}, 0)

	require.Error(t, err)
	assert.True(t, shouldReturn)
	assert.Nil(t, obj, "the theme exists but is not read")
	degraded := meta.FindStatusCondition(conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, degraded)
	assert.Contains(t, degraded.Message, "spec.referenceNamespaces")
}

// The npm credential Secret is always the host's own: a secretRef naming
// another namespace is refused (#242).
func TestSecretRefKey_RefusesAnotherNamespace(t *testing.T) {
	ipr := &kdexv1alpha1.KDexInternalPackageReferences{ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev"}}
	pkg := func(ns string) kdexv1alpha1.PackageReference {
		return kdexv1alpha1.PackageReference{Name: "@a/b", SecretRef: &kdexv1alpha1.KDexObjectReference{Kind: "Secret", Name: "npm", Namespace: ns}}
	}

	key, ok, err := secretRefKey(ipr, pkg(""))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "dev", key.Namespace)

	_, _, err = secretRefKey(ipr, pkg("dev"))
	assert.NoError(t, err, "naming the host's own namespace is fine")

	withReferenceNamespaces(t, "kdex-system")
	_, ok, err = secretRefKey(ipr, pkg("kdex-system"))
	require.Error(t, err, "referenceNamespaces never widens Secret reads")
	assert.False(t, ok)
}

// A service-backed function cannot front a Service in a namespace the host
// does not list.
func TestReconcileServiceBacked_RefusesUnlistedNamespace(t *testing.T) {
	withReferenceNamespaces(t)
	scheme := functionTestScheme(t)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "other"}}
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "f", Namespace: "dev"},
		Spec: kdexv1alpha1.KDexFunctionSpec{Backend: &kdexv1alpha1.FunctionBackend{
			Service: &kdexv1alpha1.ServiceBackend{Name: "db", Namespace: "other"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, fn).WithStatusSubresource(fn).Build()
	r := &KDexFunctionReconciler{Client: c, Scheme: scheme}

	_, err := r.reconcileServiceBacked(context.Background(), fn)
	require.NoError(t, err)
	degraded := meta.FindStatusCondition(fn.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, degraded)
	assert.Equal(t, "NamespaceNotReferenceable", degraded.Reason)
}

// The IPR accepts no secretRef.namespace and keys packages by name: the
// host's own namespace is cleared, anything else and one package at two
// versions mark the host Degraded naming the package (#242).
func TestPackageRefsForIPR(t *testing.T) {
	ref := func(name, version, ns string) kdexv1alpha1.PackageReference {
		p := kdexv1alpha1.PackageReference{Name: name, Version: version}
		if ns != "-" {
			p.SecretRef = &kdexv1alpha1.KDexObjectReference{Kind: "Secret", Name: "npm", Namespace: ns}
		}
		return p
	}

	out, err := packageRefsForIPR("dev", []kdexv1alpha1.PackageReference{ref("@a/x", "1.0.0", "dev"), ref("@a/y", "1.0.0", "-")})
	require.NoError(t, err)
	assert.Empty(t, out[0].SecretRef.Namespace, "the host's own namespace is cleared")
	assert.Nil(t, out[1].SecretRef)

	_, err = packageRefsForIPR("dev", []kdexv1alpha1.PackageReference{ref("@a/x", "1.0.0", "creds")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "@a/x")

	_, err = packageRefsForIPR("dev", []kdexv1alpha1.PackageReference{ref("@a/x", "1.0.0", "-"), ref("@a/x", "2.0.0", "-")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "two versions")
}

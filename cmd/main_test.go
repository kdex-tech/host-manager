package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/kdex-tech/host-manager/internal"
)

// The optional CRDs are scoped only when the cluster serves them: a ByObject
// entry for a kind the cluster does not serve fails the manager at startup.
func TestHostCacheOptions_OptionalCRDsOnlyWhenInstalled(t *testing.T) {
	bare := meta.NewDefaultRESTMapper(nil)
	opts, err := hostCacheOptions("dev", []string{"dev", "shared"}, bare)
	require.NoError(t, err)
	for obj := range opts.ByObject {
		_, isRoute := obj.(*gatewayv1.HTTPRoute)
		_, isUnstructured := obj.(*unstructured.Unstructured)
		assert.False(t, isRoute || isUnstructured, "no entry for an uninstalled CRD: %T", obj)
	}

	full := meta.NewDefaultRESTMapper(nil)
	full.Add(schema.GroupVersionKind{Group: gatewayv1.GroupName, Version: "v1", Kind: "HTTPRoute"}, meta.RESTScopeNamespace)
	full.Add(internal.KPackImageGVK, meta.RESTScopeNamespace)
	opts, err = hostCacheOptions("dev", []string{"dev", "shared"}, full)
	require.NoError(t, err)
	var route, image bool
	for obj, scope := range opts.ByObject {
		switch o := obj.(type) {
		case *gatewayv1.HTTPRoute:
			route = true
			assert.Contains(t, scope.Namespaces, "dev")
		case *unstructured.Unstructured:
			image = o.GroupVersionKind() == internal.KPackImageGVK
		}
	}
	assert.True(t, route, "HTTPRoute is host-only once installed")
	assert.True(t, image, "the kpack Image is host-only once installed")
}

// Workload kinds and host-bound kdex kinds are host-only; the defaults span
// the reference namespaces for what a reference can name.
func TestHostCacheOptions_Scopes(t *testing.T) {
	opts, err := hostCacheOptions("dev", []string{"dev", "shared"}, meta.NewDefaultRESTMapper(nil))
	require.NoError(t, err)
	assert.Len(t, opts.DefaultNamespaces, 2)
	hostOnly := 0
	for obj, scope := range opts.ByObject {
		switch obj.(type) {
		case *corev1.Secret, *kdexv1alpha1.KDexPage, *kdexv1alpha1.KDexInternalHost:
			hostOnly++
			assert.Len(t, scope.Namespaces, 1)
			assert.Contains(t, scope.Namespaces, "dev")
		case *corev1.Service, *kdexv1alpha1.KDexTheme:
			t.Errorf("%T must span the reference namespaces", obj)
		}
	}
	assert.Equal(t, 3, hostOnly)
}

// An empty controller namespace would make the cache cluster-wide.
func TestManagerCacheOptions_RefusesEmptyNamespace(t *testing.T) {
	_, err := managerCacheOptions(&rest.Config{}, "", "")
	assert.Error(t, err)
}

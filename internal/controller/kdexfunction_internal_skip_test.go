package controller

import (
	"testing"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestCollectInitialPaths_SkipsInternalFunctions pins kdex-tech/kdex-crds#6:
// a KDexFunction with spec.internal=true must NOT be added to the host's
// registered paths (which drive the /-/openapi catalog and the host mux), so
// it is neither advertised nor routable through the host. Non-internal
// functions are cataloged as before.
func TestCollectInitialPaths_SkipsInternalFunctions(t *testing.T) {
	r := &KDexInternalHostReconciler{}
	functions := kdexv1alpha1.KDexFunctionList{Items: []kdexv1alpha1.KDexFunction{
		{Spec: kdexv1alpha1.KDexFunctionSpec{
			API:      kdexv1alpha1.API{BasePath: "/v1/public"},
			Internal: false,
		}},
		{Spec: kdexv1alpha1.KDexFunctionSpec{
			API:      kdexv1alpha1.API{BasePath: "/v1/secret"},
			Internal: true,
		}},
	}}

	got := r.collectInitialPaths(nil, functions)

	pub, hasPublic := got["/v1/public"]
	if !hasPublic {
		t.Fatal("non-internal function /v1/public should be cataloged")
	}
	if pub.Type != ko.FunctionPathType {
		t.Errorf("/v1/public Type = %q; want %q", pub.Type, ko.FunctionPathType)
	}
	if _, hasSecret := got["/v1/secret"]; hasSecret {
		t.Error("internal function /v1/secret must be omitted from the catalog/mux paths")
	}
}

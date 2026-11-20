package host

import (
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Test helpers shared across this package's test files.

// passThroughPaths declares basePath and everything beneath it, every common
// method, no security: the #293 migration for a function that relied on
// implicit subtree pass-through. Fixtures that exercise the proxy rather than
// the gate use it, since an undeclared path is now a 404.
func passThroughPaths(basePath string) map[string]kdexv1alpha1.PathItem {
	op := func() *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(`{}`)} }
	item := kdexv1alpha1.PathItem{Get: op(), Post: op(), Put: op(), Patch: op(), Delete: op()}
	paths := map[string]kdexv1alpha1.PathItem{
		strings.TrimSuffix(basePath, "/") + "/{rest...}": item,
	}
	if basePath != "/" {
		paths[basePath] = item
	}
	return paths
}

package controller

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
)

// referenceNamespaces is KDexHost.spec.referenceNamespaces for the focal host:
// the namespaces, besides the host's own, in which its resources may reference
// namespaced objects (host-manager#290). It is fixed for the process: the
// manager's cache is scoped to these namespaces at startup, and nexus rolls
// host-manager when the list changes. SetReferenceNamespaces runs before the
// manager starts; tests swap it while reconcilers run, so it is atomic.
var referenceNamespaces atomic.Pointer[map[string]bool]

// SetReferenceNamespaces records the focal host's referenceNamespaces.
func SetReferenceNamespaces(namespaces []string) {
	set := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		set[ns] = true
	}
	referenceNamespaces.Store(&set)
}

func isReferenceNamespace(namespace string) bool {
	set := referenceNamespaces.Load()
	return set != nil && (*set)[namespace]
}

// ParseReferenceNamespaces splits the --reference-namespaces flag (comma
// separated), dropping blanks and duplicates.
func ParseReferenceNamespaces(csv string) []string {
	var out []string
	for _, ns := range strings.Split(csv, ",") {
		if ns = strings.TrimSpace(ns); ns != "" && !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

// CacheNamespaces is every namespace the manager caches: the host's own plus
// its referenceNamespaces.
func CacheNamespaces(controllerNamespace string, namespaces []string) []string {
	out := []string{controllerNamespace}
	for _, ns := range namespaces {
		if !slices.Contains(out, ns) {
			out = append(out, ns)
		}
	}
	return out
}

// checkReferenceNamespace refuses a reference from an object in
// referrerNamespace to an object in namespace unless namespace is the
// referrer's own or one of the host's referenceNamespaces. Outside them the
// manager neither caches nor watches anything, so the reference could not
// resolve anyway; this says why.
func checkReferenceNamespace(referrerNamespace, namespace string) error {
	if namespace == "" || namespace == referrerNamespace || isReferenceNamespace(namespace) {
		return nil
	}
	return fmt.Errorf("namespace %q is not referenceable: add it to the KDexHost's spec.referenceNamespaces", namespace)
}

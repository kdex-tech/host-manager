package controller

import (
	"bufio"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// rbacMarker matches a +kubebuilder:rbac marker line, capturing its
// comma-separated key=value arguments.
var rbacMarker = regexp.MustCompile(`^//\s*\+kubebuilder:rbac:(.*)$`)

// rbacMarkerArgs parses a marker's arguments, keyed by name, each split on ";"
// (spaces trimmed: the markers are column-aligned).
func rbacMarkerArgs(args string) map[string][]string {
	out := map[string][]string{}
	for _, kv := range strings.Split(args, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		for _, item := range strings.Split(v, ";") {
			out[k] = append(out[k], strings.TrimSpace(item))
		}
	}
	return out
}

// host-manager's cluster-scoped rights come from nexus-manager's fixed
// cluster-reader ClusterRole, which grants get/list/watch on every
// KDexCluster* kind and nothing else. A cluster-scoped (unnamespaced) marker
// for anything more would be a right host-manager needs and never receives
// in a cluster, so every one must be a kdex.dev kdexcluster* read.
func TestClusterScopedRBACMarkersAreKDexClusterReads(t *testing.T) {
	f, err := os.Open("rbac.go")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	reads := []string{"get", "list", "watch"}
	var clusterScoped int
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		m := rbacMarker.FindStringSubmatch(strings.TrimSpace(scanner.Text()))
		if m == nil {
			continue
		}
		args := rbacMarkerArgs(m[1])
		if len(args["namespace"]) != 0 {
			continue
		}
		clusterScoped++
		if !slices.Equal(args["groups"], []string{"kdex.dev"}) {
			t.Errorf("rbac.go:%d: cluster-scoped marker for groups %v, want only kdex.dev", line, args["groups"])
		}
		for _, r := range args["resources"] {
			if !strings.HasPrefix(r, "kdexcluster") || strings.Contains(r, "/") {
				t.Errorf("rbac.go:%d: cluster-scoped marker for resource %q, want a kdexcluster* kind", line, r)
			}
		}
		for _, v := range args["verbs"] {
			if !slices.Contains(reads, v) {
				t.Errorf("rbac.go:%d: cluster-scoped marker with verb %q, want only get/list/watch", line, v)
			}
		}
		if len(args["resourceNames"]) != 0 {
			t.Errorf("rbac.go:%d: cluster-scoped marker with resourceNames %v: the cluster reader grants whole kinds", line, args["resourceNames"])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if clusterScoped == 0 {
		t.Fatal("no cluster-scoped marker found: the parse is broken")
	}
}

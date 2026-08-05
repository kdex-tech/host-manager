package controller

import (
	"testing"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// kdex-tech/host-manager#165: an inline spec.origin.source.builder used to
// REPLACE the FaaSAdaptor's matching Builder wholesale, so every field the
// inline author omitted was dropped rather than inherited. Cluster-level
// scheduling policy (builders[].tolerations / nodeSelector) was therefore
// unreachable for any function that declared its builder inline, with nothing
// reporting the divergence.

func spotToleration() corev1.Toleration {
	return corev1.Toleration{
		Key:      "cloud.google.com/gke-spot",
		Operator: corev1.TolerationOpEqual,
		Value:    "true",
		Effect:   corev1.TaintEffectNoSchedule,
	}
}

// The adaptor as an operator would configure it: cluster scheduling policy and
// a full resource budget on every catalog entry.
func adaptorSpec() *kdexv1alpha1.KDexFaaSAdaptorSpec {
	return &kdexv1alpha1.KDexFaaSAdaptorSpec{
		DefaultBuilderGenerator: "tiny/go",
		Builders: []kdexv1alpha1.Builder{
			{
				Name:               "tiny",
				Languages:          []string{"go", "rust"},
				BuilderRef:         kdexv1alpha1.KDexObjectReference{Kind: "ClusterBuilder", Name: "tiny-builder"},
				ServiceAccountName: "kdex-builder",
				Tolerations:        []corev1.Toleration{spotToleration()},
				NodeSelector:       map[string]string{"pool": "build-spot"},
				Resources: &corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("2"),
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("4"),
						corev1.ResourceMemory: resource.MustParse("2Gi"),
					},
				},
				Cache: &kdexv1alpha1.BuildCache{VolumeSize: resource.MustParse("20Gi")},
				Env:   []corev1.EnvVar{{Name: "BP_GO_VERSION", Value: "1.26"}},
			},
			{
				Name:         "base",
				Languages:    []string{"java"},
				BuilderRef:   kdexv1alpha1.KDexObjectReference{Kind: "ClusterBuilder", Name: "base-builder"},
				NodeSelector: map[string]string{"pool": "build-java"},
				Cache:        &kdexv1alpha1.BuildCache{VolumeSize: resource.MustParse("30Gi")},
			},
		},
	}
}

func findToleration(tols []corev1.Toleration, key string) bool {
	for _, t := range tols {
		if t.Key == key {
			return true
		}
	}
	return false
}

// The reproduction from the issue, verbatim: an inline `tiny` that pins only
// memory and says nothing about scheduling. Before the fix, spec.build on the
// kpack Image came out memory-only with zero tolerations.
func TestBuilderForBuildInheritsAdaptorPolicyForInlineBuilder(t *testing.T) {
	inline := &kdexv1alpha1.Builder{
		Name:               "tiny",
		Languages:          []string{"go", "rust"},
		BuilderRef:         kdexv1alpha1.KDexObjectReference{Kind: "ClusterBuilder", Name: "tiny-builder"},
		ServiceAccountName: "kdex-builder",
		Resources: &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
			Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("4Gi")},
		},
	}

	got, err := builderForBuild(adaptorSpec(), inline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !findToleration(got.Tolerations, "cloud.google.com/gke-spot") {
		t.Errorf("adaptor toleration dropped: got %+v", got.Tolerations)
	}
	if got.NodeSelector["pool"] != "build-spot" {
		t.Errorf("adaptor nodeSelector dropped: got %v", got.NodeSelector)
	}
	if got.Cache == nil || got.Cache.VolumeSize.String() != "20Gi" {
		t.Errorf("adaptor cache dropped: got %+v", got.Cache)
	}

	// The tell from the issue: inline set memory only, so cpu must survive
	// from the adaptor while memory takes the inline value.
	if cpu, ok := got.Resources.Requests[corev1.ResourceCPU]; !ok || cpu.String() != "2" {
		t.Errorf("adaptor resources.requests.cpu dropped: got %v", got.Resources.Requests)
	}
	if mem := got.Resources.Requests[corev1.ResourceMemory]; mem.String() != "2Gi" {
		t.Errorf("inline resources.requests.memory must win: got %v", mem.String())
	}
	if cpu, ok := got.Resources.Limits[corev1.ResourceCPU]; !ok || cpu.String() != "4" {
		t.Errorf("adaptor resources.limits.cpu dropped: got %v", got.Resources.Limits)
	}
	if mem := got.Resources.Limits[corev1.ResourceMemory]; mem.String() != "4Gi" {
		t.Errorf("inline resources.limits.memory must win: got %v", mem.String())
	}
}

// The merge base is the entry NAMED by the inline block, not the one
// defaultBuilderGenerator happens to point at — otherwise a java function on
// `base` would inherit `tiny`'s spot toleration and 20Gi cache.
func TestBuilderForBuildMatchesTheNamedEntryNotTheDefault(t *testing.T) {
	inline := &kdexv1alpha1.Builder{
		Name:       "base",
		Languages:  []string{"java"},
		BuilderRef: kdexv1alpha1.KDexObjectReference{Kind: "ClusterBuilder", Name: "base-builder"},
	}

	got, err := builderForBuild(adaptorSpec(), inline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.NodeSelector["pool"] != "build-java" {
		t.Errorf("must merge from builders[name=base]: got nodeSelector %v", got.NodeSelector)
	}
	if findToleration(got.Tolerations, "cloud.google.com/gke-spot") {
		t.Errorf("must not inherit the default entry's toleration: got %+v", got.Tolerations)
	}
	if got.Cache == nil || got.Cache.VolumeSize.String() != "30Gi" {
		t.Errorf("must inherit base's cache, not tiny's: got %+v", got.Cache)
	}
}

// A function may legitimately point at a builder outside the adaptor catalog.
// There is no cluster policy to inherit, so it passes through untouched rather
// than erroring or silently picking up an unrelated entry's settings.
func TestBuilderForBuildPassesThroughAnUnlistedBuilder(t *testing.T) {
	inline := &kdexv1alpha1.Builder{
		Name:       "custom",
		Languages:  []string{"go"},
		BuilderRef: kdexv1alpha1.KDexObjectReference{Kind: "Builder", Name: "custom-builder"},
	}

	got, err := builderForBuild(adaptorSpec(), inline)
	if err != nil {
		t.Fatalf("an unlisted inline builder must not be an error: %v", err)
	}
	if got.Name != "custom" || len(got.Tolerations) != 0 || got.Cache != nil {
		t.Errorf("unlisted builder must pass through unchanged: got %+v", got)
	}
}

// Generator mode: codegen Jobs populate Status.Source without a Builder, and
// the adaptor's defaultBuilderGenerator supplies it. Unchanged by #165.
func TestBuilderForBuildResolvesTheDefaultWhenNoInlineBuilder(t *testing.T) {
	got, err := builderForBuild(adaptorSpec(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "tiny" {
		t.Errorf("expected the defaultBuilderGenerator entry, got %q", got.Name)
	}
	if !findToleration(got.Tolerations, "cloud.google.com/gke-spot") {
		t.Errorf("default entry must carry its own policy: got %+v", got.Tolerations)
	}
}

func TestBuilderForBuildErrorsWhenNoInlineBuilderAndNoResolvableDefault(t *testing.T) {
	faas := adaptorSpec()
	faas.DefaultBuilderGenerator = "nonexistent/go"

	if _, err := builderForBuild(faas, nil); err == nil {
		t.Fatal("expected an error when the default generator matches no builder")
	}
}

func TestMergeBuilderUnionsTolerationsAndDedupes(t *testing.T) {
	own := corev1.Toleration{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "build", Effect: corev1.TaintEffectNoSchedule}
	arch := corev1.Toleration{Key: "kubernetes.io/arch", Operator: corev1.TolerationOpEqual, Value: "arm64", Effect: corev1.TaintEffectNoSchedule}
	base := &kdexv1alpha1.Builder{Tolerations: []corev1.Toleration{spotToleration(), arch}}
	inline := &kdexv1alpha1.Builder{
		Name: "tiny",
		// Repeats one of the adaptor's tolerations and adds one of its
		// own. A function that sets a toleration for its own reasons must
		// not thereby lose the cluster's — that is #165 one level down.
		Tolerations: []corev1.Toleration{spotToleration(), own},
	}

	got := mergeBuilder(base, inline)

	if len(got.Tolerations) != 3 {
		t.Fatalf("expected the union deduped to 3 tolerations, got %d: %+v", len(got.Tolerations), got.Tolerations)
	}
	for _, key := range []string{"cloud.google.com/gke-spot", "kubernetes.io/arch", "dedicated"} {
		if !findToleration(got.Tolerations, key) {
			t.Errorf("union must keep %s: got %+v", key, got.Tolerations)
		}
	}
}

func TestMergeBuilderMergesEnvByName(t *testing.T) {
	base := &kdexv1alpha1.Builder{Env: []corev1.EnvVar{
		{Name: "BP_GO_VERSION", Value: "1.26"},
		{Name: "CLUSTER", Value: "dev"},
	}}
	inline := &kdexv1alpha1.Builder{Env: []corev1.EnvVar{
		{Name: "BP_GO_VERSION", Value: "1.25"},
		{Name: "EXTRA", Value: "on"},
	}}

	got := mergeBuilder(base, inline)

	want := map[string]string{"BP_GO_VERSION": "1.25", "CLUSTER": "dev", "EXTRA": "on"}
	if len(got.Env) != len(want) {
		t.Fatalf("expected %d env vars, got %d: %+v", len(want), len(got.Env), got.Env)
	}
	for _, e := range got.Env {
		if want[e.Name] != e.Value {
			t.Errorf("env %s: got %q, want %q", e.Name, e.Value, want[e.Name])
		}
	}
	// Order must be stable across reconciles or the kpack Image spec churns.
	if got.Env[0].Name != "BP_GO_VERSION" || got.Env[1].Name != "CLUSTER" || got.Env[2].Name != "EXTRA" {
		t.Errorf("env order must be base-order then inline-only additions: got %+v", got.Env)
	}
}

// hc.faasAdaptorSpec is shared across every function reconciled in the
// namespace. Mutating it here would leak one function's inline builder into
// the next function's merge base.
func TestMergeBuilderDoesNotMutateItsInputs(t *testing.T) {
	faas := adaptorSpec()
	base := &faas.Builders[0]
	inline := &kdexv1alpha1.Builder{
		Name:         "tiny",
		Tolerations:  []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}},
		NodeSelector: map[string]string{"pool": "override"},
		Resources: &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("8Gi")},
		},
		Env: []corev1.EnvVar{{Name: "BP_GO_VERSION", Value: "1.25"}},
	}

	_ = mergeBuilder(base, inline)

	if len(base.Tolerations) != 1 || base.Tolerations[0].Key != "cloud.google.com/gke-spot" {
		t.Errorf("adaptor tolerations mutated: %+v", base.Tolerations)
	}
	if base.NodeSelector["pool"] != "build-spot" {
		t.Errorf("adaptor nodeSelector mutated: %v", base.NodeSelector)
	}
	if mem := base.Resources.Requests[corev1.ResourceMemory]; mem.String() != "1Gi" {
		t.Errorf("adaptor resources mutated: %v", base.Resources.Requests)
	}
	if base.Env[0].Value != "1.26" {
		t.Errorf("adaptor env mutated: %+v", base.Env)
	}
	if len(inline.Tolerations) != 1 {
		t.Errorf("inline tolerations mutated: %+v", inline.Tolerations)
	}
}

func TestResolveBuilderByName(t *testing.T) {
	faas := adaptorSpec()

	if got := resolveBuilderByName(faas, "tiny"); got == nil || got.Name != "tiny" {
		t.Errorf("expected the tiny entry, got %+v", got)
	}
	if got := resolveBuilderByName(faas, "absent"); got != nil {
		t.Errorf("expected nil for an unlisted name, got %+v", got)
	}
	if got := resolveBuilderByName(faas, ""); got != nil {
		t.Errorf("an empty name must not match anything, got %+v", got)
	}
	if got := resolveBuilderByName(&kdexv1alpha1.KDexFaaSAdaptorSpec{}, "tiny"); got != nil {
		t.Errorf("expected nil against an empty builders list, got %+v", got)
	}
}

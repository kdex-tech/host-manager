/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newJob builds a packager Job carrying the labels cleanupJobs filters on.
// genLabel is set verbatim into kdex.dev/generation so tests can probe the
// missing-or-unparseable code path.
func newJob(iprName, name, genLabel string, succeeded, failed int32) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				"app":                 "packages",
				"packages":            iprName,
				"kdex.dev/generation": genLabel,
			},
		},
		Status: batchv1.JobStatus{
			Succeeded: succeeded,
			Failed:    failed,
		},
	}
}

var _ = Describe("KDexInternalPackageReferencesReconciler.cleanupJobs", func() {
	const iprName = "rsi-dev"
	const otherIPR = "rsi-other"

	var (
		ctx       context.Context
		scheme    *runtime.Scheme
		ipr       *kdexv1alpha1.KDexInternalPackageReferences
		listJobs  func(c client.Client) []string
		buildIPR  func(gen int64) *kdexv1alpha1.KDexInternalPackageReferences
		buildRcnl func(objs ...client.Object) (*KDexInternalPackageReferencesReconciler, client.Client)
	)

	BeforeEach(func() {
		ctx = context.Background()
		scheme = runtime.NewScheme()
		Expect(batchv1.AddToScheme(scheme)).To(Succeed())
		Expect(kdexv1alpha1.AddToScheme(scheme)).To(Succeed())

		buildIPR = func(gen int64) *kdexv1alpha1.KDexInternalPackageReferences {
			return &kdexv1alpha1.KDexInternalPackageReferences{
				ObjectMeta: metav1.ObjectMeta{
					Name:       iprName,
					Namespace:  "default",
					Generation: gen,
				},
			}
		}

		buildRcnl = func(objs ...client.Object) (*KDexInternalPackageReferencesReconciler, client.Client) {
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
			return &KDexInternalPackageReferencesReconciler{Client: c, Scheme: scheme}, c
		}

		listJobs = func(c client.Client) []string {
			var jobs batchv1.JobList
			Expect(c.List(ctx, &jobs, client.InNamespace("default"))).To(Succeed())
			names := make([]string, 0, len(jobs.Items))
			for _, j := range jobs.Items {
				names = append(names, j.Name)
			}
			return names
		}

		ipr = buildIPR(6)
	})

	It("deletes in-flight Jobs from earlier generations", func() {
		// Generations 3-5 are mid-pipeline (Succeeded=0, Failed=0); gen 6 is current.
		j3 := newJob(iprName, "rsi-dev-packages-3", "3", 0, 0)
		j4 := newJob(iprName, "rsi-dev-packages-4", "4", 0, 0)
		j5 := newJob(iprName, "rsi-dev-packages-5", "5", 0, 0)
		j6 := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)

		r, c := buildRcnl(j3, j4, j5, j6)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-6"))
	})

	It("deletes terminated Jobs from earlier generations", func() {
		// Mix of succeeded/failed prior-gen jobs - all should go.
		jSucceeded := newJob(iprName, "rsi-dev-packages-3", "3", 1, 0)
		jFailed := newJob(iprName, "rsi-dev-packages-4", "4", 0, 1)
		jCurrent := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)

		r, c := buildRcnl(jSucceeded, jFailed, jCurrent)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-6"))
	})

	It("preserves the current-generation Job", func() {
		jCurrent := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)

		r, c := buildRcnl(jCurrent)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-6"))
	})

	It("preserves Jobs labeled at a generation >= current (future or equal)", func() {
		// Defensive: if a newer-gen Job somehow exists (e.g., reconcile reordering),
		// cleanupJobs must not touch it.
		jCurrent := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)
		jFuture := newJob(iprName, "rsi-dev-packages-7", "7", 0, 0)

		r, c := buildRcnl(jCurrent, jFuture)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-6", "rsi-dev-packages-7"))
	})

	It("skips Jobs with a missing or unparseable generation label", func() {
		// Defensive: bad labels should not crash the reconciler nor cause
		// unexpected deletes. The Job is left for an operator to inspect.
		jBad := newJob(iprName, "rsi-dev-packages-x", "not-a-number", 0, 0)
		jBlank := newJob(iprName, "rsi-dev-packages-blank", "", 0, 0)
		delete(jBlank.Labels, "kdex.dev/generation")
		jCurrent := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)

		r, c := buildRcnl(jBad, jBlank, jCurrent)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-x", "rsi-dev-packages-blank", "rsi-dev-packages-6"))
	})

	It("does not touch Jobs belonging to a different IPR", func() {
		// Label-selector scoping: the prior-gen Job for otherIPR must survive
		// even though its generation is lower than ipr.Generation.
		jOtherPrior := newJob(otherIPR, "rsi-other-packages-2", "2", 0, 0)
		jMinePrior := newJob(iprName, "rsi-dev-packages-3", "3", 0, 0)
		jMineCurrent := newJob(iprName, "rsi-dev-packages-6", "6", 0, 0)

		r, c := buildRcnl(jOtherPrior, jMinePrior, jMineCurrent)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-other-packages-2", "rsi-dev-packages-6"))
	})

	It("is a no-op when there are no matching Jobs", func() {
		r, c := buildRcnl()
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(BeEmpty())
	})

	It("handles a wide burst (gen 3..6 simultaneously)", func() {
		// Mirrors the issue #19 repro: parallel jobs from a rapid CR-bump burst.
		objs := []client.Object{}
		for g := int64(3); g <= 6; g++ {
			objs = append(objs, newJob(iprName, fmt.Sprintf("rsi-dev-packages-%d", g), fmt.Sprintf("%d", g), 0, 0))
		}
		r, c := buildRcnl(objs...)
		Expect(r.cleanupJobs(ctx, ipr)).To(Succeed())
		Expect(listJobs(c)).To(ConsistOf("rsi-dev-packages-6"))
	})
})

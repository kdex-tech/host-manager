/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// TestReferencedResourcePredicate pins the watch-side guard for
// kdex-tech/host-manager#129: the kdexpage controller watches referenced
// resources (KDexApp, headers, footers, navigations, archetypes, script
// libraries, the host) to re-render pages when they change. A noisy upstream
// operator that rewrites a referenced resource's status conditions'
// LastTransitionTime ~2x/sec (observed on KDexApp) must NOT re-enqueue and
// re-render every page — that pegs a CPU core on meaningless churn.
//
// The guard filters ONLY pure noise (resourceVersion + managedFields +
// per-condition LastTransitionTime). It must still pass every meaningful
// change, including status content that carries indirect-dependency
// propagation: e.g. an archetype re-publishing a referenced header's
// generation into status.Attributes is how a header edit reaches a page that
// references the header only through the archetype's default. Filtering that
// (as a plain GenerationChangedPredicate would) breaks indirect updates.
func TestReferencedResourcePredicate(t *testing.T) {
	t1 := metav1.NewTime(time.Now())
	t2 := metav1.NewTime(t1.Add(time.Second))

	base := &kdexv1alpha1.KDexApp{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "app",
			Namespace:       "default",
			Generation:      3,
			ResourceVersion: "100",
		},
		Status: kdexv1alpha1.KDexObjectStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(kdexv1alpha1.ConditionTypeReady),
					Status:             metav1.ConditionTrue,
					Reason:             string(kdexv1alpha1.ConditionReasonReconcileSuccess),
					Message:            "ready",
					LastTransitionTime: t1,
				},
			},
		},
	}

	t.Run("status/lastTransitionTime-only churn is filtered", func(t *testing.T) {
		// Exactly the #129 scenario: an upstream operator rewrites the
		// condition's LastTransitionTime (bumping resourceVersion) without any
		// spec change.
		updated := base.DeepCopy()
		updated.ResourceVersion = "101"
		updated.Status.Conditions[0].LastTransitionTime = t2

		if referencedResourcePredicate.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: updated}) {
			t.Error("a status/LastTransitionTime-only update must NOT re-enqueue pages")
		}
	})

	t.Run("spec change (generation bump) re-enqueues", func(t *testing.T) {
		updated := base.DeepCopy()
		updated.ResourceVersion = "102"
		updated.Generation = 4 // spec change bumps generation

		if !referencedResourcePredicate.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: updated}) {
			t.Error("a spec change (generation bump) must re-enqueue pages")
		}
	})

	t.Run("status content change (not just timestamps) re-enqueues", func(t *testing.T) {
		// An archetype re-publishing a referenced header's generation into
		// status.Attributes has the same generation but genuinely-changed
		// status — this is how indirect dependency edits reach a page. It must
		// re-enqueue. (A plain GenerationChangedPredicate would wrongly drop it,
		// breaking "updates when an indirect dependency is updated".)
		updated := base.DeepCopy()
		updated.ResourceVersion = "103"
		if updated.Status.Attributes == nil {
			updated.Status.Attributes = map[string]string{}
		}
		updated.Status.Attributes["header.generation"] = "2"

		if !referencedResourcePredicate.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: updated}) {
			t.Error("a real status content change must re-enqueue pages")
		}
	})

	t.Run("condition status/reason transition re-enqueues", func(t *testing.T) {
		updated := base.DeepCopy()
		updated.ResourceVersion = "104"
		updated.Status.Conditions[0].Status = metav1.ConditionFalse
		updated.Status.Conditions[0].Reason = string(kdexv1alpha1.ConditionReasonReconcileError)
		updated.Status.Conditions[0].LastTransitionTime = t2

		if !referencedResourcePredicate.Update(event.UpdateEvent{ObjectOld: base, ObjectNew: updated}) {
			t.Error("a genuine condition transition must re-enqueue pages")
		}
	})

	t.Run("create re-enqueues", func(t *testing.T) {
		if !referencedResourcePredicate.Create(event.CreateEvent{Object: base}) {
			t.Error("a create must re-enqueue pages (a newly-appearing dependency can settle a page)")
		}
	})

	t.Run("delete re-enqueues", func(t *testing.T) {
		if !referencedResourcePredicate.Delete(event.DeleteEvent{Object: base}) {
			t.Error("a delete must re-enqueue pages (a removed dependency degrades the page)")
		}
	})
}

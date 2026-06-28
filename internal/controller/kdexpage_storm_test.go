/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrl "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
)

// pageStormScheme registers the types the KDexPage reconcile path touches.
func pageStormScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := kdexv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

const pageStormHost = "storm-host"

// stormReadyArchetype returns a KDexPageArchetype already marked Ready=True so
// the page reconcile can resolve it and settle on its own happy path.
func stormReadyArchetype(namespace string) *kdexv1alpha1.KDexPageArchetype {
	return &kdexv1alpha1.KDexPageArchetype{
		ObjectMeta: metav1.ObjectMeta{Name: "storm-archetype", Namespace: namespace},
		Spec: kdexv1alpha1.KDexPageArchetypeSpec{
			Content: "<h1>Hello, World!</h1>",
		},
		Status: kdexv1alpha1.KDexObjectStatus{
			Conditions: []metav1.Condition{
				{
					Type:    string(kdexv1alpha1.ConditionTypeReady),
					Status:  metav1.ConditionTrue,
					Reason:  string(kdexv1alpha1.ConditionReasonReconcileSuccess),
					Message: "ready",
				},
			},
		},
	}
}

// stormPage returns a KDexPage with the finalizer already present (so the
// reconcile skips the finalizer-add pass) and an inline content entry plus the
// ready archetype reference, which is everything it needs to settle Ready.
func stormPage(namespace string) *kdexv1alpha1.KDexPage {
	return &kdexv1alpha1.KDexPage{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "storm-page",
			Namespace:  namespace,
			Finalizers: []string{internal.PAGE_FINALIZER},
		},
		Spec: kdexv1alpha1.KDexPageSpec{
			ContentEntries: []kdexv1alpha1.ContentEntry{
				{
					ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
						RawHTML: "<h1>Hello, World!</h1>",
					},
					Slot: "main",
				},
			},
			HostRef: corev1.LocalObjectReference{Name: pageStormHost},
			Label:   "foo",
			PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
				Kind: "KDexPageArchetype",
				Name: "storm-archetype",
			},
			Paths: kdexv1alpha1.Paths{BasePath: "/foo"},
		},
	}
}

// newPageStormClient builds a fake client that counts status-subresource
// updates so a test can assert the reconcile path doesn't churn status when
// nothing changed (kdex-tech/host-manager#126).
func newPageStormClient(t *testing.T, statusUpdates *int, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(pageStormScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kdexv1alpha1.KDexPage{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if subResourceName == "status" {
					*statusUpdates++
				}
				return c.SubResource(subResourceName).Update(ctx, obj, opts...)
			},
		}).
		Build()
}

func newPageStormReconciler(t *testing.T, c client.Client) *KDexPageReconciler {
	t.Helper()
	cm, err := cache.NewCacheManager("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	hh := host.NewHostHandler(c, pageStormHost, "default", logr.Discard(), cm)
	return &KDexPageReconciler{
		Client:              c,
		ControllerNamespace: "default",
		FocalHost:           pageStormHost,
		HostHandler:         hh,
		Scheme:              c.Scheme(),
	}
}

// TestKDexPageReconcile_SkipsRedundantStatusWrite pins the fix for
// kdex-tech/host-manager#126: once a KDexPage has settled Ready, a repeat
// reconcile with no underlying change must NOT issue another Status().Update().
//
// Pre-fix the reconciler pulsed a transient "Reconciling" condition at the top
// of every pass (Progressing=True, Ready=Unknown) and then unconditionally
// wrote the settled status, which bumped LastTransitionTime on Ready/Progressing
// every reconcile even when the net status was unchanged. That bumped
// resourceVersion, re-fired the controller's own For() watch, and looped
// (~25 reconciles/sec, pegging a CPU core).
func TestKDexPageReconcile_SkipsRedundantStatusWrite(t *testing.T) {
	ctx := context.Background()
	const namespace = "default"

	var statusUpdates int
	c := newPageStormClient(t, &statusUpdates, stormReadyArchetype(namespace), stormPage(namespace))
	r := newPageStormReconciler(t, c)
	key := client.ObjectKey{Name: "storm-page", Namespace: namespace}
	req := ctrl.Request{NamespacedName: key}

	// First reconcile settles the page Ready and writes status exactly once.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if statusUpdates != 1 {
		t.Fatalf("expected exactly 1 status write on first reconcile, got %d", statusUpdates)
	}

	page := &kdexv1alpha1.KDexPage{}
	if err := c.Get(ctx, key, page); err != nil {
		t.Fatal(err)
	}
	if !meta_IsReadyTrue(page) {
		t.Fatalf("expected page Ready=True after first reconcile, conditions=%+v", page.Status.Conditions)
	}

	// Steady-state reconciles must not re-write status. Pre-fix each of these
	// bumped LastTransitionTime and wrote, driving the self-loop.
	for i := 0; i < 3; i++ {
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("steady-state reconcile %d: %v", i, err)
		}
	}
	if statusUpdates != 1 {
		t.Fatalf("steady-state reconciles must not re-write status; status writes=%d (want 1)", statusUpdates)
	}
}

func meta_IsReadyTrue(page *kdexv1alpha1.KDexPage) bool {
	for _, cond := range page.Status.Conditions {
		if cond.Type == string(kdexv1alpha1.ConditionTypeReady) {
			return cond.Status == metav1.ConditionTrue
		}
	}
	return false
}

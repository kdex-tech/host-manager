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
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	ctrl "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"kdex.dev/crds/configuration"

	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
)

// TestFunctionStatusEqual pins the functionStatusEqual helper added for
// kdex-tech/host-manager#131: the origin-path defer in kdexfunction_controller.go
// pulses a transient "Reconciling" condition every pass, and this helper is what
// lets that defer skip the write when nothing of substance changed.
// KDexFunctionStatus embeds KDexObjectStatus but adds function-specific fields
// (State, URL, Executable, Generator, Source, Detail, ...) that the generic
// objectStatusEqual helper doesn't see, so functionStatusEqual has to be pinned
// separately. Mirrors TestObjectStatusEqual in reconcile_storm_test.go.
func TestFunctionStatusEqual(t *testing.T) {
	t1 := metav1.NewTime(time.Now())
	t2 := metav1.NewTime(t1.Add(7 * time.Minute))

	base := kdexv1alpha1.KDexFunctionStatus{
		KDexObjectStatus: kdexv1alpha1.KDexObjectStatus{
			ObservedGeneration: 5,
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ok", Message: "ready", LastTransitionTime: t1},
			},
		},
		State: kdexv1alpha1.KDexFunctionStatePending,
		URL:   "http://fn-storm.default.svc.cluster.local",
	}

	t.Run("transition-time-only difference is equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.Conditions[0].LastTransitionTime = t2
		if !functionStatusEqual(&base, &other) {
			t.Error("statuses differing only by LastTransitionTime must be considered equal")
		}
	})

	t.Run("state change is not equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.State = kdexv1alpha1.KDexFunctionStateReady
		if functionStatusEqual(&base, &other) {
			t.Error("a State change must not be considered equal")
		}
	})

	t.Run("url change is not equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.URL = "http://fn-storm-2.default.svc.cluster.local"
		if functionStatusEqual(&base, &other) {
			t.Error("a URL change must not be considered equal")
		}
	})

	t.Run("condition status change is not equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.Conditions[0].Status = metav1.ConditionFalse
		other.Conditions[0].LastTransitionTime = t2
		if functionStatusEqual(&base, &other) {
			t.Error("a real condition Status change must not be considered equal")
		}
	})
}

const translationStormHost = "storm-host"

// stormTranslation returns a KDexInternalTranslation with the finalizer already
// present (so the reconcile skips the finalizer-add pass) and a minimal spec, so
// a single reconcile settles Ready.
func stormTranslation(namespace string) *kdexv1alpha1.KDexInternalTranslation {
	return &kdexv1alpha1.KDexInternalTranslation{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "storm-translation",
			Namespace:  namespace,
			Finalizers: []string{internal.TRANSLATION_FINALIZER},
		},
		Spec: kdexv1alpha1.KDexInternalTranslationSpec{
			HostRef: corev1.LocalObjectReference{Name: translationStormHost},
			KDexTranslationSpec: kdexv1alpha1.KDexTranslationSpec{
				Translations: []kdexv1alpha1.Translation{
					{
						Lang:          "en",
						KeysAndValues: map[string]string{"hello": "Hello"},
					},
				},
			},
		},
	}
}

// newTranslationStormClient builds a fake client that counts status-subresource
// updates so a test can assert the reconcile path doesn't churn status when
// nothing changed (kdex-tech/host-manager#131).
func newTranslationStormClient(t *testing.T, statusUpdates *int, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(pageStormScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kdexv1alpha1.KDexInternalTranslation{}).
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

func newTranslationStormReconciler(t *testing.T, c client.Client) *KDexInternalTranslationReconciler {
	t.Helper()
	cm, err := cache.NewCacheManager("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	hh := host.NewHostHandler(c, translationStormHost, "default", logr.Discard(), cm)
	return &KDexInternalTranslationReconciler{
		Client:              c,
		ControllerNamespace: "default",
		FocalHost:           translationStormHost,
		HostHandler:         hh,
		Scheme:              c.Scheme(),
	}
}

// TestKDexInternalTranslationReconcile_SkipsRedundantStatusWrite pins the fix
// for kdex-tech/host-manager#131: once a KDexInternalTranslation has settled
// Ready, a repeat reconcile with no underlying change must NOT issue another
// Status().Update().
//
// Pre-fix the reconciler pulsed a transient "Reconciling" condition at the top
// of every pass (Progressing=True, Ready=Unknown) and then unconditionally wrote
// the settled status, which bumped LastTransitionTime on Ready/Progressing every
// reconcile even when the net status was unchanged. That bumped resourceVersion,
// re-fired the controller's own For() watch, and looped (pegging a CPU core).
func TestKDexInternalTranslationReconcile_SkipsRedundantStatusWrite(t *testing.T) {
	ctx := context.Background()
	const namespace = "default"

	var statusUpdates int
	c := newTranslationStormClient(t, &statusUpdates, stormTranslation(namespace))
	r := newTranslationStormReconciler(t, c)
	key := client.ObjectKey{Name: "storm-translation", Namespace: namespace}
	req := ctrl.Request{NamespacedName: key}

	// First reconcile settles the translation Ready and writes status exactly once.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if statusUpdates != 1 {
		t.Fatalf("expected exactly 1 status write on first reconcile, got %d", statusUpdates)
	}

	translation := &kdexv1alpha1.KDexInternalTranslation{}
	if err := c.Get(ctx, key, translation); err != nil {
		t.Fatal(err)
	}
	if !meta_IsTranslationReadyTrue(translation) {
		t.Fatalf("expected translation Ready=True after first reconcile, conditions=%+v", translation.Status.Conditions)
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

func meta_IsTranslationReadyTrue(translation *kdexv1alpha1.KDexInternalTranslation) bool {
	for _, cond := range translation.Status.Conditions {
		if cond.Type == string(kdexv1alpha1.ConditionTypeReady) {
			return cond.Status == metav1.ConditionTrue
		}
	}
	return false
}

const utilityPageStormHost = "storm-host"

// stormDefaultClusterArchetype returns a KDexClusterPageArchetype labeled as
// the cluster default. ResolveOrDefaultPageArchetype falls back to listing
// KDexClusterPageArchetypes with label kdex.dev/default=true when the utility
// page doesn't set PageArchetypeRef, and (unlike the explicit-ref path) that
// fallback doesn't gate on Ready, so no status is needed here.
func stormDefaultClusterArchetype() *kdexv1alpha1.KDexClusterPageArchetype {
	return &kdexv1alpha1.KDexClusterPageArchetype{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "storm-default-archetype",
			Labels: map[string]string{"kdex.dev/default": "true"},
		},
		Spec: kdexv1alpha1.KDexPageArchetypeSpec{
			Content: "<h1>Hello, World!</h1>",
		},
	}
}

// stormUtilityPage returns a KDexInternalUtilityPage with the finalizer
// already present and a single "main" RawHTML content entry, which is
// everything ResolveContents needs to resolve inline (no client fetch). No
// PageArchetypeRef, footer/header overrides, or navigation refs are set, so
// the reconcile falls back to the default cluster archetype and skips the
// optional footer/header/navigation/script-library resolution branches
// entirely.
func stormUtilityPage(namespace string) *kdexv1alpha1.KDexInternalUtilityPage {
	return &kdexv1alpha1.KDexInternalUtilityPage{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "storm-utilitypage",
			Namespace:  namespace,
			Finalizers: []string{UTILITY_PAGE_FINALIZER},
		},
		Spec: kdexv1alpha1.KDexInternalUtilityPageSpec{
			HostRef: corev1.LocalObjectReference{Name: utilityPageStormHost},
			KDexUtilityPageSpec: kdexv1alpha1.KDexUtilityPageSpec{
				Type: kdexv1alpha1.ErrorUtilityPageType,
				ContentEntries: []kdexv1alpha1.ContentEntry{
					{
						Slot: "main",
						ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
							RawHTML: "<p>Not Found</p>",
						},
					},
				},
			},
		},
	}
}

// newUtilityPageStormClient builds a fake client that counts status-subresource
// updates so a test can assert the reconcile path doesn't churn status when
// nothing changed (kdex-tech/host-manager#131).
func newUtilityPageStormClient(t *testing.T, statusUpdates *int, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(pageStormScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kdexv1alpha1.KDexInternalUtilityPage{}).
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

func newUtilityPageStormReconciler(t *testing.T, c client.Client) *KDexInternalUtilityPageReconciler {
	t.Helper()
	cm, err := cache.NewCacheManager("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	hh := host.NewHostHandler(c, utilityPageStormHost, "default", logr.Discard(), cm)
	return &KDexInternalUtilityPageReconciler{
		Client:              c,
		Configuration:       configuration.NexusConfiguration{},
		ControllerNamespace: "default",
		FocalHost:           utilityPageStormHost,
		HostHandler:         hh,
		Scheme:              c.Scheme(),
	}
}

// TestKDexInternalUtilityPageReconcile_SkipsRedundantStatusWrite pins the fix
// for kdex-tech/host-manager#131: once a KDexInternalUtilityPage has settled
// Ready, a repeat reconcile with no underlying change must NOT issue another
// Status().Update(). Mirrors TestKDexPageReconcile_SkipsRedundantStatusWrite
// (kdexpage_storm_test.go, #126) and
// TestKDexInternalTranslationReconcile_SkipsRedundantStatusWrite above.
func TestKDexInternalUtilityPageReconcile_SkipsRedundantStatusWrite(t *testing.T) {
	ctx := context.Background()
	const namespace = "default"

	var statusUpdates int
	c := newUtilityPageStormClient(t, &statusUpdates, stormDefaultClusterArchetype(), stormUtilityPage(namespace))
	r := newUtilityPageStormReconciler(t, c)
	key := client.ObjectKey{Name: "storm-utilitypage", Namespace: namespace}
	req := ctrl.Request{NamespacedName: key}

	// First reconcile settles the utility page Ready and writes status exactly once.
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if statusUpdates != 1 {
		t.Fatalf("expected exactly 1 status write on first reconcile, got %d", statusUpdates)
	}

	utilityPage := &kdexv1alpha1.KDexInternalUtilityPage{}
	if err := c.Get(ctx, key, utilityPage); err != nil {
		t.Fatal(err)
	}
	if !meta_IsUtilityPageReadyTrue(utilityPage) {
		t.Fatalf("expected utility page Ready=True after first reconcile, conditions=%+v", utilityPage.Status.Conditions)
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

func meta_IsUtilityPageReadyTrue(utilityPage *kdexv1alpha1.KDexInternalUtilityPage) bool {
	for _, cond := range utilityPage.Status.Conditions {
		if cond.Type == string(kdexv1alpha1.ConditionTypeReady) {
			return cond.Status == metav1.ConditionTrue
		}
	}
	return false
}

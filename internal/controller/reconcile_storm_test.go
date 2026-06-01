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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// stormScheme registers the types the service-backed reconcile path touches.
func stormScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := kdexv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func stormServiceBackedFunction(svcName string) *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-storm", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/v1/docs",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/v1/docs/find": {Get: &runtime.RawExtension{Raw: []byte("{}")}},
				},
			},
			Backend: &kdexv1alpha1.FunctionBackend{
				Type: kdexv1alpha1.FunctionBackendTypeService,
				Service: &kdexv1alpha1.ServiceBackend{
					Name:   svcName,
					Port:   intstr.FromInt(8080),
					Scheme: "http",
					Path:   "/api",
				},
			},
		},
	}
}

// newStormClient builds a fake client that counts status-subresource updates so
// a test can assert the reconcile path doesn't churn the status when nothing
// changed (kdex-tech/host-manager#102, Fix A).
func newStormClient(t *testing.T, statusUpdates *int, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(stormScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&kdexv1alpha1.KDexFunction{}).
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

// TestReconcileServiceBacked_SkipsRedundantStatusWrite pins Fix A from
// kdex-tech/host-manager#102: once a service-backed function is Ready, a repeat
// reconcile with no underlying change must NOT issue another Status().Update().
// Pre-fix the happy path wrote status unconditionally, self-amplifying every
// upstream ping into a burst of reconciles via the controller's own For() watch.
func TestReconcileServiceBacked_SkipsRedundantStatusWrite(t *testing.T) {
	ctx := context.Background()
	ready := true
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "knowdb", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt(8080)}},
		},
	}
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "knowdb-1",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "knowdb"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		Ports:       []discoveryv1.EndpointPort{{Name: ptr.To("http"), Port: ptr.To[int32](8080)}},
	}

	var statusUpdates int
	c := newStormClient(t, &statusUpdates, svc, es, stormServiceBackedFunction("knowdb"))
	r := &KDexFunctionReconciler{Client: c, Scheme: c.Scheme()}
	key := client.ObjectKey{Name: "fn-storm", Namespace: "default"}

	// First reconcile resolves the backend and writes Ready exactly once.
	fn := &kdexv1alpha1.KDexFunction{}
	if err := c.Get(ctx, key, fn); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileServiceBacked(ctx, fn); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if statusUpdates != 1 {
		t.Fatalf("expected exactly 1 status write on first reconcile, got %d", statusUpdates)
	}
	if fn.Status.State != kdexv1alpha1.KDexFunctionStateReady {
		t.Fatalf("expected Ready, got %q", fn.Status.State)
	}

	// Re-fetch the now-Ready function and reconcile again with no change: the
	// status is byte-stable, so no second write may be issued.
	fn2 := &kdexv1alpha1.KDexFunction{}
	if err := c.Get(ctx, key, fn2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reconcileServiceBacked(ctx, fn2); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if statusUpdates != 1 {
		t.Fatalf("steady-state reconcile must not re-write status; status writes=%d (want 1)", statusUpdates)
	}
}

// TestMarkBackendUnready_SkipsRedundantStatusWrite pins the same diff guard on
// the unready path: repeated ServiceNotFound polls must not churn status.
func TestMarkBackendUnready_SkipsRedundantStatusWrite(t *testing.T) {
	ctx := context.Background()

	var statusUpdates int
	// No Service object exists -> ServiceNotFound -> markBackendUnready.
	c := newStormClient(t, &statusUpdates, stormServiceBackedFunction("ghost"))
	r := &KDexFunctionReconciler{Client: c, Scheme: c.Scheme()}
	key := client.ObjectKey{Name: "fn-storm", Namespace: "default"}

	for i := 0; i < 3; i++ {
		fn := &kdexv1alpha1.KDexFunction{}
		if err := c.Get(ctx, key, fn); err != nil {
			t.Fatal(err)
		}
		if _, err := r.reconcileServiceBacked(ctx, fn); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	if statusUpdates != 1 {
		t.Fatalf("expected exactly 1 status write across 3 unready reconciles, got %d", statusUpdates)
	}
}

// TestInternalHostStatusEqual pins Fix C's comparison helper from
// kdex-tech/host-manager#102: per-condition LastTransitionTime must be ignored
// (the reconciler pulses a transient Reconciling condition every pass), while
// genuine status changes must still register as different.
func TestInternalHostStatusEqual(t *testing.T) {
	t1 := metav1.NewTime(time.Now())
	t2 := metav1.NewTime(t1.Add(7 * time.Minute))

	base := kdexv1alpha1.KDexObjectStatus{
		ObservedGeneration: 5,
		Conditions: []metav1.Condition{
			{Type: "Ready", Status: metav1.ConditionTrue, Reason: "ok", Message: "ready", LastTransitionTime: t1},
		},
	}

	t.Run("transition-time-only difference is equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.Conditions[0].LastTransitionTime = t2
		if !internalHostStatusEqual(&base, &other) {
			t.Error("statuses differing only by LastTransitionTime must be considered equal")
		}
	})

	t.Run("condition status change is not equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.Conditions[0].Status = metav1.ConditionFalse
		other.Conditions[0].LastTransitionTime = t2
		if internalHostStatusEqual(&base, &other) {
			t.Error("a real condition Status change must not be considered equal")
		}
	})

	t.Run("observedGeneration change is not equal", func(t *testing.T) {
		other := *base.DeepCopy()
		other.ObservedGeneration = 6
		if internalHostStatusEqual(&base, &other) {
			t.Error("an ObservedGeneration change must not be considered equal")
		}
	})
}

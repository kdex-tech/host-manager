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

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func funcWith(gen int64, state kdexv1alpha1.KDexFunctionState, url string) *kdexv1alpha1.KDexFunction {
	f := &kdexv1alpha1.KDexFunction{ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "dev"}}
	f.Generation = gen
	f.Status.State = state
	f.Status.URL = url
	return f
}

// TestFunctionHostWatchPredicate pins kdex-tech/host-manager#116 while
// preserving #112. The host mounts a function's proxy route only when the
// function is Ready (host.go), and the host's function list is refreshed by the
// KDexInternalHost reconcile. #112 added GenerationChangedPredicate to the
// host's KDexFunction watch to drop the high-frequency observe-tick status
// writes — but that also dropped the Pending->Ready / URL-populated transition,
// so a newly-Ready function's route wasn't registered until a host-manager
// restart. The predicate must wake the host on route-relevant changes (Ready
// transition, URL change, spec/generation change) while still filtering
// steady-state status churn.
func TestFunctionHostWatchPredicate(t *testing.T) {
	const (
		pending = kdexv1alpha1.KDexFunctionStatePending
		ready   = kdexv1alpha1.KDexFunctionStateReady
	)

	tests := []struct {
		name     string
		oldFn    *kdexv1alpha1.KDexFunction
		newFn    *kdexv1alpha1.KDexFunction
		wantPass bool
	}{
		{
			name:     "Pending->Ready (URL populated) must wake the host (#116)",
			oldFn:    funcWith(2, pending, ""),
			newFn:    funcWith(2, ready, "http://svc.dev.svc.cluster.local"),
			wantPass: true,
		},
		{
			name:     "URL change on a Ready function must wake the host",
			oldFn:    funcWith(2, ready, "http://old.dev.svc.cluster.local"),
			newFn:    funcWith(2, ready, "http://new.dev.svc.cluster.local"),
			wantPass: true,
		},
		{
			name:     "Ready->not-Ready (backend lost) must wake the host to unmount",
			oldFn:    funcWith(2, ready, "http://svc.dev.svc.cluster.local"),
			newFn:    funcWith(2, pending, "http://svc.dev.svc.cluster.local"),
			wantPass: true,
		},
		{
			name:     "spec/generation change must wake the host",
			oldFn:    funcWith(2, ready, "http://svc.dev.svc.cluster.local"),
			newFn:    funcWith(3, ready, "http://svc.dev.svc.cluster.local"),
			wantPass: true,
		},
		{
			name:     "steady-state status churn is filtered (#112)",
			oldFn:    funcWith(2, ready, "http://svc.dev.svc.cluster.local"),
			newFn:    funcWith(2, ready, "http://svc.dev.svc.cluster.local"),
			wantPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := functionHostWatchPredicate.Update(event.UpdateEvent{ObjectOld: tt.oldFn, ObjectNew: tt.newFn})
			if got != tt.wantPass {
				t.Errorf("Update predicate = %v, want %v", got, tt.wantPass)
			}
		})
	}

	// Create / Delete must always pass so initial wiring and teardown still
	// reach the host.
	if !functionHostWatchPredicate.Create(event.CreateEvent{Object: funcWith(1, ready, "http://svc")}) {
		t.Error("Create event must pass the predicate")
	}
	if !functionHostWatchPredicate.Delete(event.DeleteEvent{Object: funcWith(1, ready, "http://svc")}) {
		t.Error("Delete event must pass the predicate")
	}
}

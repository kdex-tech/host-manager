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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// TestHandleExecutableAvailable_SelfHealsNilStatusExecutable pins the
// fix for kdex-tech/host-manager#77. handleExecutableAvailable runs
// when the controller sees a function already at state=
// ExecutableAvailable — but in some pre-upgrade scenarios (older binary
// landed the state without populating Status.Executable, or a partial
// status write between handlers), it reaches this handler with
// Status.Executable=nil. Pre-fix the handler called deployer.Deploy
// directly, which rejects "function … has no executable" and
// permanently wedges the reconcile loop with no self-heal — the
// populate site (handleOpenAPIValid) never re-runs.
//
// Post-fix the handler re-derives Status.Executable from
// Spec.Origin.Executable (the case for executable-origin functions),
// or steps state back to OpenAPIValid (the case where Spec doesn't
// declare an executable). Mirrors the existing self-heal in
// handleReady (line 1409).
func TestHandleExecutableAvailable_SelfHealsNilStatusExecutable(t *testing.T) {
	r := &KDexFunctionReconciler{
		RequeueDelay: 50 * time.Millisecond,
	}

	t.Run("spec has executable: re-derive from spec", func(t *testing.T) {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				Origin: kdexv1alpha1.FunctionOrigin{
					Executable: &kdexv1alpha1.Executable{
						Image: "ghcr.io/example/fn:v1",
					},
				},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{
				State:      kdexv1alpha1.KDexFunctionStateExecutableAvailable,
				Executable: nil, // ← the wedge state
			},
		}
		hc := handlerContext{
			ctx:      context.Background(),
			function: fn,
		}
		res, err := r.handleExecutableAvailable(hc)
		require.NoError(t, err, "self-heal must not return an error")
		assert.NotZero(t, res.RequeueAfter, "must requeue after self-heal so the next loop re-enters with populated Executable")
		require.NotNil(t, fn.Status.Executable, "Status.Executable must be re-derived from Spec.Origin.Executable (#77)")
		assert.Equal(t, "ghcr.io/example/fn:v1", fn.Status.Executable.Image)
	})

	t.Run("spec has no executable: step back to OpenAPIValid", func(t *testing.T) {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				Origin: kdexv1alpha1.FunctionOrigin{},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{
				State:      kdexv1alpha1.KDexFunctionStateExecutableAvailable,
				Executable: nil,
			},
		}
		hc := handlerContext{
			ctx:      context.Background(),
			function: fn,
		}
		res, err := r.handleExecutableAvailable(hc)
		require.NoError(t, err, "step-back must not return an error")
		assert.NotZero(t, res.RequeueAfter, "must requeue so OpenAPIValid handler runs")
		assert.Equal(t, kdexv1alpha1.KDexFunctionStateOpenAPIValid, fn.Status.State,
			"must step state back so the populate site re-runs (#77)")
	})
}

// Compile-time interface check — keeps the signature pinned so a
// refactor that drops the handlerContext parameter still surfaces in
// CI.
var _ = func() ctrl.Result {
	r := &KDexFunctionReconciler{}
	res, _ := r.handleExecutableAvailable(handlerContext{})
	return res
}

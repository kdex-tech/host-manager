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
)

// TestHandleReady_SelfHealsNilStatusSource pins the fix for
// kdex-tech/host-manager#136. A source-authoritative function (Spec.Origin.Source
// set, Executable nil) that reaches state=Ready with Status.Source==nil is
// permanently invisible to the kpack drift check at the top of Reconcile — that
// check is gated on Status.Source != nil, so new kpack builds advance
// Image.status.latestImage but never deploy, and the function reports Ready on a
// stale image forever. It never self-heals: the only site populating
// Status.Source from Spec.Origin.Source (handleBuildValid) is unreachable once
// Ready. handleReady already self-heals the sibling field (Status.Executable,
// #77) but had no equivalent for Status.Source.
//
// Post-fix handleReady re-derives Status.Source from Spec.Origin.Source when it
// is nil and requeues, so the next loop's drift check promotes the already-built
// image with no rebuild. Only when nil — never overwriting a codegen-resolved
// revision (#38).
func TestHandleReady_SelfHealsNilStatusSource(t *testing.T) {
	r := &KDexFunctionReconciler{
		RequeueDelay: 50 * time.Millisecond,
	}

	t.Run("source-authoritative Ready with nil Status.Source: re-derive from spec", func(t *testing.T) {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				Origin: kdexv1alpha1.FunctionOrigin{
					Source: &kdexv1alpha1.Source{
						Repository: "https://gitlab.com/example/repo.git",
						Revision:   "main",
						Path:       "functions/fn",
					},
				},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{
				State:  kdexv1alpha1.KDexFunctionStateReady,
				Source: nil, // ← the wedge state (#136)
				// A deployed image is present (Executable != nil): this is the
				// exact scenario the #77 Executable self-heal does NOT catch.
				Executable: &kdexv1alpha1.Executable{Image: "ghcr.io/example/fn@sha256:old"},
			},
		}
		hc := handlerContext{
			ctx:      context.Background(),
			function: fn,
		}

		res, err := r.handleReady(hc)

		require.NoError(t, err, "self-heal must not return an error")
		assert.NotZero(t, res.RequeueAfter, "must requeue so the next loop's drift check promotes the already-built image")
		require.NotNil(t, fn.Status.Source, "Status.Source must be re-derived from Spec.Origin.Source (#136)")
		assert.Equal(t, "main", fn.Status.Source.Revision)
		assert.Equal(t, "functions/fn", fn.Status.Source.Path)
	})

	t.Run("already-populated Status.Source is never clobbered", func(t *testing.T) {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				Origin: kdexv1alpha1.FunctionOrigin{
					Source: &kdexv1alpha1.Source{
						Repository: "https://gitlab.com/example/repo.git",
						Revision:   "main",
						Path:       "functions/fn",
					},
				},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{
				State: kdexv1alpha1.KDexFunctionStateReady,
				// A codegen-resolved SHA already sits in Status.Source; the
				// self-heal must leave it untouched (#38).
				Source: &kdexv1alpha1.Source{
					Repository: "https://gitlab.com/example/repo.git",
					Revision:   "abc1234deadbeef",
					Path:       "functions/fn",
				},
				Executable: &kdexv1alpha1.Executable{Image: "ghcr.io/example/fn@sha256:cur"},
			},
		}
		hc := handlerContext{
			ctx:      context.Background(),
			function: fn,
		}

		_, err := r.handleReady(hc)

		require.NoError(t, err)
		require.NotNil(t, fn.Status.Source)
		assert.Equal(t, "abc1234deadbeef", fn.Status.Source.Revision,
			"must never overwrite a populated (codegen-resolved) revision (#38)")
	})
}

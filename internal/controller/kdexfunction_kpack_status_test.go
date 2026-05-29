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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestInspectKPackImageStatus pins the fix for
// kdex-tech/host-manager#94. Pre-fix handleSourceAvailable gated the
// WHOLE conditions inspection (Ready=True and Failed=True both) on
// `observedGeneration >= imgUnstruct.GetGeneration()`. When kpack
// lagged reconciling its own Image (pod restart, stuck webhook, etc.)
// observedGeneration trailed metadata.generation indefinitely, the
// Failed=True signal was discarded, and the function infinite-looped
// at Progressing=True / Degraded=False — operators saw no alert
// despite a clear terminal build failure.
//
// Post-fix Failed=True surfaces regardless of observedGeneration
// staleness (a Failed signal from any generation is real). Ready=True
// stays gated on observedGeneration >= generation so a stale success
// from before the operator's most recent spec edit doesn't promote
// the function to Ready before kpack catches up.
func TestInspectKPackImageStatus(t *testing.T) {
	const currentGen int64 = 5

	mkImg := func(generation, observed int64, conditions []any) *unstructured.Unstructured {
		u := &unstructured.Unstructured{}
		u.SetGeneration(generation)
		u.Object = map[string]any{
			"metadata": map[string]any{"generation": generation},
			"status": map[string]any{
				"observedGeneration": observed,
				"conditions":         conditions,
			},
		}
		return u
	}

	t.Run("stale Failed=True is surfaced (#94)", func(t *testing.T) {
		// kpack lags: observedGeneration < generation. Pre-fix the
		// Failed=True was discarded; post-fix it surfaces.
		img := mkImg(currentGen, currentGen-1, []any{
			map[string]any{
				"type":    "Failed",
				"status":  "True",
				"message": "ERROR detect failed: unable to fetch image",
			},
		})

		success, failedErr := inspectKPackImageStatus(img)
		assert.False(t, success)
		require.Error(t, failedErr,
			"Failed=True must surface even when observedGeneration < generation (#94)")
	})

	t.Run("current Ready=True is success", func(t *testing.T) {
		img := mkImg(currentGen, currentGen, []any{
			map[string]any{"type": "Ready", "status": "True"},
		})

		success, failedErr := inspectKPackImageStatus(img)
		assert.True(t, success)
		assert.NoError(t, failedErr)
	})

	t.Run("stale Ready=True is NOT trusted", func(t *testing.T) {
		// Ready=True on a prior generation may reflect a build that
		// preceded the operator's latest spec edit. Don't promote to
		// success until kpack has observed the current generation.
		img := mkImg(currentGen, currentGen-1, []any{
			map[string]any{"type": "Ready", "status": "True"},
		})

		success, failedErr := inspectKPackImageStatus(img)
		assert.False(t, success,
			"Ready=True from a stale generation must NOT be accepted as success")
		assert.NoError(t, failedErr)
	})

	t.Run("empty conditions: not success, not failed", func(t *testing.T) {
		img := mkImg(currentGen, currentGen, []any{})
		success, failedErr := inspectKPackImageStatus(img)
		assert.False(t, success)
		assert.NoError(t, failedErr)
	})

	t.Run("current Failed=True is also surfaced (regression baseline)", func(t *testing.T) {
		// The not-stale Failed case was already handled pre-fix.
		// Pin it so the new helper preserves that.
		img := mkImg(currentGen, currentGen, []any{
			map[string]any{
				"type":    "Failed",
				"status":  "True",
				"message": "build failed at fresh generation",
			},
		})

		success, failedErr := inspectKPackImageStatus(img)
		assert.False(t, success)
		require.Error(t, failedErr)
	})

	t.Run("nil image is benign", func(t *testing.T) {
		success, failedErr := inspectKPackImageStatus(nil)
		assert.False(t, success)
		assert.NoError(t, failedErr)
	})
}

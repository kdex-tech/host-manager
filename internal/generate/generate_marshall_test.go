/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package generate

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestMarshall_PropagatesError pins the fix for
// kdex-tech/host-manager#67. Pre-fix, `marshall` discarded
// yaml.Marshal's error: `yamlBytes, _ := yaml.Marshal(...)`. A
// marshal failure (e.g. a future CRD field that adds a yaml.Marshaler
// returning errBoom) silently produced FUNCTION_SPEC="", the codegen
// container exited 0 on empty input, the Job reported success, and
// git-push overwrote the developer's authored cmd/custom.go with a
// generator-default stub.
//
// The fix changes the signature to return (string, error), so a
// revert won't compile. This test also pins the happy-path
// behaviour so a future change doesn't silently start returning
// errors on valid inputs.
func TestMarshall_PropagatesError(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "default", Generation: 1},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/x"},
		},
	}

	// Signature contract: must return (string, error). A revert to the
	// `yamlBytes, _ := yaml.Marshal(...)` form would change the
	// signature back to a single string return and this assignment
	// would fail at compile time.
	out, err := marshall(fn)
	require.NoError(t, err, "marshall must succeed on a valid KDexFunction")
	require.NotEmpty(t, out, "marshall must produce non-empty YAML on a valid KDexFunction (otherwise FUNCTION_SPEC is empty and codegen runs against defaults — #67)")
	require.Contains(t, out, "fn", "produced YAML must include the function name")
}

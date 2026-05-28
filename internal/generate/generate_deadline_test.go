/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package generate

import (
	"context"
	"testing"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/stretchr/testify/assert"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestGenerateJob_ActiveDeadlineSecondsSet pins the fix for
// kdex-tech/host-manager#63: the codegen Job must carry an
// ActiveDeadlineSeconds. Pre-fix only BackoffLimit:3 was set; a pod
// blocked on a slow git checkout / hung generate-code container ran
// forever, BackoffLimit never engaged, and the KDexFunction stayed
// Progressing=True indefinitely.
func TestGenerateJob_ActiveDeadlineSecondsSet(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, batchv1.AddToScheme(scheme))
	assert.NoError(t, kdexv1alpha1.AddToScheme(scheme))

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "dev", Generation: 1, UID: "u-fn"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/x"},
		},
	}

	g := &Generator{
		Client:         fake.NewClientBuilder().WithScheme(scheme).Build(),
		Config:         kdexv1alpha1.Generator{Entrypoint: "main", Image: "gen"},
		GitSecret:      corev1.LocalObjectReference{Name: "git-secret"},
		OpenAPIBuilder: &ko.Builder{},
		Scheme:         scheme,
		ServerUrl:      "http://example.com",
	}

	job, err := g.GetOrCreateGenerateJob(context.Background(), fn)
	assert.NoError(t, err)

	assert.NotNil(t, job.Spec.ActiveDeadlineSeconds,
		"codegen Job must set ActiveDeadlineSeconds (#63) — without it a hung git/generate pod runs forever and BackoffLimit never fires")
	if job.Spec.ActiveDeadlineSeconds != nil {
		assert.Greater(t, *job.Spec.ActiveDeadlineSeconds, int64(0))
		assert.LessOrEqual(t, *job.Spec.ActiveDeadlineSeconds, int64(2*60*60),
			"codegen Job ActiveDeadlineSeconds should be aggressive (≤ 2h)")
	}
}

/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package packref

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestPackRefJob_ActiveDeadlineSecondsSet pins the fix for
// kdex-tech/host-manager#63: the packref Job must carry an
// ActiveDeadlineSeconds. Pre-fix only BackoffLimit:3 was set; a pod
// blocked on npm install / oras push / kaniko-style image push that
// never failed (e.g. registry deadlocked, network half-open) ran
// forever, BackoffLimit never engaged, and the IPR stayed
// Progressing=True indefinitely.
func TestPackRefJob_ActiveDeadlineSecondsSet(t *testing.T) {
	scheme := runtime.NewScheme()
	assert.NoError(t, corev1.AddToScheme(scheme))
	assert.NoError(t, batchv1.AddToScheme(scheme))
	assert.NoError(t, kdexv1alpha1.AddToScheme(scheme))

	ipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "ipr", Namespace: "dev", Generation: 1, UID: "u-ipr"},
	}
	host := &kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev", Generation: 1},
	}

	p := &PackRef{
		Client:       fake.NewClientBuilder().WithScheme(scheme).Build(),
		ConfigMap:    &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "dev"}},
		InternalHost: host,
		ImageRegistry: "example.com",
		NPMSecret:    corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "npmrc", Namespace: "dev"}},
		Log:          logr.Discard(),
		Packages:     &configuration.Packages{PackagerImage: "pkg", ToolsImage: "tools"},
		Scheme:       scheme,
	}

	job, err := p.GetOrCreatePackRefJob(context.Background(), ipr)
	assert.NoError(t, err)

	assert.NotNil(t, job.Spec.ActiveDeadlineSeconds,
		"packref Job must set ActiveDeadlineSeconds (#63) — without it a hung npm/oras pod runs forever and BackoffLimit never fires")
	if job.Spec.ActiveDeadlineSeconds != nil {
		assert.Greater(t, *job.Spec.ActiveDeadlineSeconds, int64(0))
		assert.LessOrEqual(t, *job.Spec.ActiveDeadlineSeconds, int64(2*60*60),
			"packref Job ActiveDeadlineSeconds should be aggressive (≤ 2h)")
	}
}

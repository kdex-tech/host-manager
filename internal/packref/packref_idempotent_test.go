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
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func idempotentTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	require.NoError(t, kdexv1alpha1.AddToScheme(scheme))
	return scheme
}

func newIdempotentPackRef(t *testing.T, scheme *runtime.Scheme) *PackRef {
	t.Helper()
	return &PackRef{
		Client:        fake.NewClientBuilder().WithScheme(scheme).Build(),
		ConfigMap:     &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "dev"}},
		InternalHost:  &kdexv1alpha1.KDexInternalHost{ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev", Generation: 1}},
		ImageRegistry: "example.com",
		NPMSecret:     corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "npmrc", Namespace: "dev"}},
		Log:           logr.Discard(),
		Packages:      &configuration.Packages{PackagerImage: "pkg", ToolsImage: "tools"},
		Scheme:        scheme,
	}
}

func countPackagerJobs(t *testing.T, p *PackRef, ns string) int {
	t.Helper()
	var jobs batchv1.JobList
	require.NoError(t, p.List(context.Background(), &jobs, client.InNamespace(ns), client.MatchingLabels{"app": "packages"}))
	return len(jobs.Items)
}

// TestGetOrCreatePackRefJob_SkipsRebuildWhenImageRecordedForCurrentGen pins
// kdex-tech/host-manager#111: when the packages image for the CURRENT generation
// is already recorded in status, a missing Job object (GC'd after success, or
// reaped on a controller restart) must NOT trigger a full rebuild. The build is
// content-complete for this generation; re-running npm install + image build +
// push is pure waste and (per #110) rolls the packages Deployment.
func TestGetOrCreatePackRefJob_SkipsRebuildWhenImageRecordedForCurrentGen(t *testing.T) {
	scheme := idempotentTestScheme(t)
	p := newIdempotentPackRef(t, scheme)

	ipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "ipr", Namespace: "dev", Generation: 5, UID: "u-ipr"},
	}
	ipr.Status.Attributes = map[string]string{
		"image":     fmt.Sprintf("example.com/%s/packages:%d@sha256:deadbeef", ipr.Name, ipr.Generation),
		"importmap": `{"imports":{}}`,
	}

	job, err := p.GetOrCreatePackRefJob(context.Background(), ipr)
	require.NoError(t, err)

	assert.Nil(t, job, "expected no Job when the image for the current generation is already built (#111)")
	assert.Equal(t, 0, countPackagerJobs(t, p, "dev"),
		"a GC'd Job for an already-built generation must not be re-created (#111)")
}

// TestGetOrCreatePackRefJob_BuildsWhenNoImageRecorded ensures the normal path
// is unaffected: with nothing recorded, the packager Job is created.
func TestGetOrCreatePackRefJob_BuildsWhenNoImageRecorded(t *testing.T) {
	scheme := idempotentTestScheme(t)
	p := newIdempotentPackRef(t, scheme)

	ipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "ipr", Namespace: "dev", Generation: 5, UID: "u-ipr"},
	}

	job, err := p.GetOrCreatePackRefJob(context.Background(), ipr)
	require.NoError(t, err)
	require.NotNil(t, job, "a packager Job must be created when no image is recorded")
	assert.Equal(t, 1, countPackagerJobs(t, p, "dev"))
}

// TestGetOrCreatePackRefJob_RebuildsWhenRecordedImageIsStale ensures a genuine
// generation bump still rebuilds: a recorded image for an OLDER generation must
// not suppress the build for the current generation.
func TestGetOrCreatePackRefJob_RebuildsWhenRecordedImageIsStale(t *testing.T) {
	scheme := idempotentTestScheme(t)
	p := newIdempotentPackRef(t, scheme)

	ipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "ipr", Namespace: "dev", Generation: 6, UID: "u-ipr"},
	}
	// Image recorded for generation 5, but the IPR is now at generation 6.
	ipr.Status.Attributes = map[string]string{
		"image":     fmt.Sprintf("example.com/%s/packages:%d@sha256:deadbeef", ipr.Name, 5),
		"importmap": `{"imports":{}}`,
	}

	job, err := p.GetOrCreatePackRefJob(context.Background(), ipr)
	require.NoError(t, err)
	require.NotNil(t, job, "a stale (older-generation) recorded image must not suppress the rebuild")
	assert.Equal(t, 1, countPackagerJobs(t, p, "dev"))
}

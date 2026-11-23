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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kdex-tech/host-manager/internal"
)

const (
	harvestGoodDigest = "sha256:fbc036ef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	harvestRuncError  = `failed to create containerd task: failed to create shim task: OCI runtime create failed: ` +
		`runc create failed: unable to start container process: error during container init: error mounting ` +
		`"/var/lib/kubelet/pods/x/volume-subpaths/image-push-secret/packager/4" to rootfs at "/shared/config.json": ` +
		`no such file or directory: unknown`
	harvestImportmap = `{"imports":{"lit":"/~/m/lit/index.js"}}`
)

var harvestNow = time.Date(2026, 11, 23, 20, 40, 0, 0, time.UTC)

func harvestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, batchv1.AddToScheme(s))
	require.NoError(t, kdexv1alpha1.AddToScheme(s))
	return s
}

// harvestJob is the rsi-dev-packages-449 shape from #301: a Job that
// succeeded on retry after one Failed pod.
func harvestJob(succeeded, failed int32, completed *time.Time) *batchv1.Job {
	j := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "rsi-dev-packages-449",
			Namespace:   "dev",
			Annotations: map[string]string{internal.ANNOTATION_GENERATION: "449"},
			Labels:      map[string]string{"app": "packages", "packages": "rsi-dev", internal.ANNOTATION_GENERATION: "449"},
		},
		Status: batchv1.JobStatus{Succeeded: succeeded, Failed: failed},
	}
	if completed != nil {
		ct := metav1.NewTime(*completed)
		j.Status.CompletionTime = &ct
	}
	return j
}

func harvestPod(name string, phase corev1.PodPhase, created time.Time, digest, importmap string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "dev",
			Labels:            map[string]string{"job-name": "rsi-dev-packages-449"},
			Annotations:       map[string]string{internal.ANNOTATION_GENERATION: "449"},
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: corev1.PodStatus{
			Phase: phase,
			InitContainerStatuses: []corev1.ContainerStatus{{
				Name:  "importmap-generator",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: importmap}},
			}},
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "packager",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: digest}},
			}},
		},
	}
}

func failedHarvestPod(name string, created time.Time) *corev1.Pod {
	// A runc mount failure terminates the container with the error as its
	// message; the importmap init container did run and emitted output.
	return harvestPod(name, corev1.PodFailed, created, harvestRuncError, harvestImportmap)
}

func harvestIPR() *kdexv1alpha1.KDexInternalPackageReferences {
	ipr := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{Name: "rsi-dev", Namespace: "dev", Generation: 449},
	}
	ipr.Status.Attributes = map[string]string{
		"image":     "reg.example/rsi-dev/packages:448@" + harvestGoodDigest,
		"importmap": `{"imports":{}}`,
	}
	return ipr
}

func runHarvest(t *testing.T, job *batchv1.Job, pods ...*corev1.Pod) (
	*kdexv1alpha1.KDexInternalPackageReferences, packagesHarvest, client.Client,
) {
	t.Helper()
	objs := []client.Object{job}
	for _, p := range pods {
		objs = append(objs, p)
	}
	c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(objs...).Build()
	r := &KDexInternalPackageReferencesReconciler{Client: c, Scheme: c.Scheme(), RequeueDelay: time.Second}
	ipr := harvestIPR()
	h, err := r.harvestPackagesJob(context.Background(), ipr, job, "reg.example", harvestNow)
	require.NoError(t, err)
	return ipr, h, c
}

func jobExists(t *testing.T, c client.Client, job *batchv1.Job) bool {
	t.Helper()
	err := c.Get(context.Background(), client.ObjectKeyFromObject(job), &batchv1.Job{})
	if apierrors.IsNotFound(err) {
		return false
	}
	require.NoError(t, err)
	return true
}

// Regression for kdex-tech/host-manager#301: a Job that succeeded on retry
// owns a Failed pod (runc subPath mount error) and a Succeeded pod. The good
// digest and importmap must be harvested regardless of the pods' list order.
func TestHarvestPackagesJob_FailedPodPlusSucceededRetry(t *testing.T) {
	done := harvestNow.Add(-time.Minute)
	base := harvestNow.Add(-10 * time.Minute)
	good := harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, base.Add(time.Minute), harvestGoodDigest+"\n", harvestImportmap)

	for name, failed := range map[string]*corev1.Pod{
		"failed pod listed before succeeded": failedHarvestPod("rsi-dev-packages-449-8jbbb", base),
		"failed pod listed after succeeded":  failedHarvestPod("rsi-dev-packages-449-zzzzz", base),
		"failed pod newer than succeeded":    failedHarvestPod("rsi-dev-packages-449-00000", base.Add(5*time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			ipr, h, _ := runHarvest(t, harvestJob(1, 1, &done), failed, good.DeepCopy())
			require.Nil(t, h.result, "a good Succeeded pod must be harvested, not requeued/degraded")
			assert.Equal(t, "reg.example/rsi-dev/packages:449@"+harvestGoodDigest, h.builtImage)
			assert.Equal(t, harvestImportmap, h.importmap)
			assert.NotContains(t, h.builtImage, "containerd")
			assert.Empty(t, ipr.Status.Conditions, "a clean harvest sets no condition here")
		})
	}
}

// Only a Failed pod for a Job the cache already reports Succeeded: the
// Succeeded pod has not reached the cache yet. Wait; record nothing; don't
// delete the Job.
func TestHarvestPackagesJob_OnlyFailedPodWaits(t *testing.T) {
	done := harvestNow.Add(-10 * time.Second)
	job := harvestJob(1, 1, &done)
	ipr, h, c := runHarvest(t, job, failedHarvestPod("rsi-dev-packages-449-8jbbb", harvestNow.Add(-time.Minute)))

	require.NotNil(t, h.result)
	assert.Positive(t, h.result.RequeueAfter)
	assert.Empty(t, h.builtImage)
	assert.Equal(t, "reg.example/rsi-dev/packages:448@"+harvestGoodDigest, ipr.Status.Attributes["image"])
	assert.False(t, meta.IsStatusConditionTrue(ipr.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded)))
	assert.True(t, jobExists(t, c, job), "a cache lag must not delete the Job")
}

// The Succeeded pod never shows up (garbage-collected): past the grace
// window, fall back to the pre-#301 behaviour for a job with no harvestable
// pod — Degraded, Job deleted so the next pass rebuilds.
func TestHarvestPackagesJob_NoSucceededPodPastGraceRebuilds(t *testing.T) {
	done := harvestNow.Add(-time.Hour)
	job := harvestJob(1, 1, &done)
	ipr, h, c := runHarvest(t, job, failedHarvestPod("rsi-dev-packages-449-8jbbb", harvestNow.Add(-2*time.Hour)))

	require.NotNil(t, h.result)
	assert.Empty(t, h.builtImage)
	assert.Equal(t, "reg.example/rsi-dev/packages:448@"+harvestGoodDigest, ipr.Status.Attributes["image"])
	assert.True(t, meta.IsStatusConditionTrue(ipr.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded)))
	assert.False(t, jobExists(t, c, job))
}

// A Succeeded pod whose packager emitted something that is not a digest:
// Degraded with a clear, truncated message; status.image untouched; Job
// deleted so the next pass rebuilds (as for the #161 verify failure).
func TestHarvestPackagesJob_MalformedDigestDegrades(t *testing.T) {
	done := harvestNow.Add(-time.Minute)
	job := harvestJob(1, 0, &done)
	garbage := strings.Repeat("not-a-digest ", 100)
	ipr, h, c := runHarvest(t, job,
		harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, harvestNow.Add(-5*time.Minute), garbage, harvestImportmap))

	require.NotNil(t, h.result)
	assert.Positive(t, h.result.RequeueAfter)
	assert.Empty(t, h.builtImage)
	assert.Equal(t, "reg.example/rsi-dev/packages:448@"+harvestGoodDigest, ipr.Status.Attributes["image"],
		"a malformed digest must never be written to status.image")

	cond := meta.FindStatusCondition(ipr.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Contains(t, cond.Message, "not a valid image digest")
	assert.Contains(t, cond.Message, "rsi-dev-packages-449-nflq5")
	assert.Less(t, len(cond.Message), 500, "the bad text must be truncated")
	assert.False(t, jobExists(t, c, job), "the Job must be deleted so the next pass rebuilds")
}

// Outputs not yet visible on a Succeeded pod: keep the existing wait.
func TestHarvestPackagesJob_EmptyOutputsWait(t *testing.T) {
	done := harvestNow.Add(-time.Minute)
	job := harvestJob(1, 0, &done)
	ipr, h, c := runHarvest(t, job,
		harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, harvestNow.Add(-5*time.Minute), harvestGoodDigest, ""))

	require.NotNil(t, h.result)
	assert.Empty(t, h.builtImage)
	assert.Empty(t, ipr.Status.Conditions)
	assert.True(t, jobExists(t, c, job))
}

// harvestablePod is shared by the packages, codegen and deployer harvests.
func TestHarvestablePod(t *testing.T) {
	base := harvestNow.Add(-10 * time.Minute)
	recent := harvestNow.Add(-10 * time.Second)
	old := harvestNow.Add(-time.Hour)
	failed := failedHarvestPod("p-failed", base)
	good := harvestPod("p-good", corev1.PodSucceeded, base.Add(time.Minute), harvestGoodDigest, harvestImportmap)
	terminal := harvestJob(0, 4, nil)
	terminal.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"},
	}

	tests := []struct {
		name     string
		job      *batchv1.Job
		pods     []*corev1.Pod
		wantPod  string
		wantWait bool
		wantErr  bool
	}{
		{name: "not started: wait", job: harvestJob(0, 0, nil), wantWait: true},
		{name: "mid-retry (Failed>0, not terminal): wait, never harvest the failed pod",
			job: harvestJob(0, 1, nil), pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded on retry: the succeeded pod", job: harvestJob(1, 1, &recent),
			pods: []*corev1.Pod{failed, good}, wantPod: "p-good"},
		{name: "succeeded, pod cache lagging: wait", job: harvestJob(1, 1, &recent),
			pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded, no CompletionTime yet: wait", job: harvestJob(1, 1, nil),
			pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded long ago, succeeded pod gone: error", job: harvestJob(1, 1, &old),
			pods: []*corev1.Pod{failed}, wantErr: true},
		{name: "terminal failed: any pod, for diagnostics", job: terminal,
			pods: []*corev1.Pod{failed}, wantPod: "p-failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{tt.job}
			for _, p := range tt.pods {
				objs = append(objs, p.DeepCopy())
			}
			c := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(objs...).Build()
			pod, wait, err := harvestablePod(context.Background(), c, tt.job, harvestNow)
			assert.Equal(t, tt.wantWait, wait)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantPod == "" {
				assert.Nil(t, pod)
			} else {
				require.NotNil(t, pod)
				assert.Equal(t, tt.wantPod, pod.Name)
			}
		})
	}
}

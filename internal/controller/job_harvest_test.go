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
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/kdex-tech/host-manager/internal"
	kjob "github.com/kdex-tech/host-manager/internal/job"
)

const (
	harvestGoodDigest = "sha256:fbc036ef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	harvestRuncError  = `failed to create containerd task: failed to create shim task: OCI runtime create failed: ` +
		`runc create failed: unable to start container process: error during container init: error mounting ` +
		`"/var/lib/kubelet/pods/x/volume-subpaths/image-push-secret/packager/4" to rootfs at "/shared/config.json": ` +
		`no such file or directory: unknown`
	harvestImportmap = `{"imports":{"lit":"/~/m/lit/index.js"}}`
	harvestJobName   = "rsi-dev-packages-449"
	harvestJobUID    = types.UID("uid-rsi-dev-packages-449")
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
			Name:              harvestJobName,
			Namespace:         "dev",
			UID:               harvestJobUID,
			CreationTimestamp: metav1.NewTime(harvestNow.Add(-15 * time.Minute)),
			Annotations:       map[string]string{internal.ANNOTATION_GENERATION: "449"},
			Labels:            map[string]string{"app": "packages", "packages": "rsi-dev", internal.ANNOTATION_GENERATION: "449"},
		},
		Status: batchv1.JobStatus{Succeeded: succeeded, Failed: failed},
	}
	if completed != nil {
		ct := metav1.NewTime(*completed)
		j.Status.CompletionTime = &ct
	}
	return j
}

func terminalHarvestJob() *batchv1.Job {
	j := harvestJob(0, 4, nil)
	j.Status.Conditions = []batchv1.JobCondition{{
		Type: batchv1.JobFailed, Status: corev1.ConditionTrue,
		Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit",
	}}
	return j
}

func harvestPod(name string, phase corev1.PodPhase, created time.Time, digest, importmap string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "dev",
			Labels:            map[string]string{"job-name": harvestJobName},
			Annotations:       map[string]string{internal.ANNOTATION_GENERATION: "449"},
			CreationTimestamp: metav1.NewTime(created),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "batch/v1", Kind: "Job", Name: harvestJobName, UID: harvestJobUID,
				Controller: ptr.To(true), BlockOwnerDeletion: ptr.To(true),
			}},
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

func harvestClient(t *testing.T, funcs *interceptor.Funcs, objs ...client.Object) client.Client {
	t.Helper()
	b := fake.NewClientBuilder().WithScheme(harvestScheme(t)).WithObjects(objs...)
	if funcs != nil {
		b = b.WithInterceptorFuncs(*funcs)
	}
	return b.Build()
}

func harvestObjs(job *batchv1.Job, pods ...*corev1.Pod) []client.Object {
	objs := []client.Object{job}
	for _, p := range pods {
		objs = append(objs, p.DeepCopy())
	}
	return objs
}

// failingPodList makes every pod List fail as a transient API error would.
var failingPodList = &interceptor.Funcs{
	List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(*corev1.PodList); ok {
			return apierrors.NewServiceUnavailable("etcd leader election")
		}
		return c.List(ctx, list, opts...)
	},
}

func runHarvestOn(t *testing.T, c client.Client, ipr *kdexv1alpha1.KDexInternalPackageReferences, job *batchv1.Job) (packagesHarvest, error) {
	t.Helper()
	r := &KDexInternalPackageReferencesReconciler{Client: c, Scheme: c.Scheme(), RequeueDelay: time.Second}
	return r.harvestPackagesJob(context.Background(), ipr, job, "reg.example", harvestNow)
}

func runHarvest(t *testing.T, job *batchv1.Job, pods ...*corev1.Pod) (
	*kdexv1alpha1.KDexInternalPackageReferences, packagesHarvest, client.Client,
) {
	t.Helper()
	c := harvestClient(t, nil, harvestObjs(job, pods...)...)
	ipr := harvestIPR()
	h, err := runHarvestOn(t, c, ipr, job)
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

func degradedMessage(t *testing.T, conds []metav1.Condition) string {
	t.Helper()
	cond := meta.FindStatusCondition(conds, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	return cond.Message
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

// A transient API error listing pods is not "no harvestable pod": it goes
// back to controller-runtime for backoff, and a good Job is never deleted.
func TestHarvestPackagesJob_ListErrorIsReturnedAndKeepsJob(t *testing.T) {
	done := harvestNow.Add(-time.Hour)
	job := harvestJob(1, 0, &done)
	c := harvestClient(t, failingPodList, harvestObjs(job)...)
	ipr := harvestIPR()

	_, err := runHarvestOn(t, c, ipr, job)
	require.Error(t, err)
	assert.True(t, apierrors.IsServiceUnavailable(err), "got %v", err)
	assert.True(t, jobExists(t, c, job), "an API error must never delete a good Job")
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

	msg := degradedMessage(t, ipr.Status.Conditions)
	assert.Contains(t, msg, "not a valid image digest")
	assert.Contains(t, msg, "rsi-dev-packages-449-nflq5")
	assert.Contains(t, msg, "rebuild 1 of 3")
	assert.Less(t, len(msg), 500, "the bad text must be truncated")
	assert.False(t, jobExists(t, c, job), "the Job must be deleted so the next pass rebuilds")
	assert.Equal(t, "449=1", ipr.Status.Attributes[attrHarvestFailures])
}

// A deterministic bad output must not delete+rebuild every RequeueDelay
// forever: after maxBadOutputRebuilds rebuilds of one generation, keep the
// Job, stay Degraded and back off.
func TestHarvestPackagesJob_MalformedDigestRebuildsAreBounded(t *testing.T) {
	done := harvestNow.Add(-time.Minute)
	ipr := harvestIPR()
	for i := 1; i <= maxBadOutputRebuilds+1; i++ {
		job := harvestJob(1, 0, &done)
		pod := harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, harvestNow.Add(-5*time.Minute), "garbage", harvestImportmap)
		c := harvestClient(t, nil, harvestObjs(job, pod)...)
		h, err := runHarvestOn(t, c, ipr, job)
		require.NoError(t, err)
		require.NotNil(t, h.result)
		msg := degradedMessage(t, ipr.Status.Conditions)

		if i <= maxBadOutputRebuilds {
			assert.False(t, jobExists(t, c, job), "rebuild %d deletes the Job", i)
			assert.Equal(t, time.Second, h.result.RequeueAfter)
			continue
		}
		assert.True(t, jobExists(t, c, job), "past the bound the Job is kept for inspection")
		assert.Equal(t, badOutputGiveUpRequeue, h.result.RequeueAfter)
		assert.Contains(t, msg, "gave up after 3 rebuilds")
		assert.Equal(t, "449=3", ipr.Status.Attributes[attrHarvestFailures], "giving up does not count")
	}

	// A new generation starts a fresh budget.
	ipr.Generation = 450
	job := harvestJob(1, 0, &done)
	c := harvestClient(t, nil, harvestObjs(job,
		harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, harvestNow.Add(-5*time.Minute), "garbage", harvestImportmap))...)
	_, err := runHarvestOn(t, c, ipr, job)
	require.NoError(t, err)
	assert.False(t, jobExists(t, c, job))
	assert.Equal(t, "450=1", ipr.Status.Attributes[attrHarvestFailures])
}

// Outputs not yet visible on a Succeeded pod: wait, within the grace window.
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

// ... but not forever: past the grace window empty outputs are bad output.
func TestHarvestPackagesJob_EmptyOutputsPastGraceIsBadOutput(t *testing.T) {
	done := harvestNow.Add(-time.Hour)
	job := harvestJob(1, 0, &done)
	ipr, h, c := runHarvest(t, job,
		harvestPod("rsi-dev-packages-449-nflq5", corev1.PodSucceeded, harvestNow.Add(-2*time.Hour), harvestGoodDigest, ""))

	require.NotNil(t, h.result)
	assert.Empty(t, h.builtImage)
	assert.Contains(t, degradedMessage(t, ipr.Status.Conditions), "importmap")
	assert.False(t, jobExists(t, c, job))
	assert.Equal(t, "449=1", ipr.Status.Attributes[attrHarvestFailures])
}

// harvestablePod is shared by the packages, codegen and deployer harvests.
func TestHarvestablePod(t *testing.T) {
	base := harvestNow.Add(-10 * time.Minute)
	recent := harvestNow.Add(-10 * time.Second)
	old := harvestNow.Add(-time.Hour)
	failed := failedHarvestPod("p-failed", base)
	good := harvestPod("p-good", corev1.PodSucceeded, base.Add(time.Minute), harvestGoodDigest, harvestImportmap)

	noCompletionRecentCreate := harvestJob(1, 1, nil)
	noCompletionRecentCreate.CreationTimestamp = metav1.NewTime(recent)
	noCompletionOldCreate := harvestJob(1, 1, nil)
	noCompletionOldCreate.CreationTimestamp = metav1.NewTime(old)
	completeCondRecent := harvestJob(1, 1, nil)
	completeCondRecent.CreationTimestamp = metav1.NewTime(old)
	completeCondRecent.Status.Conditions = []batchv1.JobCondition{
		{Type: batchv1.JobComplete, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(recent)},
	}

	tests := []struct {
		name     string
		job      *batchv1.Job
		pods     []*corev1.Pod
		funcs    *interceptor.Funcs
		wantPod  string
		wantWait bool
		wantErr  error
	}{
		{name: "not started: wait", job: harvestJob(0, 0, nil), wantWait: true},
		{name: "mid-retry (Failed>0, not terminal): wait, never harvest the failed pod",
			job: harvestJob(0, 1, nil), pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded on retry: the succeeded pod", job: harvestJob(1, 1, &recent),
			pods: []*corev1.Pod{failed, good}, wantPod: "p-good"},
		{name: "succeeded, pod cache lagging: wait", job: harvestJob(1, 1, &recent),
			pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded, no CompletionTime, created recently: wait", job: noCompletionRecentCreate,
			pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded, no CompletionTime, created long ago: grace measured from creation", job: noCompletionOldCreate,
			pods: []*corev1.Pod{failed}, wantErr: errNoSucceededPodSentinel},
		{name: "succeeded, no CompletionTime, recent Complete condition: wait", job: completeCondRecent,
			pods: []*corev1.Pod{failed}, wantWait: true},
		{name: "succeeded long ago, succeeded pod gone: ErrNoSucceededPod", job: harvestJob(1, 1, &old),
			pods: []*corev1.Pod{failed}, wantErr: errNoSucceededPodSentinel},
		{name: "succeeded, list fails: the API error, never ErrNoSucceededPod", job: harvestJob(1, 0, &old),
			funcs: failingPodList, wantErr: errServiceUnavailable},
		{name: "terminal failed: any pod, for diagnostics", job: terminalHarvestJob(),
			pods: []*corev1.Pod{failed}, wantPod: "p-failed"},
		{name: "terminal failed, no pod: nothing to quote, not an error", job: terminalHarvestJob()},
		{name: "terminal failed, list fails: the API error", job: terminalHarvestJob(),
			funcs: failingPodList, wantErr: errServiceUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := harvestClient(t, tt.funcs, harvestObjs(tt.job, tt.pods...)...)
			pod, wait, err := harvestablePod(context.Background(), c, tt.job, harvestNow)
			assert.Equal(t, tt.wantWait, wait)
			switch tt.wantErr {
			case nil:
				require.NoError(t, err)
			case errNoSucceededPodSentinel:
				assert.True(t, isNoSucceededPod(err), "got %v", err)
				return
			case errServiceUnavailable:
				assert.True(t, apierrors.IsServiceUnavailable(err), "got %v", err)
				assert.False(t, isNoSucceededPod(err))
				return
			}
			if tt.wantPod == "" {
				assert.Nil(t, pod)
			} else {
				require.NotNil(t, pod)
				assert.Equal(t, tt.wantPod, pod.Name)
			}
		})
	}
}

func isNoSucceededPod(err error) bool { return errors.Is(err, kjob.ErrNoSucceededPod) }

var (
	errNoSucceededPodSentinel = errors.New("want ErrNoSucceededPod")
	errServiceUnavailable     = errors.New("want ServiceUnavailable")
)

func TestQuoteBadOutput(t *testing.T) {
	t.Run("short text is quoted whole", func(t *testing.T) {
		assert.Equal(t, `"oops"`, quoteBadOutput("oops"))
	})
	t.Run("truncates on a rune boundary", func(t *testing.T) {
		s := strings.Repeat("a", badOutputQuoteLimit-1) + "é" + strings.Repeat("z", 50)
		q := quoteBadOutput(s)
		assert.True(t, utf8.ValidString(q))
		assert.NotContains(t, q, `\x`, "no split rune escaped as a raw byte")
		assert.Contains(t, q, "bytes)")
	})
	t.Run("strips URL userinfo", func(t *testing.T) {
		q := quoteBadOutput(`clone of https://x-access-token:ghp_s3cr3t@github.com/kdex-tech/fn.git failed; ` +
			`retry oci://bob:p@ss@registry.example/ns/repo`)
		assert.NotContains(t, q, "ghp_s3cr3t")
		assert.NotContains(t, q, "x-access-token")
		assert.NotContains(t, q, "bob")
		assert.NotContains(t, q, "p@ss")
		assert.Contains(t, q, "https://github.com/kdex-tech/fn.git")
		assert.Contains(t, q, "oci://registry.example/ns/repo")
	})
}

// --- KDexFunction codegen / deployer harvests -----------------------------

func harvestFunction() *kdexv1alpha1.KDexFunction {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "billing", Namespace: "dev", Generation: 7},
	}
	fn.Status.Attributes = map[string]string{}
	return fn
}

func resultsPod(name string, phase corev1.PodPhase, msg string) *corev1.Pod {
	p := harvestPod(name, phase, harvestNow.Add(-5*time.Minute), "", "")
	p.Status.InitContainerStatuses = nil
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "results",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: msg}},
	}}
	return p
}

func runFunctionHarvest(t *testing.T, c client.Client, fn *kdexv1alpha1.KDexFunction, job *batchv1.Job) (functionHarvest, error) {
	t.Helper()
	r := &KDexFunctionReconciler{Client: c, Scheme: c.Scheme(), RequeueDelay: time.Second}
	return r.harvestFunctionJob(context.Background(), fn, job, "results", harvestNow)
}

// #27 retry storm via the terminal-no-pod path: a terminally Failed Job whose
// pods are gone (GC, or never scheduled) must be marked terminally failed
// with the Job condition's message and KEPT, not deleted and recreated.
func TestHarvestFunctionJob_TerminalWithoutPodKeepsJob(t *testing.T) {
	job := terminalHarvestJob()
	c := harvestClient(t, nil, harvestObjs(job)...)
	fn := harvestFunction()

	h, err := runFunctionHarvest(t, c, fn, job)
	require.NoError(t, err)
	assert.True(t, h.terminal)
	require.NotNil(t, h.result)
	assert.Zero(t, h.result.RequeueAfter, "terminal failure does not requeue")
	msg := degradedMessage(t, fn.Status.Conditions)
	assert.Contains(t, msg, "BackoffLimitExceeded")
	assert.Contains(t, msg, "exhausted retries")
	assert.NotContains(t, msg, "results:")
	assert.True(t, jobExists(t, c, job), "a terminally failed Job is kept for inspection (#27)")
}

// The failed pod's termination text is attacker-influenced (repo contents,
// clone URLs): it is capped and its URL credentials stripped.
func TestHarvestFunctionJob_TerminalQuotesCappedRedactedText(t *testing.T) {
	job := terminalHarvestJob()
	long := "fatal: could not read from https://bot:hunter2@git.example/org/fn.git\n" + strings.Repeat("x", 4000)
	c := harvestClient(t, nil, harvestObjs(job, resultsPod("p-failed", corev1.PodFailed, long))...)
	fn := harvestFunction()

	h, err := runFunctionHarvest(t, c, fn, job)
	require.NoError(t, err)
	assert.True(t, h.terminal)
	msg := degradedMessage(t, fn.Status.Conditions)
	assert.Contains(t, msg, "results:")
	assert.Contains(t, msg, "https://git.example/org/fn.git")
	assert.NotContains(t, msg, "hunter2")
	assert.Less(t, len(msg), 1000, "the termination text must be capped")
	assert.True(t, jobExists(t, c, job))
}

func TestHarvestFunctionJob_ListErrorIsReturnedAndKeepsJob(t *testing.T) {
	done := harvestNow.Add(-time.Hour)
	job := harvestJob(1, 0, &done)
	c := harvestClient(t, failingPodList, harvestObjs(job)...)

	_, err := runFunctionHarvest(t, c, harvestFunction(), job)
	require.Error(t, err)
	assert.True(t, apierrors.IsServiceUnavailable(err), "got %v", err)
	assert.True(t, jobExists(t, c, job), "an API error must never delete a good Job")
}

func TestHarvestFunctionJob_NoSucceededPodPastGraceRebuilds(t *testing.T) {
	done := harvestNow.Add(-time.Hour)
	job := harvestJob(1, 0, &done)
	c := harvestClient(t, nil, harvestObjs(job)...)
	fn := harvestFunction()

	h, err := runFunctionHarvest(t, c, fn, job)
	require.NoError(t, err)
	require.NotNil(t, h.result)
	assert.Positive(t, h.result.RequeueAfter)
	degradedMessage(t, fn.Status.Conditions)
	assert.False(t, jobExists(t, c, job))
}

func TestHarvestFunctionJob_SucceededReturnsOutput(t *testing.T) {
	done := harvestNow.Add(-time.Minute)
	job := harvestJob(1, 1, &done)
	c := harvestClient(t, nil, harvestObjs(job,
		resultsPod("p-failed", corev1.PodFailed, "boom"),
		resultsPod("p-good", corev1.PodSucceeded, `{"repository":"r"}`))...)

	h, err := runFunctionHarvest(t, c, harvestFunction(), job)
	require.NoError(t, err)
	assert.Nil(t, h.result)
	assert.False(t, h.waiting)
	assert.Equal(t, `{"repository":"r"}`, h.output)
}

func TestBadFunctionOutput_Bounded(t *testing.T) {
	fn := harvestFunction()
	for i := 1; i <= maxBadOutputRebuilds+1; i++ {
		job := harvestJob(1, 0, nil)
		c := harvestClient(t, nil, harvestObjs(job)...)
		r := &KDexFunctionReconciler{Client: c, Scheme: c.Scheme(), RequeueDelay: time.Second}

		res, err := r.badFunctionOutput(context.Background(), fn, job, "failed to parse results")
		require.NoError(t, err)
		msg := degradedMessage(t, fn.Status.Conditions)
		if i <= maxBadOutputRebuilds {
			assert.False(t, jobExists(t, c, job))
			assert.Equal(t, time.Second, res.RequeueAfter)
			continue
		}
		assert.True(t, jobExists(t, c, job))
		assert.Equal(t, badOutputGiveUpRequeue, res.RequeueAfter)
		assert.Contains(t, msg, "gave up after 3 rebuilds")
	}

	resetBadOutputRebuilds(fn.Status.Attributes)
	assert.NotContains(t, fn.Status.Attributes, attrHarvestFailures)
}

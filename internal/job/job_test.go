package job

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kdex-tech/host-manager/internal"
)

const runcMessage = `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: ` +
	`unable to start container process: error during container init: error mounting ` +
	`"/var/lib/kubelet/pods/x/volume-subpaths/image-push-secret/packager/4" to rootfs at "/shared/config.json": no such file or directory`

var base = time.Date(2026, 11, 23, 20, 32, 59, 0, time.UTC)

func testJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "rsi-dev-packages-449",
			Namespace:   "dev",
			Annotations: map[string]string{internal.ANNOTATION_GENERATION: "449"},
		},
		Status: batchv1.JobStatus{Succeeded: 1, Failed: 1},
	}
}

func testPod(name, gen string, phase corev1.PodPhase, created time.Time, msg string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "dev",
			Labels:            map[string]string{"job-name": "rsi-dev-packages-449"},
			Annotations:       map[string]string{internal.ANNOTATION_GENERATION: gen},
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: corev1.PodStatus{
			Phase: phase,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "packager",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: msg}},
			}},
		},
	}
}

func fakeClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// Regression for kdex-tech/host-manager#301: a Job that succeeded on retry
// has a Failed pod (runc subPath mount error) next to its Succeeded pod. Only
// the Succeeded pod's outputs may be harvested, whatever the list order.
func TestGetSucceededPodForJob_IgnoresFailedPodRegardlessOfOrder(t *testing.T) {
	failed := testPod("rsi-dev-packages-449-8jbbb", "449", corev1.PodFailed, base, runcMessage)
	succeeded := testPod("rsi-dev-packages-449-nflq5", "449", corev1.PodSucceeded, base.Add(time.Minute), "sha256:good")
	// The fake client lists by name; name the Failed pod both before and
	// after the Succeeded one to cover both orders.
	failedAfter := testPod("rsi-dev-packages-449-zzzzz", "449", corev1.PodFailed, base.Add(2*time.Minute), runcMessage)

	for name, objs := range map[string][]client.Object{
		"failed listed first": {failed, succeeded},
		"failed listed last":  {succeeded, failedAfter},
		"failed on both sides": {
			failed.DeepCopy(), succeeded.DeepCopy(), failedAfter.DeepCopy(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			pod, err := GetSucceededPodForJob(context.Background(), fakeClient(t, objs...), testJob())
			require.NoError(t, err)
			assert.Equal(t, "rsi-dev-packages-449-nflq5", pod.Name)
		})
	}
}

func TestGetSucceededPodForJob_OnlyFailedPods(t *testing.T) {
	c := fakeClient(t,
		testPod("rsi-dev-packages-449-8jbbb", "449", corev1.PodFailed, base, runcMessage),
		testPod("rsi-dev-packages-449-9kccc", "449", corev1.PodRunning, base.Add(time.Minute), ""),
	)
	pod, err := GetSucceededPodForJob(context.Background(), c, testJob())
	assert.Nil(t, pod)
	assert.True(t, errors.Is(err, ErrNoSucceededPod), "got %v", err)
}

func TestGetSucceededPodForJob_NewestSucceededWins(t *testing.T) {
	c := fakeClient(t,
		testPod("rsi-dev-packages-449-bbbbb", "449", corev1.PodSucceeded, base.Add(time.Minute), "sha256:newer"),
		testPod("rsi-dev-packages-449-aaaaa", "449", corev1.PodSucceeded, base, "sha256:older"),
		testPod("rsi-dev-packages-449-ccccc", "449", corev1.PodSucceeded, base, "sha256:also-older"),
	)
	pod, err := GetSucceededPodForJob(context.Background(), c, testJob())
	require.NoError(t, err)
	assert.Equal(t, "rsi-dev-packages-449-bbbbb", pod.Name)
}

func TestGetSucceededPodForJob_IgnoresOtherGenerations(t *testing.T) {
	c := fakeClient(t,
		testPod("rsi-dev-packages-449-old", "448", corev1.PodSucceeded, base.Add(time.Hour), "sha256:wrong-gen"),
	)
	_, err := GetSucceededPodForJob(context.Background(), c, testJob())
	assert.True(t, errors.Is(err, ErrNoSucceededPod), "got %v", err)
}

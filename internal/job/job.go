package job

import (
	"context"
	"errors"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kdex-tech/host-manager/internal"
)

// ErrNoSucceededPod reports that a Job has no pod in phase Succeeded for its
// generation (yet): the pod cache may lag the Job status, or the pods were
// garbage-collected. Callers decide between waiting and rebuilding.
var ErrNoSucceededPod = errors.New("no succeeded pod found for job")

// GetPodForJob returns a pod of the job's generation in ANY phase — the newest
// by creation timestamp. It is for diagnostics only (e.g. quoting a failed
// pod's termination message): never harvest a job's outputs from it, since a
// Job that succeeded on retry also owns the Failed pods of its earlier
// attempts. Use GetSucceededPodForJob to harvest. See kdex-tech/host-manager#301.
func GetPodForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*corev1.Pod, error) {
	pods, err := podsForJob(ctx, c, job)
	if err != nil {
		return nil, err
	}
	if pod := newest(pods, func(*corev1.Pod) bool { return true }); pod != nil {
		return pod, nil
	}
	return nil, fmt.Errorf("no pods found for job %s", job.Name)
}

// GetSucceededPodForJob returns the newest pod of the job's generation whose
// phase is Succeeded — the only pod whose termination messages are the job's
// outputs. A Failed pod's container is terminated too, and its termination
// message is the failure text (e.g. a runc mount error), which pre-#301 was
// recorded as the packages image digest. Returns an error wrapping
// ErrNoSucceededPod when there is none.
func GetSucceededPodForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*corev1.Pod, error) {
	pods, err := podsForJob(ctx, c, job)
	if err != nil {
		return nil, err
	}
	if pod := newest(pods, func(p *corev1.Pod) bool { return p.Status.Phase == corev1.PodSucceeded }); pod != nil {
		return pod, nil
	}
	return nil, fmt.Errorf("%w: %s/%s (%d pods of its generation)", ErrNoSucceededPod, job.Namespace, job.Name, len(pods))
}

func podsForJob(ctx context.Context, c client.Client, job *batchv1.Job) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := c.List(ctx, podList, client.InNamespace(job.Namespace), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return nil, err
	}
	gen := job.Annotations[internal.ANNOTATION_GENERATION]
	pods := make([]corev1.Pod, 0, len(podList.Items))
	for _, pod := range podList.Items {
		if pod.Annotations[internal.ANNOTATION_GENERATION] == gen {
			pods = append(pods, pod)
		}
	}
	return pods, nil
}

// newest returns the matching pod with the latest creation timestamp, ties
// broken by name so the choice never depends on list order.
func newest(pods []corev1.Pod, match func(*corev1.Pod) bool) *corev1.Pod {
	var best *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if !match(p) {
			continue
		}
		if best == nil ||
			best.CreationTimestamp.Before(&p.CreationTimestamp) ||
			(best.CreationTimestamp.Equal(&p.CreationTimestamp) && p.Name > best.Name) {
			best = p
		}
	}
	return best
}

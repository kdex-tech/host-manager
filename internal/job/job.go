package job

import (
	"context"
	"errors"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kdex-tech/host-manager/internal"
)

// ErrNoSucceededPod reports that a Job has no pod in phase Succeeded for its
// generation (yet): the pod cache may lag the Job status, or the pods were
// garbage-collected. Callers decide between waiting and rebuilding.
var ErrNoSucceededPod = errors.New("no succeeded pod found for job")

// ErrNoPods reports that a Job controls no pod of its generation at all.
var ErrNoPods = errors.New("no pods found for job")

// GetPodForJob returns a pod of the job's generation in ANY phase — the newest
// by creation timestamp. It is for diagnostics only (e.g. quoting a failed
// pod's termination message): never harvest a job's outputs from it, since a
// Job that succeeded on retry also owns the Failed pods of its earlier
// attempts. Use GetSucceededPodForJob to harvest. Returns an error wrapping
// ErrNoPods when there is none. See kdex-tech/host-manager#301.
func GetPodForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*corev1.Pod, error) {
	pods, err := podsForJob(ctx, c, job)
	if err != nil {
		return nil, err
	}
	if pod := newest(pods, func(*corev1.Pod) bool { return true }); pod != nil {
		return pod, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", ErrNoPods, job.Namespace, job.Name)
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

// podsForJob lists the pods of the job's generation that the job CONTROLS.
// The job-name label and generation annotation narrow the list, but neither
// proves a pod is this Job's: a deleted Job of the same name and generation
// (rebuildPackagesJob and the #161 verify failure recreate exactly that)
// leaves its pods behind until GC, and anyone with pods/create in the
// namespace can forge both, along with a termination message posing as a
// digest, codegen results or a deployer URL. Only the controller
// ownerReference — Kind Job, this Job's name AND UID — ties a pod to this
// Job instance.
//
// Trust boundary: a principal that can write both pods and Jobs in the
// namespace can still forge outputs (a pod carrying a matching
// ownerReference, or a Job of its own); namespace pod+job write access
// remains equivalent to control over these harvests.
func podsForJob(ctx context.Context, c client.Client, job *batchv1.Job) ([]corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := c.List(ctx, podList, client.InNamespace(job.Namespace), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return nil, err
	}
	gen := job.Annotations[internal.ANNOTATION_GENERATION]
	pods := make([]corev1.Pod, 0, len(podList.Items))
	for i := range podList.Items {
		pod := &podList.Items[i]
		if pod.Annotations[internal.ANNOTATION_GENERATION] == gen && controlledBy(pod, job) {
			pods = append(pods, *pod)
		}
	}
	return pods, nil
}

// controlledBy reports whether pod's controller ownerReference is job.
func controlledBy(pod *corev1.Pod, job *batchv1.Job) bool {
	ref := metav1.GetControllerOf(pod)
	return ref != nil && ref.Kind == "Job" && ref.Name == job.Name && ref.UID == job.UID
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

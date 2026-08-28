package job

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kdex-tech/host-manager/internal"
)

func GetPodForJob(ctx context.Context, c client.Client, job *batchv1.Job) (*corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := c.List(ctx, podList, client.InNamespace(job.Namespace), client.MatchingLabels{"job-name": job.Name}); err != nil {
		return nil, err
	}

	// find pod with matching generation
	for _, pod := range podList.Items {
		if pod.Annotations[internal.ANNOTATION_GENERATION] == job.Annotations[internal.ANNOTATION_GENERATION] {
			return &pod, nil
		}
	}

	return nil, fmt.Errorf("no pods found for job %s", job.Name)
}

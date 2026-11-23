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
	"fmt"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kjob "github.com/kdex-tech/host-manager/internal/job"
	"github.com/kdex-tech/host-manager/internal/packref"
)

// succeededPodGrace bounds how long a Job the cache reports Succeeded may lack
// a visible Succeeded pod before that is treated as "gone" (pod GC) rather
// than "not in the cache yet". Past it, callers fall back to their
// no-harvestable-pod path (Degraded + delete the Job so it rebuilds).
const succeededPodGrace = 2 * time.Minute

// badOutputQuoteLimit caps how much of an unexpected termination message is
// quoted into a condition — a runc error runs to several hundred bytes.
const badOutputQuoteLimit = 200

// harvestablePod picks the pod a finished Job's outputs may be read from.
//
//   - Terminal-Failed Job: the newest pod of any phase, for diagnostics only.
//   - Not yet Succeeded (fresh, or mid-retry with Failed>0 under its
//     BackoffLimit): wait=true. A Failed pod's terminated message is its
//     failure text, never an output.
//   - Succeeded: the newest Succeeded pod. A Job that succeeded on retry also
//     owns the Failed pods of earlier attempts; pre-#301 the first-listed pod
//     was harvested and a runc error was recorded as an image digest. If no
//     Succeeded pod is visible yet, wait=true within succeededPodGrace of the
//     Job's completion (cache lag); after it, an error (pod GC'd).
//
// See kdex-tech/host-manager#301.
func harvestablePod(ctx context.Context, c client.Client, job *batchv1.Job, now time.Time) (*corev1.Pod, bool, error) {
	if terminal, _ := isCodegenJobTerminal(job); terminal {
		pod, err := kjob.GetPodForJob(ctx, c, job)
		return pod, false, err
	}
	if job.Status.Succeeded == 0 {
		return nil, true, nil
	}
	pod, err := kjob.GetSucceededPodForJob(ctx, c, job)
	if errors.Is(err, kjob.ErrNoSucceededPod) &&
		(job.Status.CompletionTime == nil || now.Sub(job.Status.CompletionTime.Time) < succeededPodGrace) {
		return nil, true, nil
	}
	return pod, false, err
}

// terminatedMessage returns the named container's terminated message, or "".
func terminatedMessage(statuses []corev1.ContainerStatus, name string) string {
	for _, cs := range statuses {
		if cs.Name == name && cs.State.Terminated != nil {
			return cs.State.Terminated.Message
		}
	}
	return ""
}

// quoteBadOutput truncates s for a condition message.
func quoteBadOutput(s string) string {
	if len(s) <= badOutputQuoteLimit {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q… (%d bytes)", s[:badOutputQuoteLimit], len(s))
}

// packagesHarvest is the outcome of harvestPackagesJob: either the outputs to
// publish (result nil), or a result the reconcile must return as-is.
type packagesHarvest struct {
	builtImage string
	importmap  string
	result     *ctrl.Result
}

// harvestPackagesJob reads a Succeeded packages Job's outputs — the image
// digest from the packager container and the importmap from the
// importmap-generator init container — from its Succeeded pod, and builds the
// image reference to record. It writes nothing to ipr.Status.Attributes; a
// non-nil result means the caller must return it (waiting, or Degraded with
// the Job deleted to rebuild). See kdex-tech/host-manager#301.
func (r *KDexInternalPackageReferencesReconciler) harvestPackagesJob(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	job *batchv1.Job,
	registry string,
	now time.Time,
) (packagesHarvest, error) {
	wait := packagesHarvest{result: &ctrl.Result{RequeueAfter: r.RequeueDelay}}

	pod, waiting, err := harvestablePod(ctx, r.Client, job, now)
	if waiting {
		return wait, nil
	}
	if err != nil {
		return r.rebuildPackagesJob(ctx, ipr, job, err.Error())
	}

	imageDigest := strings.TrimSpace(terminatedMessage(pod.Status.ContainerStatuses, "packager"))
	importmap := terminatedMessage(pod.Status.InitContainerStatuses, "importmap-generator")
	if imageDigest == "" || importmap == "" {
		// Job reported success but we can't find the outputs yet? Wait a bit.
		return wait, nil
	}

	// Never record anything but a digest: a malformed value poisons the
	// host's image pull (`invalid checksum digest format`).
	if !packref.IsValidImageDigest(imageDigest) {
		return r.rebuildPackagesJob(ctx, ipr, job, fmt.Sprintf(
			"packages job %s/%s pod %s emitted %s, which is not a valid image digest (want sha256:<64 hex>) — refusing to publish; the next reconcile rebuilds",
			job.Namespace, job.Name, pod.Name, quoteBadOutput(imageDigest),
		))
	}

	return packagesHarvest{
		builtImage: fmt.Sprintf("%s/%s/packages:%d@%s", registry, ipr.Name, ipr.Generation, imageDigest),
		importmap:  importmap,
	}, nil
}

// rebuildPackagesJob marks the IPR Degraded with msg and deletes the Job so
// the next pass rebuilds. status.image is left untouched: the host keeps
// serving the last known-good image. Same shape as the #161 verify failure.
func (r *KDexInternalPackageReferencesReconciler) rebuildPackagesJob(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	job *batchv1.Job,
	msg string,
) (packagesHarvest, error) {
	kdexv1alpha1.SetConditions(
		&ipr.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconcileError,
		msg,
	)
	if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
		return packagesHarvest{}, err
	}
	return packagesHarvest{result: &ctrl.Result{RequeueAfter: r.RequeueDelay}}, nil
}

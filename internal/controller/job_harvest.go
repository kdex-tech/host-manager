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
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
// a visible Succeeded pod (or, for packages, its outputs) before that is
// treated as "gone" (pod GC) rather than "not in the cache yet". Past it,
// callers fall back to their no-harvestable-pod path.
const succeededPodGrace = 2 * time.Minute

// badOutputQuoteLimit caps how much of an unexpected termination message is
// quoted into a condition — a runc error runs to several hundred bytes, and
// a termination message to 4 KiB.
const badOutputQuoteLimit = 200

// maxBadOutputRebuilds bounds the delete-and-rebuild loop for a Job whose
// Succeeded pod emitted unusable output (a malformed digest, unparseable
// results, a packages image failing its pins). A deterministic bad output
// would otherwise rebuild every RequeueDelay forever. See #301.
const maxBadOutputRebuilds = 3

// badOutputGiveUpRequeue is the requeue once maxBadOutputRebuilds is
// reached: the Job is kept and nothing is deleted; the long requeue only
// re-evaluates the kept output (e.g. after a FaaS adaptor fix). A spec
// change starts a new generation, and so a fresh budget.
const badOutputGiveUpRequeue = 30 * time.Minute

// attrHarvestFailures is the Status.Attributes key counting consecutive
// bad-output rebuilds, as "<generation>=<count>". A count recorded for
// another generation reads as zero; a successful harvest deletes the key.
const attrHarvestFailures = "harvestFailures"

// harvestablePod picks the pod a finished Job's outputs may be read from.
//
//   - Terminal-Failed Job: the newest pod of any phase, for diagnostics only;
//     (nil, false, nil) when none is left. Callers mark the Job terminally
//     failed and KEEP it (#27) either way.
//   - Not yet Succeeded (fresh, or mid-retry with Failed>0 under its
//     BackoffLimit): wait=true. A Failed pod's terminated message is its
//     failure text, never an output.
//   - Succeeded: the newest Succeeded pod. A Job that succeeded on retry also
//     owns the Failed pods of earlier attempts; pre-#301 the first-listed pod
//     was harvested and a runc error was recorded as an image digest. If no
//     Succeeded pod is visible yet, wait=true within succeededPodGrace of the
//     Job's completion (cache lag); after it, an error wrapping
//     kjob.ErrNoSucceededPod (pod GC'd) — the only error a caller may answer
//     by rebuilding. Any other error (a failed List) is an API error for
//     controller-runtime's backoff.
//
// See kdex-tech/host-manager#301.
func harvestablePod(ctx context.Context, c client.Client, job *batchv1.Job, now time.Time) (*corev1.Pod, bool, error) {
	if terminal, _ := isCodegenJobTerminal(job); terminal {
		pod, err := kjob.GetPodForJob(ctx, c, job)
		if errors.Is(err, kjob.ErrNoPods) {
			return nil, false, nil
		}
		return pod, false, err
	}
	if job.Status.Succeeded == 0 {
		return nil, true, nil
	}
	pod, err := kjob.GetSucceededPodForJob(ctx, c, job)
	if errors.Is(err, kjob.ErrNoSucceededPod) && withinSucceededGrace(job, now) {
		return nil, true, nil
	}
	return pod, false, err
}

// jobCompletedAt is when a Succeeded Job completed: its CompletionTime, else
// its Complete condition's transition, else (a Job the cache reports
// Succeeded but not yet complete) its creation — so the grace window always
// ends.
func jobCompletedAt(job *batchv1.Job) time.Time {
	if job.Status.CompletionTime != nil {
		return job.Status.CompletionTime.Time
	}
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue && !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time
		}
	}
	return job.CreationTimestamp.Time
}

func withinSucceededGrace(job *batchv1.Job, now time.Time) bool {
	return now.Sub(jobCompletedAt(job)) < succeededPodGrace
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

// urlUserinfoRE matches a URL's scheme and userinfo ("user:pass@"). The
// userinfo run is greedy up to the authority's last '@', so a password
// containing a literal '@' is stripped whole.
var urlUserinfoRE = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://)[^/?#\s]+@`)

// redactURLUserinfo strips the credentials from every URL in s.
func redactURLUserinfo(s string) string {
	return urlUserinfoRE.ReplaceAllString(s, "${1}")
}

// quoteBadOutput quotes pod output for a condition message: URL credentials
// stripped, truncated (on a rune boundary) to badOutputQuoteLimit bytes. A
// termination message is written by whatever ran in the pod — repo contents,
// clone URLs — so it is never copied into a condition uncapped.
func quoteBadOutput(s string) string {
	s = redactURLUserinfo(s)
	if len(s) <= badOutputQuoteLimit {
		return fmt.Sprintf("%q", s)
	}
	cut := badOutputQuoteLimit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return fmt.Sprintf("%q… (%d bytes)", s[:cut], len(s))
}

// badOutputRebuilds returns the consecutive bad-output rebuilds recorded for
// generation gen.
func badOutputRebuilds(attrs map[string]string, gen int64) int {
	g, n, ok := strings.Cut(attrs[attrHarvestFailures], "=")
	if !ok || g != strconv.FormatInt(gen, 10) {
		return 0
	}
	count, err := strconv.Atoi(n)
	if err != nil {
		return 0
	}
	return count
}

// boundBadOutput decides whether a Job with unusable output may be deleted to
// rebuild (rebuild=true, the rebuild recorded against gen) or the budget is
// spent (rebuild=false: keep the Job, stay Degraded, back off). The returned
// message is msg annotated with that decision.
func boundBadOutput(attrs *map[string]string, gen int64, job *batchv1.Job, msg string) (bool, string) {
	n := badOutputRebuilds(*attrs, gen)
	if n >= maxBadOutputRebuilds {
		return false, fmt.Sprintf(
			"%s — gave up after %d rebuilds of generation %d; Job %s/%s is kept for inspection: change the spec, or delete the Job to retry once",
			msg, maxBadOutputRebuilds, gen, job.Namespace, job.Name,
		)
	}
	if *attrs == nil {
		*attrs = map[string]string{}
	}
	(*attrs)[attrHarvestFailures] = fmt.Sprintf("%d=%d", gen, n+1)
	return true, fmt.Sprintf("%s (rebuild %d of %d)", msg, n+1, maxBadOutputRebuilds)
}

// resetBadOutputRebuilds clears the bad-output budget after a good harvest.
func resetBadOutputRebuilds(attrs map[string]string) {
	delete(attrs, attrHarvestFailures)
}

func setDegraded(conditions *[]metav1.Condition, msg string) {
	kdexv1alpha1.SetConditions(
		conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconcileError,
		msg,
	)
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
// image reference to record. It writes only the bad-output budget to
// ipr.Status.Attributes; a non-nil result means the caller must return it
// (waiting, or Degraded and possibly rebuilding). An error is an API error
// for controller-runtime's backoff: the Job is left alone. Callers classify
// terminal-Failed Jobs first (classifyPackRefJob). See
// kdex-tech/host-manager#301.
func (r *KDexInternalPackageReferencesReconciler) harvestPackagesJob(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	job *batchv1.Job,
	registry string,
	now time.Time,
) (packagesHarvest, error) {
	if terminal, _ := isCodegenJobTerminal(job); terminal {
		return packagesHarvest{}, fmt.Errorf("packages job %s/%s is terminally failed; nothing to harvest", job.Namespace, job.Name)
	}
	wait := packagesHarvest{result: &ctrl.Result{RequeueAfter: r.RequeueDelay}}

	pod, waiting, err := harvestablePod(ctx, r.Client, job, now)
	if waiting {
		return wait, nil
	}
	if errors.Is(err, kjob.ErrNoSucceededPod) {
		return r.rebuildPackagesJob(ctx, ipr, job, err.Error())
	}
	if err != nil {
		return packagesHarvest{}, err
	}

	imageDigest := strings.TrimSpace(terminatedMessage(pod.Status.ContainerStatuses, "packager"))
	importmap := terminatedMessage(pod.Status.InitContainerStatuses, "importmap-generator")
	if imageDigest == "" || importmap == "" {
		// Phase and container statuses normally land together; give a lagging
		// status the same grace as a lagging pod, then treat it as bad output.
		if withinSucceededGrace(job, now) {
			return wait, nil
		}
		return r.badPackagesOutput(ctx, ipr, job, fmt.Sprintf(
			"packages job %s/%s pod %s succeeded but emitted no image digest and/or importmap (digest %s, importmap %d bytes) %s after completing — refusing to publish",
			job.Namespace, job.Name, pod.Name, quoteBadOutput(imageDigest), len(importmap), succeededPodGrace,
		))
	}

	// Never record anything but a digest: a malformed value poisons the
	// host's image pull (`invalid checksum digest format`).
	if !packref.IsValidImageDigest(imageDigest) {
		return r.badPackagesOutput(ctx, ipr, job, fmt.Sprintf(
			"packages job %s/%s pod %s emitted %s, which is not a valid image digest (want sha256:<64 hex>) — refusing to publish",
			job.Namespace, job.Name, pod.Name, quoteBadOutput(imageDigest),
		))
	}

	return packagesHarvest{
		builtImage: fmt.Sprintf("%s/%s/packages:%d@%s", registry, ipr.Name, ipr.Generation, imageDigest),
		importmap:  importmap,
	}, nil
}

// badPackagesOutput handles a packages Job whose output must not be
// published: rebuild within the maxBadOutputRebuilds budget for the IPR's
// generation; past it, stay Degraded, keep the Job and back off.
func (r *KDexInternalPackageReferencesReconciler) badPackagesOutput(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	job *batchv1.Job,
	msg string,
) (packagesHarvest, error) {
	rebuild, msg := boundBadOutput(&ipr.Status.Attributes, ipr.Generation, job, msg)
	if rebuild {
		return r.rebuildPackagesJob(ctx, ipr, job, msg)
	}
	setDegraded(&ipr.Status.Conditions, msg)
	return packagesHarvest{result: &ctrl.Result{RequeueAfter: badOutputGiveUpRequeue}}, nil
}

// rebuildPackagesJob marks the IPR Degraded with msg and deletes the Job so
// the next pass rebuilds. status.image is left untouched: the host keeps
// serving the last known-good image.
func (r *KDexInternalPackageReferencesReconciler) rebuildPackagesJob(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	job *batchv1.Job,
	msg string,
) (packagesHarvest, error) {
	setDegraded(&ipr.Status.Conditions, msg)
	if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
		return packagesHarvest{}, err
	}
	return packagesHarvest{result: &ctrl.Result{RequeueAfter: r.RequeueDelay}}, nil
}

// functionHarvest is the outcome of harvestFunctionJob.
type functionHarvest struct {
	// output is the container's termination message of a Succeeded pod.
	output string
	// waiting: the Job is still running (or its pod not yet visible); the
	// caller reports Progressing and requeues.
	waiting bool
	// terminal: the Job is terminally Failed and was marked so; it is kept.
	terminal bool
	// result, when non-nil, is returned by the caller as-is.
	result *ctrl.Result
}

// harvestFunctionJob reads a KDexFunction codegen or deployer Job's output —
// the named container's termination message — from its Succeeded pod.
//
//   - waiting: still running, or the Succeeded pod not visible yet.
//   - terminal: JobFailed=True. Marked terminally failed with the Job
//     condition's message and the (capped, redacted) termination text of the
//     newest pod, if any is left; the Job is never deleted (#27).
//   - Succeeded pod gone past the grace: Degraded, Job deleted to rebuild.
//   - any other error: an API error, Degraded and returned for backoff; the
//     Job is left alone.
//
// See kdex-tech/host-manager#301.
func (r *KDexFunctionReconciler) harvestFunctionJob(
	ctx context.Context,
	fn *kdexv1alpha1.KDexFunction,
	job *batchv1.Job,
	container string,
	now time.Time,
) (functionHarvest, error) {
	pod, waiting, err := harvestablePod(ctx, r.Client, job, now)
	if waiting {
		return functionHarvest{waiting: true}, nil
	}
	if errors.Is(err, kjob.ErrNoSucceededPod) {
		res, err := r.rebuildFunctionJob(ctx, fn, job, err.Error())
		return functionHarvest{result: &res}, err
	}
	if err != nil {
		setDegraded(&fn.Status.Conditions, err.Error())
		return functionHarvest{}, err
	}

	var output string
	if pod != nil {
		output = terminatedMessage(pod.Status.ContainerStatuses, container)
	}
	if terminal, msg := isCodegenJobTerminal(job); terminal {
		markCodegenJobTerminallyFailed(fn, job, msg, output)
		return functionHarvest{terminal: true, result: &ctrl.Result{}}, nil
	}
	return functionHarvest{output: output}, nil
}

// badFunctionOutput handles a function Job whose Succeeded pod emitted
// unusable output: rebuild within the maxBadOutputRebuilds budget for the
// function's generation; past it, stay Degraded, keep the Job and back off.
func (r *KDexFunctionReconciler) badFunctionOutput(
	ctx context.Context,
	fn *kdexv1alpha1.KDexFunction,
	job *batchv1.Job,
	msg string,
) (ctrl.Result, error) {
	rebuild, msg := boundBadOutput(&fn.Status.Attributes, fn.Generation, job, msg)
	if rebuild {
		return r.rebuildFunctionJob(ctx, fn, job, msg)
	}
	setDegraded(&fn.Status.Conditions, msg)
	return ctrl.Result{RequeueAfter: badOutputGiveUpRequeue}, nil
}

// rebuildFunctionJob marks the function Degraded with msg and deletes the
// Job so the next pass recreates it.
func (r *KDexFunctionReconciler) rebuildFunctionJob(
	ctx context.Context,
	fn *kdexv1alpha1.KDexFunction,
	job *batchv1.Job,
	msg string,
) (ctrl.Result, error) {
	setDegraded(&fn.Status.Conditions, msg)
	if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
}

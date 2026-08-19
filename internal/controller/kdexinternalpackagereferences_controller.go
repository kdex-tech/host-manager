/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	kjob "github.com/kdex-tech/host-manager/internal/job"
	"github.com/kdex-tech/host-manager/internal/packref"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// KDexInternalPackageReferencesReconciler reconciles a KDexInternalPackageReferences object
type KDexInternalPackageReferencesReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	RequeueDelay        time.Duration
	Scheme              *runtime.Scheme
}

//nolint:gocyclo
func (r *KDexInternalPackageReferencesReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	if req.Namespace != r.ControllerNamespace {
		log.V(4).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	var ipr kdexv1alpha1.KDexInternalPackageReferences
	if err := r.Get(ctx, req.NamespacedName, &ipr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if ipr.Spec.HostRef.Name != r.FocalHost {
		log.V(4).Info("skipping reconcile", "host", ipr.Spec.HostRef.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	if ipr.Status.Attributes == nil {
		ipr.Status.Attributes = make(map[string]string)
	}

	// Snapshot the observed status so the deferred write can be made
	// conditional on an actual change.
	observedStatus := ipr.Status.DeepCopy()

	// Defer status update
	defer func() {
		ipr.Status.ObservedGeneration = ipr.Generation

		// Only write status when it actually changed. The reconciler pulses a
		// transient "Reconciling" condition every pass, which bumps
		// LastTransitionTime even when the net settled status is unchanged. An
		// unconditional Status().Update() would then bump resourceVersion every
		// reconcile, re-firing the controller's own For() watch and self-looping
		// (pegs a CPU core). See kdex-tech/host-manager#131 (#126 residual).
		if !objectStatusEqual(observedStatus, &ipr.Status) {
			updateErr := r.Status().Update(ctx, &ipr)
			if updateErr != nil {
				if kerrors.IsConflict(updateErr) {
					err = nil
					res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
				} else {
					err = updateErr
					res = ctrl.Result{}
				}
			}
		}

		log.V(3).Info("status", "status", ipr.Status, "err", err, "res", res)
	}()

	kdexv1alpha1.SetConditions(
		&ipr.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionUnknown,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		"Reconciling",
	)

	internalHost, shouldReturn, r1, err := ResolveHost(ctx, r.Client, &ipr, &ipr.Status.Conditions, &ipr.Spec.HostRef, r.RequeueDelay, false)
	if shouldReturn {
		return r1, err
	}

	secrets, err := ResolveSecrets(ctx, r.Client, &ipr.Status, internalHost.Namespace, internalHost.Spec.SecretSelector)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return ctrl.Result{}, err
	}

	imagePullSecrets := secrets.Filter(
		func(s corev1.Secret) bool {
			return s.Type == corev1.SecretTypeDockerConfigJson
		},
	)

	imagePullSecretRefs := make([]corev1.LocalObjectReference, 0, len(imagePullSecrets))
	for _, s := range imagePullSecrets {
		imagePullSecretRefs = append(imagePullSecretRefs, corev1.LocalObjectReference{Name: s.Name})
	}

	imagePushSecret := secrets.Find(
		func(s corev1.Secret) bool {
			return s.Type == corev1.SecretTypeDockerConfigJson && s.Annotations["kdex.dev/secret-type"] == "docker-push"
		},
	)

	configMapOp, configMap, err := r.createOrUpdateJobConfigMap(ctx, &ipr)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return ctrl.Result{}, err
	}

	// registries is optional, so read it through the accessor and keep the
	// resolved default local — mutating the fetched CR only ever confused the
	// next reader, and nothing writes it back.
	npmRegistry := internalHost.Spec.GetRegistries().NpmRegistry
	if npmRegistry == "" {
		npmRegistry = r.Configuration.DefaultNpmRegistry
	}

	secretOp, secret, err := r.createOrUpdateJobSecret(ctx, &ipr, npmRegistry, secrets)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return ctrl.Result{}, err
	}

	log.V(2).Info(
		"created or updated job config map and secret",
		"configMap", configMap.Name,
		"configMapOperation", configMapOp,
		"secret", secret.Name,
		"secretOperation", secretOp,
	)

	builder := packref.PackRef{
		Client:           r.Client,
		ConfigMap:        configMap,
		InternalHost:     internalHost,
		ImageRegistry:    internalHost.Spec.GetRegistries().ImageRegistry,
		ImagePushSecret:  imagePushSecret,
		ImagePullSecrets: imagePullSecretRefs,
		Log:              log,
		NPMSecret:        *secret,
		Packages:         &r.Configuration.Packages,
		Scheme:           r.Scheme,
		ServiceAccount:   os.Getenv("KUBERNETES_SERVICE_ACCOUNT"),
	}

	job, err := builder.GetOrCreatePackRefJob(ctx, &ipr)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	// A nil Job means the image for the current generation is already built and
	// recorded in status (the Job object was GC'd / reaped). Don't rebuild —
	// just GC superseded prior-gen Jobs and report Ready. See
	// kdex-tech/host-manager#111.
	if job == nil {
		if err := r.cleanupJobs(ctx, &ipr); err != nil {
			return ctrl.Result{}, err
		}
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionFalse,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionTrue,
			},
			kdexv1alpha1.ConditionReasonReconcileSuccess,
			"Reconciliation successful, package image already built for current generation",
		)
		log.V(2).Info("package image already built for current generation, skipping rebuild", "image", ipr.Status.Attributes["image"])
		return ctrl.Result{}, nil
	}

	switch state, terminalMsg := classifyPackRefJob(job); state {
	case packRefJobTerminalFailed:
		// BackoffLimit exhausted (or JobFailed flipped True for any
		// other reason). Mark Degraded but DO NOT delete the Job —
		// operator needs to inspect the failed pods. See
		// kdex-tech/host-manager#61 (and #27 for the parallel
		// KDexFunction fix).
		err := fmt.Errorf("packages job %s/%s exhausted retries: %s — inspect pods for details (Job is NOT auto-deleted)", job.Namespace, job.Name, terminalMsg)
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)
		log.V(1).Info("packages job terminally failed", "job", job.Name, "msg", terminalMsg)
		return ctrl.Result{}, nil

	case packRefJobInProgress:
		// Either freshly created (Succeeded=0, Failed=0) or mid-retry
		// (Failed>0 but JobFailed!=True — BackoffLimit hasn't fired).
		// Both cases: wait. Pre-#61 the controller treated Failed==1 as
		// terminal here, defeating BackoffLimit and surfacing transient
		// npm flakes as permanent failures.
		message := fmt.Sprintf("Waiting on packages job %s/%s to complete (Succeeded=%d, Failed=%d)",
			job.Namespace, job.Name, job.Status.Succeeded, job.Status.Failed)
		kdexv1alpha1.SetConditions(
			&ipr.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionFalse,
				Progressing: metav1.ConditionTrue,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconciling,
			message,
		)
		log.V(2).Info(message)
		if err := r.cleanupJobs(ctx, &ipr); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil

	case packRefJobSucceeded:
		// Harvest results from the successful pod.
		pod, err := kjob.GetPodForJob(ctx, r.Client, job)
		if err != nil {
			kdexv1alpha1.SetConditions(
				&ipr.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)
			if err := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		var imageDigest string
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.Name == "packager" && containerStatus.State.Terminated != nil {
				imageDigest = strings.TrimSpace(containerStatus.State.Terminated.Message)
				break
			}
		}

		var importmap string
		for _, containerStatus := range pod.Status.InitContainerStatuses {
			if containerStatus.Name == "importmap-generator" && containerStatus.State.Terminated != nil {
				importmap = containerStatus.State.Terminated.Message
				break
			}
		}

		if imageDigest == "" || importmap == "" {
			// Job reported success but we can't find the outputs yet? Wait a bit.
			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		builtImage := fmt.Sprintf(
			"%s/%s/packages:%d@%s", internalHost.Spec.GetRegistries().ImageRegistry, ipr.Name, ipr.Generation, imageDigest,
		)

		// The Job reported success, but "success" has been observed to mean
		// "shipped the PREVIOUS version's bytes": during the npm propagation
		// window the aggregation can retain a package's prior content instead
		// of failing. Verify the built image actually carries the pinned
		// versions BEFORE publishing status.image, so a poisoned build is
		// never promoted onto the serving Deployment.
		// See kdex-tech/host-manager#161.
		if mismatches, verifyErr := r.verifyBuiltImage(ctx, &ipr, builtImage, secrets); verifyErr != nil {
			// Could not verify (registry unreachable, unfamiliar image shape).
			// Do NOT treat unverifiable as poisoned — that would fail every
			// build on a registry blip. Publish and record the gap.
			log.V(1).Info("could not verify pinned versions in packages image; publishing unverified",
				"image", builtImage, "error", verifyErr.Error())
			ipr.Status.Attributes["verified"] = "unknown"
		} else if len(mismatches) > 0 {
			msgs := make([]string, 0, len(mismatches))
			for _, m := range mismatches {
				msgs = append(msgs, m.String())
			}
			err := fmt.Errorf(
				"packages image %s does not match its pins: %s — refusing to publish (likely an npm propagation-window aggregation; the next reconcile rebuilds)",
				builtImage, strings.Join(msgs, "; "),
			)
			kdexv1alpha1.SetConditions(
				&ipr.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)
			log.Error(err, "stale packages image rejected", "image", builtImage)

			// Delete the Job so the next pass rebuilds rather than reusing this
			// build. status.image is deliberately left untouched: the host
			// keeps serving the last KNOWN-GOOD image instead of promoting
			// stale bytes.
			if delErr := r.Delete(ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(delErr) != nil {
				return ctrl.Result{}, delErr
			}
			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		} else {
			ipr.Status.Attributes["verified"] = "pins"
		}

		ipr.Status.Attributes["image"] = builtImage
		ipr.Status.Attributes["importmap"] = importmap
	}

	if err := r.cleanupJobs(ctx, &ipr); err != nil {
		return ctrl.Result{}, err
	}

	kdexv1alpha1.SetConditions(
		&ipr.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful, package image ready",
	)

	log.V(1).Info("package image ready", "job", job.Name)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KDexInternalPackageReferencesReconciler) SetupWithManager(mgr ctrl.Manager) error {
	hasFocalHost := func(o client.Object) bool {
		switch t := o.(type) {
		case *kdexv1alpha1.KDexInternalPackageReferences:
			return t.Spec.HostRef.Name == r.FocalHost
		default:
			return true
		}
	}

	var enabledFilter = predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasFocalHost(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return hasFocalHost(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasFocalHost(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasFocalHost(e.Object)
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexInternalPackageReferences{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{}).
		WithEventFilter(enabledFilter).
		WithOptions(
			controller.TypedOptions[reconcile.Request]{
				LogConstructor: LogConstructor("kdexinternalpackagereferences", mgr),
			},
		).
		Named("kdexinternalpackagereferences").
		Complete(r)
}

// cleanupJobs deletes packager Jobs from generations strictly older than
// ipr.Generation, regardless of whether they have terminated. This supersedes
// in-flight prior-gen Jobs when a burst of IPR generation bumps would otherwise
// spawn parallel packager runs that all but the latest are guaranteed to be
// discarded (see kdex-tech/host-manager#19).
func (r *KDexInternalPackageReferencesReconciler) cleanupJobs(ctx context.Context, ipr *kdexv1alpha1.KDexInternalPackageReferences) error {
	log := logf.FromContext(ctx)
	var jobList batchv1.JobList
	if err := r.List(ctx, &jobList, client.InNamespace(ipr.Namespace), client.MatchingLabels{
		"app":      "packages",
		"packages": ipr.Name,
	}); err != nil {
		return err
	}

	for _, job := range jobList.Items {
		genLabel := job.Labels["kdex.dev/generation"]
		jobGen, parseErr := strconv.ParseInt(genLabel, 10, 64)
		if parseErr != nil {
			log.V(2).Info("Skipping job with missing or unparseable generation label", "job", job.Name, "label", genLabel)
			continue
		}
		if jobGen >= ipr.Generation {
			continue
		}

		log.V(2).Info("Deleting superseded packager job", "job", job.Name, "jobGen", jobGen, "currentGen", ipr.Generation)
		if err := r.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
			return err
		}
	}
	return nil
}

func (r *KDexInternalPackageReferencesReconciler) createOrUpdateJobConfigMap(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
) (controllerutil.OperationResult, *corev1.ConfigMap, error) {
	configmap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-packages", ipr.Name),
			Namespace: ipr.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		configmap,
		func() error {
			if configmap.CreationTimestamp.IsZero() {
				configmap.Annotations = make(map[string]string)
				maps.Copy(configmap.Annotations, ipr.Annotations)
				configmap.Labels = make(map[string]string)
				maps.Copy(configmap.Labels, ipr.Labels)

				configmap.Labels["kdex.dev/packages"] = ipr.Name
			}

			pj := struct {
				Name         string            `json:"name"`
				Type         string            `json:"type"`
				Dependencies map[string]string `json:"dependencies"`
			}{
				Name:         "importmap",
				Type:         "module",
				Dependencies: map[string]string{},
			}

			for _, pkg := range ipr.Spec.PackageReferences {
				pj.Dependencies[pkg.Name] = pkg.Version
			}

			bytes, _ := json.MarshalIndent(pj, "", "  ")

			configmap.Data = map[string]string{
				"package.json": string(bytes),
			}

			return ctrl.SetControllerReference(ipr, configmap, r.Scheme)
		},
	)

	return op, configmap, err
}

// verifyBuiltImage reports which pinned packages the built image fails to
// satisfy. An error means verification could not be performed at all, which is
// distinct from — and must not be conflated with — a confirmed mismatch.
//
// Split out so the propagation-window guard (kdex-tech/host-manager#161) is
// exercised directly by tests; VerifyPinnedVersions itself is registry-free.
func (r *KDexInternalPackageReferencesReconciler) verifyBuiltImage(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	imageRef string,
	secrets kdexv1alpha1.Secrets,
) ([]VersionMismatch, error) {
	pins := make(map[string]string, len(ipr.Spec.PackageReferences))
	for _, pkg := range ipr.Spec.PackageReferences {
		pins[pkg.Name] = pkg.Version
	}
	if len(pins) == 0 {
		return nil, nil
	}

	layers, fetch, err := openImageLayers(ctx, imageRef, secrets)
	if err != nil {
		return nil, fmt.Errorf("open packages image %s: %w", imageRef, err)
	}
	return VerifyPinnedVersions(ctx, layers, pins, fetch)
}

func (r *KDexInternalPackageReferencesReconciler) createOrUpdateJobSecret(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	npmRegistry string,
	secrets kdexv1alpha1.Secrets,
) (controllerutil.OperationResult, *corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-secret", ipr.Name),
			Namespace: ipr.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		secret,
		func() error {
			if secret.CreationTimestamp.IsZero() {
				secret.Annotations = make(map[string]string)
				maps.Copy(secret.Annotations, ipr.Annotations)
				secret.Labels = make(map[string]string)
				maps.Copy(secret.Labels, ipr.Labels)

				secret.Labels["kdex.dev/packages"] = ipr.Name
			}

			var npmrcContent strings.Builder

			if !strings.Contains(npmRegistry, "://") {
				// add https://
				npmRegistry = "https://" + npmRegistry
			}

			fmt.Fprintf(&npmrcContent, "registry=%s\n", npmRegistry)

			npmSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "npm" })

			for _, s := range npmSecrets {
				fmt.Fprintf(&npmrcContent, "%s\n", s.Data[".npmrc"])
			}

			for _, packageReference := range ipr.Spec.PackageReferences {
				if packageReference.SecretRef != nil {
					namespace := ipr.Namespace
					if packageReference.SecretRef.Namespace != "" {
						namespace = packageReference.SecretRef.Namespace
					}

					secret := &corev1.Secret{}
					if err := r.Get(ctx, client.ObjectKey{
						Namespace: namespace,
						Name:      packageReference.SecretRef.Name,
					}, secret); err != nil {
						return err
					}
					fmt.Fprintf(&npmrcContent, "%s\n", secret.Data[".npmrc"])
				}

				if packageReference.Registry != "" {
					namespace := strings.Split(packageReference.Name, "/")[0]

					if !strings.HasSuffix(packageReference.Registry, "/") {
						packageReference.Registry = packageReference.Registry + "/"
					}

					regEntry := fmt.Sprintf("%s:registry=%s\n", namespace, packageReference.Registry)

					if !strings.Contains(npmrcContent.String(), regEntry) {
						fmt.Fprint(&npmrcContent, regEntry)
					}
				}
			}

			secret.StringData = map[string]string{
				".npmrc": npmrcContent.String(),
			}

			return ctrl.SetControllerReference(ipr, secret, r.Scheme)
		},
	)

	return op, secret, err
}

// packRefJobState classifies the high-level state of the IPR's packref
// Job (`InProgress`, `Succeeded`, `TerminalFailed`). Used to remove the
// hard-coded `job.Status.Failed == 1` short-circuit that prematurely
// retired transient first-pod failures and let `Failed >= 2` fall
// through to a bogus imageDigest extraction from a failed pod's
// termination message. See kdex-tech/host-manager#61, and the parallel
// fix for KDexFunction in #27 (isCodegenJobTerminal).
type packRefJobState int

const (
	packRefJobInProgress packRefJobState = iota
	packRefJobSucceeded
	packRefJobTerminalFailed
)

func classifyPackRefJob(job *batchv1.Job) (packRefJobState, string) {
	if ok, msg := isCodegenJobTerminal(job); ok {
		return packRefJobTerminalFailed, msg
	}
	if job.Status.Succeeded > 0 {
		return packRefJobSucceeded, ""
	}
	return packRefJobInProgress, ""
}

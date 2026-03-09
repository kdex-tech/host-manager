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
	"strings"
	"time"

	kjob "github.com/kdex-tech/host-manager/internal/job"
	"github.com/kdex-tech/host-manager/internal/packref"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
		log.V(3).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	var ipr kdexv1alpha1.KDexInternalPackageReferences
	if err := r.Get(ctx, req.NamespacedName, &ipr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if ipr.Spec.HostRef.Name != r.FocalHost {
		log.V(3).Info("skipping reconcile", "host", ipr.Spec.HostRef.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	if ipr.Status.Attributes == nil {
		ipr.Status.Attributes = make(map[string]string)
	}

	// Defer status update
	defer func() {
		ipr.Status.ObservedGeneration = ipr.Generation
		if updateErr := r.Status().Update(ctx, &ipr); updateErr != nil {
			err = updateErr
			res = ctrl.Result{}
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

	serviceAccount := internalHost.Name
	if internalHost.Spec.ServiceAccountRef != nil && internalHost.Spec.ServiceAccountRef.Name != "" {
		serviceAccount = internalHost.Spec.ServiceAccountRef.Name
	}
	secrets, err := ResolveServiceAccountSecrets(ctx, r.Client, &ipr.Status, internalHost.Namespace, serviceAccount)
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

	internalHost.Spec.ServiceAccountSecrets = secrets

	imagePullSecrets := internalHost.Spec.ServiceAccountSecrets.Filter(
		func(s corev1.Secret) bool {
			return s.Type == corev1.SecretTypeDockerConfigJson
		},
	)

	imagePullSecretRefs := make([]corev1.LocalObjectReference, 0, len(imagePullSecrets))
	for _, s := range imagePullSecrets {
		imagePullSecretRefs = append(imagePullSecretRefs, corev1.LocalObjectReference{Name: s.Name})
	}

	imagePushSecret := internalHost.Spec.ServiceAccountSecrets.Find(
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

	secretOp, secret, err := r.createOrUpdateJobSecret(ctx, &ipr, internalHost.Spec.Registries.NpmRegistry, internalHost.Spec.ServiceAccountSecrets)
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

	serviceAccountRef := internalHost.Spec.ServiceAccountRef
	if serviceAccountRef == nil || serviceAccountRef.Name == "" {
		serviceAccountRef = &corev1.LocalObjectReference{
			Name: internalHost.Name,
		}
	}

	builder := packref.PackRef{
		Client:            r.Client,
		ConfigMap:         configMap,
		InternalHost:      internalHost,
		ImageRegistry:     internalHost.Spec.Registries.ImageRegistry,
		ImagePushSecret:   imagePushSecret,
		ImagePullSecrets:  imagePullSecretRefs,
		Log:               log,
		NPMSecret:         *secret,
		Packages:          &r.Configuration.Packages,
		Scheme:            r.Scheme,
		ServiceAccountRef: *serviceAccountRef,
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

	if job.Status.Succeeded == 0 && job.Status.Failed == 0 {
		message := fmt.Sprintf("Waiting on packages job %s/%s to complete", job.Namespace, job.Name)
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

		if err := r.cleanupJobs(ctx, &ipr, "packages"); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	} else {
		// Harvest results from the pods
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

		var terminationMessage string
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.Name == "packager" && containerStatus.State.Terminated != nil {
				terminationMessage = strings.TrimSpace(containerStatus.State.Terminated.Message)
				break
			}
		}

		if job.Status.Failed == 1 {
			err := fmt.Errorf("packages job %s/%s failed: %s", job.Namespace, job.Name, terminationMessage)
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

		imageDigest := terminationMessage

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

		ipr.Status.Attributes["image"] = fmt.Sprintf(
			"%s/%s/packages:%d@%s", internalHost.Spec.Registries.ImageRegistry, ipr.Name, ipr.Generation, imageDigest,
		)
		ipr.Status.Attributes["importmap"] = importmap
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

func (r *KDexInternalPackageReferencesReconciler) cleanupJobs(ctx context.Context, ipr *kdexv1alpha1.KDexInternalPackageReferences, appLabel string) error {
	log := logf.FromContext(ctx)
	var jobList batchv1.JobList
	if err := r.List(ctx, &jobList, client.InNamespace(ipr.Namespace), client.MatchingLabels{
		"app":      appLabel,
		"packages": ipr.Name,
	}); err != nil {
		return err
	}

	currentGen := fmt.Sprintf("%d", ipr.Generation)
	for _, job := range jobList.Items {
		if job.Labels["kdex.dev/generation"] != currentGen && (job.Status.Succeeded > 0 || job.Status.Failed > 0) {
			log.V(2).Info("Cleaning up obsolete job from previous generation", "job", job.Name, "jobGen", job.Labels["kdex.dev/generation"], "app", appLabel)
			if err := r.Delete(ctx, &job, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
				return err
			}
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

func (r *KDexInternalPackageReferencesReconciler) createOrUpdateJobSecret(
	ctx context.Context,
	ipr *kdexv1alpha1.KDexInternalPackageReferences,
	npmRegistry string,
	secrets kdexv1alpha1.ServiceAccountSecrets,
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

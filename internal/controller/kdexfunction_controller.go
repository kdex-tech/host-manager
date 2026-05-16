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
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/build"
	"github.com/kdex-tech/host-manager/internal/deploy"
	"github.com/kdex-tech/host-manager/internal/generate"
	"github.com/kdex-tech/host-manager/internal/host"
	kjob "github.com/kdex-tech/host-manager/internal/job"
	"github.com/kdex-tech/host-manager/internal/utils"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// KDexFunctionReconciler reconciles a KDexFunction object
type KDexFunctionReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	HostHandler         *host.HostHandler
	RequeueDelay        time.Duration
	Scheme              *runtime.Scheme
}

type handlerContext struct {
	ctx              context.Context
	faasAdaptorSpec  kdexv1alpha1.KDexFaaSAdaptorSpec
	function         *kdexv1alpha1.KDexFunction
	gitSecret        *corev1.Secret
	host             kdexv1alpha1.KDexInternalHost
	imagePullSecrets []corev1.Secret
	req              ctrl.Request
	serviceAccount   string
}

//nolint:gocyclo
func (r *KDexFunctionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	if req.Namespace != r.ControllerNamespace {
		log.V(4).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	var function kdexv1alpha1.KDexFunction
	if err := r.Get(ctx, req.NamespacedName, &function); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if function.Spec.HostRef.Name != r.FocalHost {
		log.V(4).Info("skipping reconcile", "name", function.Spec.HostRef.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	if function.Status.Attributes == nil {
		function.Status.Attributes = make(map[string]string)
	}

	// Defer status update
	defer func() {
		function.Status.ObservedGeneration = function.Generation
		updateErr := r.Status().Update(ctx, &function)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("status", "status", function.Status, "err", err, "res", res)
	}()

	if function.Status.ObservedGeneration < function.Generation {
		function.Status.State = kdexv1alpha1.KDexFunctionStatePending
	}

	kdexv1alpha1.SetConditions(
		&function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionUnknown,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		string(function.Status.State),
	)

	internalHost, shouldReturn, r1, err := ResolveHost(ctx, r.Client, &function, &function.Status.Conditions, &function.Spec.HostRef, r.RequeueDelay, false)
	if shouldReturn {
		return r1, err
	}

	function.Status.Attributes["host.generation"] = fmt.Sprintf("%d", internalHost.GetGeneration())

	faasAdaptorObj, shouldReturn, r1, err := ResolveOrDefaultFaaSAdaptor(ctx, r.Client, &function, &function.Status.Conditions, internalHost, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if faasAdaptorObj == nil {
		err = fmt.Errorf("no KDexFaaSAdaptors were found to handle function %s/%s", function.Namespace, function.Name)

		kdexv1alpha1.SetConditions(
			&function.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileSuccess,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	var faasAdaptorSpec *kdexv1alpha1.KDexFaaSAdaptorSpec

	switch v := faasAdaptorObj.(type) {
	case *kdexv1alpha1.KDexClusterFaaSAdaptor:
		faasAdaptorSpec = &v.Spec
	case *kdexv1alpha1.KDexFaaSAdaptor:
		faasAdaptorSpec = &v.Spec
	}

	currentGen := fmt.Sprintf("%d", faasAdaptorObj.GetGeneration())
	if function.Status.Attributes["faasAdaptor.generation"] != "" && function.Status.Attributes["faasAdaptor.generation"] != currentGen {
		log.Info("FaaS Adaptor updated, re-reconciling", "oldGen", function.Status.Attributes["faasAdaptor.generation"], "newGen", currentGen)
		function.Status.State = kdexv1alpha1.KDexFunctionStateOpenAPIValid
	}
	function.Status.Attributes["faasAdaptor.generation"] = currentGen

	secrets, err := ResolveSecrets(ctx, r.Client, &function.Status.KDexObjectStatus, internalHost.Namespace, internalHost.Spec.SecretSelector)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&function.Status.Conditions,
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

	hc := handlerContext{
		ctx:             ctx,
		faasAdaptorSpec: *faasAdaptorSpec,
		function:        &function,
		gitSecret: secrets.Find(
			func(s corev1.Secret) bool {
				return s.Annotations["kdex.dev/secret-type"] == "git"
			},
		),
		host: *internalHost,
		imagePullSecrets: secrets.Filter(
			func(s corev1.Secret) bool {
				return s.Type == corev1.SecretTypeDockerConfigJson
			},
		),
		req:            req,
		serviceAccount: os.Getenv("KUBERNETES_SERVICE_ACCOUNT"),
	}

	// Pick up asynchronous builder updates (e.g. from KPack git polling)
	if function.Spec.Origin.Executable == nil && function.Status.Source != nil {
		kImageName := fmt.Sprintf("%s-%s", hc.host.Name, function.Name)
		image := &unstructured.Unstructured{}
		image.SetGroupVersionKind(internal.KPackImageGVK)
		if err := r.Get(ctx, types.NamespacedName{Name: kImageName, Namespace: function.Namespace}, image); err == nil {
			latestImage, found, _ := unstructured.NestedString(image.Object, "status", "latestImage")
			if found && latestImage != "" {
				if function.Status.State == kdexv1alpha1.KDexFunctionStateReady && function.Status.Executable.Image != latestImage {
					log.Info("New image detected from KPack, re-reconciling from source available", "latestImage", latestImage)
					function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
				}
			}
		} else if !kerrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
			return ctrl.Result{}, err
		}
	}

	switch function.Status.State {
	case kdexv1alpha1.KDexFunctionStatePending:
		return r.handlePending(hc), nil
	case kdexv1alpha1.KDexFunctionStateOpenAPIValid:
		return r.handleOpenAPIValid(hc)
	case kdexv1alpha1.KDexFunctionStateBuildValid:
		return r.handleBuildValid(hc)
	case kdexv1alpha1.KDexFunctionStateSourceAvailable:
		return r.handleSourceAvailable(hc)
	case kdexv1alpha1.KDexFunctionStateExecutableAvailable:
		return r.handleExecutableAvailable(hc)
	case kdexv1alpha1.KDexFunctionStateFunctionDeployed:
		return r.handleFunctionDeployed(hc)
	case kdexv1alpha1.KDexFunctionStateReady:
		return r.handleReady(hc)
	}

	kdexv1alpha1.SetConditions(
		&function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	log.V(1).Info("reconciled")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *KDexFunctionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	kPackUn := &unstructured.Unstructured{}
	kPackUn.SetGroupVersionKind(internal.KPackImageGVK)

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexFunction{}).
		Owns(&batchv1.Job{}).
		Owns(&batchv1.CronJob{})

	ok, err := CRDExists(mgr, internal.KPackImageGVK)
	if err != nil {
		return err
	}
	if ok {
		builder = builder.Owns(kPackUn)
	}

	return builder.
		Watches(
			&kdexv1alpha1.KDexInternalHost{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexFunction{}, &kdexv1alpha1.KDexFunctionList{}, "{.Spec.HostRef}")).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			LogConstructor: LogConstructor("kdexfunction", mgr),
		}).
		Named("kdexfunction").
		Complete(r)
}

// parseBuilderGenerator splits a FaaSAdaptor DefaultBuilderGenerator string
// "<builder>/<language>" into its two parts. Returns an error if the value
// is empty or contains no "/" separator, so callers don't index a 1-element
// slice and panic.
func parseBuilderGenerator(s string) (builder, language string, err error) {
	builder, language, ok := strings.Cut(s, "/")
	if !ok {
		return "", "", fmt.Errorf("invalid defaultBuilderGenerator %q: expected '<builder>/<language>'", s)
	}
	return builder, language, nil
}

func (r *KDexFunctionReconciler) handlePending(hc handlerContext) ctrl.Result {
	log := logf.FromContext(hc.ctx)

	scheme := hc.host.Spec.Routing.Scheme
	hc.function.Status.OpenAPISchemaURL = fmt.Sprintf("%s://%s/-/openapi?type=function&tag=%s", scheme, hc.host.Spec.Routing.Domains[0], hc.function.Name)
	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateOpenAPIValid
	hc.function.Status.Detail = fmt.Sprintf("%v: %s", kdexv1alpha1.KDexFunctionStateOpenAPIValid, hc.function.Status.OpenAPISchemaURL)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{RequeueAfter: r.RequeueDelay}
}

func (r *KDexFunctionReconciler) handleOpenAPIValid(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	if hc.function.Spec.Origin.Executable != nil {
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateExecutableAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	} else if hc.function.Spec.Origin.Source != nil {
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	if hc.function.Spec.Origin.Generator != nil {
		hc.function.Status.Generator = hc.function.Spec.Origin.Generator
	} else {
		var g *kdexv1alpha1.Generator

		_, defaultLanguage, err := parseBuilderGenerator(hc.faasAdaptorSpec.DefaultBuilderGenerator)
		if err != nil {
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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

		for _, generator := range hc.faasAdaptorSpec.Generators {
			if generator.Language == defaultLanguage {
				g = &generator
				break
			}
		}

		if g == nil {
			err := fmt.Errorf(
				"generator %s not found for function %s/%s",
				defaultLanguage,
				hc.function.Namespace,
				hc.function.Name,
			)
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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

		hc.function.Status.Generator = g
	}

	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateBuildValid
	hc.function.Status.Detail = fmt.Sprintf("%v: %s/%s", kdexv1alpha1.KDexFunctionStateBuildValid, hc.function.Status.Generator.Language, hc.function.Status.Generator.Image)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
}

func (r *KDexFunctionReconciler) handleBuildValid(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	if hc.function.Spec.Origin.Executable != nil {
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateExecutableAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	if hc.function.Spec.Origin.Source != nil {
		hc.function.Status.Source = hc.function.Spec.Origin.Source
	} else {
		if hc.gitSecret == nil {
			err := fmt.Errorf(
				"git secret not found for host %s/%s",
				hc.host.Namespace,
				hc.host.Name,
			)
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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

		generator := generate.Generator{
			Client: r.Client,
			Config: *hc.function.Status.Generator,
			GitSecret: corev1.LocalObjectReference{
				Name: hc.gitSecret.Name,
			},
			ImagePullSecrets: utils.MapSlice(hc.imagePullSecrets, func(s corev1.Secret) corev1.LocalObjectReference {
				return corev1.LocalObjectReference{
					Name: s.Name,
				}
			}),
			OpenAPIBuilder: r.HostHandler.GetOpenAPIBuilder(),
			Scheme:         r.Scheme,
			ServerUrl:      fmt.Sprintf("%s://%s", hc.host.Spec.Routing.Scheme, hc.host.Spec.Routing.Domains[0]),
			ServiceAccount: hc.serviceAccount,
		}

		job, err := generator.GetOrCreateGenerateJob(hc.ctx, hc.function)
		if err != nil {
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionFalse,
					Progressing: metav1.ConditionTrue,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconciling,
				fmt.Sprintf("Waiting on code generation job %s/%s to complete", job.Namespace, job.Name),
			)

			log.V(2).Info(fmt.Sprintf("Waiting on code generation job %s/%s to complete", job.Namespace, job.Name))

			if err := r.cleanupJobs(hc.ctx, hc.function, "codegen"); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		} else {
			pod, err := kjob.GetPodForJob(hc.ctx, r.Client, job)
			if err != nil {
				kdexv1alpha1.SetConditions(
					&hc.function.Status.Conditions,
					kdexv1alpha1.ConditionStatuses{
						Degraded:    metav1.ConditionTrue,
						Progressing: metav1.ConditionFalse,
						Ready:       metav1.ConditionFalse,
					},
					kdexv1alpha1.ConditionReasonReconcileError,
					err.Error(),
				)

				if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
					return ctrl.Result{}, err
				}

				return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
			}

			var terminationMessage string
			for _, containerStatus := range pod.Status.ContainerStatuses {
				if containerStatus.Name == "results" && containerStatus.State.Terminated != nil {
					terminationMessage = containerStatus.State.Terminated.Message
					break
				}
			}

			if job.Status.Failed == 1 {
				err := fmt.Errorf("code generation job %s/%s failed: %s", job.Namespace, job.Name, terminationMessage)
				kdexv1alpha1.SetConditions(
					&hc.function.Status.Conditions,
					kdexv1alpha1.ConditionStatuses{
						Degraded:    metav1.ConditionTrue,
						Progressing: metav1.ConditionFalse,
						Ready:       metav1.ConditionFalse,
					},
					kdexv1alpha1.ConditionReasonReconcileError,
					err.Error(),
				)

				if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
					return ctrl.Result{}, err
				}

				return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
			}

			type results struct {
				Repository string `json:"repository"`
				Revision   string `json:"revision"`
				Path       string `json:"path"`
			}
			var res results
			if err := json.Unmarshal([]byte(terminationMessage), &res); err != nil {
				kdexv1alpha1.SetConditions(
					&hc.function.Status.Conditions,
					kdexv1alpha1.ConditionStatuses{
						Degraded:    metav1.ConditionTrue,
						Progressing: metav1.ConditionFalse,
						Ready:       metav1.ConditionFalse,
					},
					kdexv1alpha1.ConditionReasonReconcileError,
					err.Error(),
				)

				if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
					return ctrl.Result{}, err
				}

				return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
			}

			hc.function.Status.Source = &kdexv1alpha1.Source{
				Repository: res.Repository,
				Revision:   res.Revision,
				Path:       res.Path,
			}

			defaultBuilderName, defaultLanguage, err := parseBuilderGenerator(hc.faasAdaptorSpec.DefaultBuilderGenerator)
			if err != nil {
				kdexv1alpha1.SetConditions(
					&hc.function.Status.Conditions,
					kdexv1alpha1.ConditionStatuses{
						Degraded:    metav1.ConditionTrue,
						Progressing: metav1.ConditionFalse,
						Ready:       metav1.ConditionFalse,
					},
					kdexv1alpha1.ConditionReasonReconcileError,
					err.Error(),
				)
				if delErr := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); delErr != nil {
					return ctrl.Result{}, delErr
				}
				return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
			}
			sourceLanguage := generator.Config.Language
			builderName := ""
			if sourceLanguage == defaultLanguage {
				builderName = defaultBuilderName
			} else {
				for _, b := range hc.faasAdaptorSpec.Builders {
					if slices.Contains(b.Languages, sourceLanguage) {
						builderName = b.Name
					}
				}
			}

			for _, builder := range hc.faasAdaptorSpec.Builders {
				if builder.Name == builderName {
					hc.function.Status.Source.Builder = &builder
				}
			}
		}
	}

	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
	hc.function.Status.Detail = fmt.Sprintf("%v: %s@%s", kdexv1alpha1.KDexFunctionStateSourceAvailable, hc.function.Status.Source.Repository, hc.function.Status.Source.Revision)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
}

func (r *KDexFunctionReconciler) handleSourceAvailable(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	if hc.function.Spec.Origin.Executable != nil {
		hc.function.Status.Executable = hc.function.Spec.Origin.Executable
	} else {
		source := hc.function.Status.Source
		if hc.function.Spec.Origin.Source != nil {
			source = hc.function.Spec.Origin.Source
		}

		if source == nil {
			err := fmt.Errorf(
				"spec.origin.source and status.source are nil for %s/%s",
				hc.function.Namespace,
				hc.function.Name,
			)
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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

		builder := build.Builder{
			Client:         r.Client,
			ImageRegistry:  hc.host.Spec.Registries.ImageRegistry,
			Scheme:         r.Scheme,
			ServiceAccount: hc.serviceAccount,
			Source:         *source,
		}

		op, imgUnstruct, err := builder.GetOrCreateKPackImage(hc.ctx, hc.function)
		if err != nil {
			if strings.Contains(err.Error(), "Immutable field changed") {
				log.V(2).Info("Immutable field changed, deleting image builder", "image builder", imgUnstruct)

				if err := r.Delete(hc.ctx, imgUnstruct); err != nil {
					return ctrl.Result{}, err
				}

				return ctrl.Result{RequeueAfter: time.Second}, nil
			}

			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
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
			"GetOrCreateKPackImage",
			"op", op,
			"generation", hc.function.GetGeneration(),
			"source", hc.function.Status.Source,
			"KPackImage", imgUnstruct,
		)

		success := false
		if imgUnstruct != nil && imgUnstruct.Object != nil {
			status, ok := imgUnstruct.Object["status"].(map[string]any)
			if ok {
				observedGeneration, found, _ := unstructured.NestedInt64(imgUnstruct.Object, "status", "observedGeneration")
				if found && observedGeneration >= imgUnstruct.GetGeneration() {
					conditions, ok := status["conditions"].([]any)
					if ok {
						for _, cond := range conditions {
							if cond.(map[string]any)["type"] == "Ready" && cond.(map[string]any)["status"] == "True" {
								success = true
							} else if cond.(map[string]any)["type"] == "Failed" && cond.(map[string]any)["status"] == "True" {
								err := fmt.Errorf("image builder job %s/%s failed: %s", imgUnstruct.GetNamespace(), imgUnstruct.GetName(), cond.(map[string]any)["message"])
								kdexv1alpha1.SetConditions(
									&hc.function.Status.Conditions,
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
						}
					}
				}
			}
		}

		if !success {
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionFalse,
					Progressing: metav1.ConditionTrue,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconciling,
				fmt.Sprintf("Waiting on image builder job %s/%s to complete", imgUnstruct.GetNamespace(), imgUnstruct.GetName()),
			)

			log.V(2).Info(fmt.Sprintf("Waiting on image builder job %s/%s to complete", imgUnstruct.GetNamespace(), imgUnstruct.GetName()))

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		} else {
			status, _ := imgUnstruct.Object["status"].(map[string]any)

			hc.function.Status.Executable = &kdexv1alpha1.Executable{
				Image: status["latestImage"].(string),
			}
			tags := []string{}
			tag, ok, _ := unstructured.NestedString(imgUnstruct.Object, "spec", "tag")
			if ok {
				tags = append(tags, tag)
			}
			additionalTags, ok, _ := unstructured.NestedSlice(imgUnstruct.Object, "spec", "additionalTags")
			if ok {
				for _, t := range additionalTags {
					tags = append(tags, t.(string))
				}
			}
			hc.function.Status.Attributes["image.tags"] = strings.Join(tags, ",")
		}
	}

	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateExecutableAvailable
	hc.function.Status.Detail = fmt.Sprintf("%v: %s", kdexv1alpha1.KDexFunctionStateExecutableAvailable, hc.function.Status.Executable.Image)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{}, nil
}

func (r *KDexFunctionReconciler) handleExecutableAvailable(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	deployer := deploy.Deployer{
		Client:      r.Client,
		FaaSAdaptor: hc.faasAdaptorSpec,
		Host:        hc.host,
		ImagePullSecrets: utils.MapSlice(hc.imagePullSecrets, func(s corev1.Secret) corev1.LocalObjectReference {
			return corev1.LocalObjectReference{
				Name: s.Name,
			}
		}),
		Scheme:         r.Scheme,
		ServiceAccount: hc.serviceAccount,
	}

	job, err := deployer.Deploy(hc.ctx, hc.function)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&hc.function.Status.Conditions,
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
		kdexv1alpha1.SetConditions(
			&hc.function.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionFalse,
				Progressing: metav1.ConditionTrue,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconciling,
			fmt.Sprintf("Waiting on function deployer job %s/%s to complete", job.Namespace, job.Name),
		)

		log.V(2).Info(fmt.Sprintf("Waiting on function deployer job %s/%s to complete", job.Namespace, job.Name))

		if err := r.cleanupJobs(hc.ctx, hc.function, "deployer"); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	} else {
		pod, err := kjob.GetPodForJob(hc.ctx, r.Client, job)
		if err != nil {
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		var terminationMessage string
		for _, containerStatus := range pod.Status.ContainerStatuses {
			if containerStatus.Name == "deployer" && containerStatus.State.Terminated != nil {
				terminationMessage = containerStatus.State.Terminated.Message
				break
			}
		}

		if job.Status.Failed == 1 {
			err := fmt.Errorf("function deployment job %s/%s failed: %s", job.Namespace, job.Name, terminationMessage)
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		type results struct {
			URL string `json:"url"`
		}
		var res results
		if err := json.Unmarshal([]byte(terminationMessage), &res); err != nil {
			kdexv1alpha1.SetConditions(
				&hc.function.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			if err := r.Delete(hc.ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil {
				return ctrl.Result{}, err
			}

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		hc.function.Status.URL = res.URL
	}

	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateFunctionDeployed
	hc.function.Status.Detail = fmt.Sprintf("%v: %s", kdexv1alpha1.KDexFunctionStateFunctionDeployed, hc.function.Status.URL)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{}, nil
}

func (r *KDexFunctionReconciler) handleFunctionDeployed(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	deployer := deploy.Deployer{
		Client:      r.Client,
		FaaSAdaptor: hc.faasAdaptorSpec,
		Host:        hc.host,
		ImagePullSecrets: utils.MapSlice(hc.imagePullSecrets, func(s corev1.Secret) corev1.LocalObjectReference {
			return corev1.LocalObjectReference{
				Name: s.Name,
			}
		}),
		ServiceAccount: hc.serviceAccount,
		Scheme:         r.Scheme,
	}

	_, err := deployer.Observe(hc.ctx, hc.function)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&hc.function.Status.Conditions,
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

	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateReady
	hc.function.Status.Detail = fmt.Sprintf("%v: %s%s", kdexv1alpha1.KDexFunctionStateReady, hc.function.Status.URL, hc.function.Spec.API.BasePath)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		hc.function.Status.Detail,
	)

	log.V(2).Info(hc.function.Status.Detail)

	return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
}

func (r *KDexFunctionReconciler) handleReady(hc handlerContext) (ctrl.Result, error) {
	log := logf.FromContext(hc.ctx)

	if hc.function.Status.Executable == nil {
		log.V(2).Info("Executable is nil, re-reconciling")
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	deployer := deploy.Deployer{
		Client:      r.Client,
		FaaSAdaptor: hc.faasAdaptorSpec,
		Host:        hc.host,
		ImagePullSecrets: utils.MapSlice(hc.imagePullSecrets, func(s corev1.Secret) corev1.LocalObjectReference {
			return corev1.LocalObjectReference{
				Name: s.Name,
			}
		}),
		ServiceAccount: hc.serviceAccount,
		Scheme:         r.Scheme,
	}

	_, err := deployer.Observe(hc.ctx, hc.function)
	if err != nil {
		kdexv1alpha1.SetConditions(
			&hc.function.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse, // Keep ready state ?
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)
		return ctrl.Result{}, err
	}

	// Stay In Ready State
	hc.function.Status.State = kdexv1alpha1.KDexFunctionStateReady
	hc.function.Status.Detail = fmt.Sprintf("%v: %s%s", kdexv1alpha1.KDexFunctionStateReady, hc.function.Status.URL, hc.function.Spec.API.BasePath)

	kdexv1alpha1.SetConditions(
		&hc.function.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Function is ready",
	)

	log.V(2).Info("Function is ready")

	return ctrl.Result{}, nil
}

func (r *KDexFunctionReconciler) cleanupJobs(ctx context.Context, function *kdexv1alpha1.KDexFunction, appLabel string) error {
	log := logf.FromContext(ctx)
	var jobList batchv1.JobList
	if err := r.List(ctx, &jobList, client.InNamespace(function.Namespace), client.MatchingLabels{
		"app":      appLabel,
		"function": function.Name,
	}); err != nil {
		return err
	}

	currentGen := fmt.Sprintf("%d", function.Generation)
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

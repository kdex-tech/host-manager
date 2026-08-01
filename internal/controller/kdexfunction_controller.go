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
	"crypto/sha256"
	"encoding/hex"
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
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlbuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// BackendServiceIndexKey indexes KDexFunctions by the namespaced name of the
// Service referenced in spec.backend.service. Used by Service/EndpointSlice
// watches to enqueue dependent functions when a backend Service or its
// EndpointSlices change.
const BackendServiceIndexKey = "spec.backend.service.namespacedName"

func backendServiceIndexer(o client.Object) []string {
	fn, ok := o.(*kdexv1alpha1.KDexFunction)
	if !ok || fn.Spec.Backend == nil || fn.Spec.Backend.Service == nil {
		return nil
	}
	ns := fn.Spec.Backend.Service.Namespace
	if ns == "" {
		ns = fn.Namespace
	}
	return []string{ns + "/" + fn.Spec.Backend.Service.Name}
}

// KDexFunctionReconciler reconciles a KDexFunction object
type KDexFunctionReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	// FunctionImagePrefix overrides the function-image path segment before
	// <func>. nil = unset (default to HostRef.Name+"/"); non-nil = literal
	// (may be "" for a flat path). From FUNCTION_IMAGE_PREFIX env in main.go.
	FunctionImagePrefix *string
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

	// Dispatch by backend type. Service-backed functions bypass the FaaS
	// build/deploy pipeline and resolve directly to an existing Service URL.
	if function.Spec.Backend != nil {
		return r.reconcileServiceBacked(ctx, &function)
	}
	// Origin path (existing build/deploy state machine) continues below.

	// Snapshot the observed status so the deferred write can be made
	// conditional on an actual change. (Service-backed functions return before
	// this defer and guard their own write; this covers the origin-path
	// build/deploy state machine, which pulses a transient "Reconciling"
	// condition every pass.)
	observedStatus := function.Status.DeepCopy()

	// Defer status update
	defer func() {
		function.Status.ObservedGeneration = function.Generation

		// Only write status when it actually changed. The origin path pulses a
		// transient "Reconciling" condition every pass, bumping
		// LastTransitionTime even when the net settled status is unchanged. An
		// unconditional Status().Update() would then bump resourceVersion every
		// reconcile, re-firing the controller's own For() watch and self-looping
		// (pegs a CPU core). functionStatusEqual ignores LastTransitionTime but
		// compares every meaningful field (State/URL/conditions/etc.). See
		// kdex-tech/host-manager#131 (#126 residual).
		if !functionStatusEqual(observedStatus, &function.Status) {
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
				// nil-guard Status.Executable: the same #77 scenario
				// (older binary landed state=Ready without populating
				// Status.Executable) would nil-deref Image here and
				// crash the controller before handleReady's self-heal
				// runs. Skip the drift check when nil — let handleReady
				// re-derive on the next loop.
				if function.Status.State == kdexv1alpha1.KDexFunctionStateReady &&
					function.Status.Executable != nil &&
					function.Status.Executable.Image != latestImage {
					log.Info("New image detected from KPack, re-reconciling from source available", "latestImage", latestImage)
					function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
				}
			}
		} else if !kerrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
			return ctrl.Result{}, err
		}
	}

	// Edge-trigger re-codegen on a Ready function when spec.api (or the
	// resolved generator image) drifted from what the last codegen run
	// recorded. Without this regression, handleReady never compares
	// inputs — only handleBuildValid does — and a spec.api edit on an
	// already-Ready function silently keeps serving the old image.
	// Mirrors the kpack-SHA regression above. See kdex-tech/host-manager#41.
	if function.Status.State == kdexv1alpha1.KDexFunctionStateReady &&
		function.Spec.Origin.Source != nil &&
		!shouldSkipCodegen(&function) {
		log.Info("Codegen inputs changed on Ready function, re-reconciling from build valid")
		function.Status.State = kdexv1alpha1.KDexFunctionStateBuildValid
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

func (r *KDexFunctionReconciler) reconcileServiceBacked(ctx context.Context, fn *kdexv1alpha1.KDexFunction) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	svcRef := fn.Spec.Backend.Service
	if svcRef == nil {
		// CEL prevents this, but defend.
		return ctrl.Result{}, nil
	}
	ns := svcRef.Namespace
	if ns == "" {
		ns = fn.Namespace
	}

	// 1. Resolve the Service.
	svc := &corev1.Service{}
	if err := r.Get(ctx, client.ObjectKey{Name: svcRef.Name, Namespace: ns}, svc); err != nil {
		if kerrors.IsNotFound(err) {
			// ServiceNotFound is a hard failure: clear Status.URL so the
			// host-handler tears down the route on the next refresh.
			return r.markBackendUnready(ctx, fn, "ServiceNotFound", fmt.Sprintf("Service %s/%s not found", ns, svcRef.Name), false)
		}
		return ctrl.Result{}, err
	}

	// 2. Resolve port (numeric pass-through or named-port lookup).
	port, ok := resolveServicePort(svc, svcRef.Port)
	if !ok {
		return r.markBackendUnready(ctx, fn, "InvalidPort", fmt.Sprintf("port %s not found in Service %s/%s", svcRef.Port.String(), ns, svcRef.Name), false)
	}

	// 3. Check endpoints.
	hasReady, err := r.hasReadyEndpoint(ctx, ns, svcRef.Name)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !hasReady {
		return r.markBackendUnready(ctx, fn, "NoEndpoints", fmt.Sprintf("Service %s/%s has no ready endpoints", ns, svcRef.Name), true)
	}

	// 4. Build URL and mark Ready.
	scheme := svcRef.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := svcRef.Path
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("%s://%s.%s.svc.cluster.local:%d%s", scheme, svcRef.Name, ns, port, path)

	// Snapshot status before mutation so the write below is conditional on an
	// actual diff. A service-backed function's happy path is byte-stable once
	// resolved, but an unconditional Status().Update() bumps resourceVersion
	// on every reconcile, which re-fires the controller's own For() watch and
	// self-amplifies a single upstream ping into 5-20 reconciles. See
	// kdex-tech/host-manager#102.
	oldStatus := fn.Status.DeepCopy()

	// Clear stale build-pathway status fields when switching from origin -> backend.
	fn.Status.Executable = nil
	fn.Status.Generator = nil
	fn.Status.Source = nil

	fn.Status.URL = url
	fn.Status.State = kdexv1alpha1.KDexFunctionStateReady
	fn.Status.ObservedGeneration = fn.Generation
	meta.SetStatusCondition(&fn.Status.Conditions, metav1.Condition{
		Type:    string(kdexv1alpha1.ConditionTypeReady),
		Status:  metav1.ConditionTrue,
		Reason:  "BackendResolved",
		Message: fmt.Sprintf("Backend Service %s/%s resolved to %s", ns, svcRef.Name, url),
	})
	meta.RemoveStatusCondition(&fn.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	if !equality.Semantic.DeepEqual(*oldStatus, fn.Status) {
		if err := r.Status().Update(ctx, fn); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("Service-backed function ready", "function", fn.Name, "url", url)
	}
	return ctrl.Result{}, nil
}

func resolveServicePort(svc *corev1.Service, ref intstr.IntOrString) (int32, bool) {
	if ref.Type == intstr.Int {
		return int32(ref.IntValue()), true
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == ref.StrVal {
			return p.Port, true
		}
	}
	return 0, false
}

func (r *KDexFunctionReconciler) hasReadyEndpoint(ctx context.Context, ns, svcName string) (bool, error) {
	var sliceList discoveryv1.EndpointSliceList
	if err := r.List(ctx, &sliceList,
		client.InNamespace(ns),
		client.MatchingLabels{discoveryv1.LabelServiceName: svcName},
	); err != nil {
		return false, err
	}
	for _, s := range sliceList.Items {
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				return true, nil
			}
		}
	}
	return false, nil
}

// markBackendUnready sets Ready=False with the given reason. If retainURL is
// true, Status.URL is left as-is so the proxy keeps the route mounted
// (transient drops yield 503s instead of 404s). If false, Status.URL is
// cleared and State degrades back to OpenAPIValid.
func (r *KDexFunctionReconciler) markBackendUnready(ctx context.Context, fn *kdexv1alpha1.KDexFunction, reason, msg string, retainURL bool) (ctrl.Result, error) {
	// Snapshot before mutation; only write on a real diff so repeated unready
	// polls don't churn resourceVersion and re-fan-out the watch. See
	// kdex-tech/host-manager#102.
	oldStatus := fn.Status.DeepCopy()
	meta.SetStatusCondition(&fn.Status.Conditions, metav1.Condition{
		Type:    string(kdexv1alpha1.ConditionTypeReady),
		Status:  metav1.ConditionFalse,
		Reason:  reason,
		Message: msg,
	})
	if retainURL {
		meta.SetStatusCondition(&fn.Status.Conditions, metav1.Condition{
			Type:    string(kdexv1alpha1.ConditionTypeProgressing),
			Status:  metav1.ConditionTrue,
			Reason:  reason,
			Message: msg,
		})
	} else {
		fn.Status.URL = ""
		fn.Status.State = kdexv1alpha1.KDexFunctionStateOpenAPIValid
		meta.SetStatusCondition(&fn.Status.Conditions, metav1.Condition{
			Type:    string(kdexv1alpha1.ConditionTypeDegraded),
			Status:  metav1.ConditionTrue,
			Reason:  reason,
			Message: msg,
		})
	}
	fn.Status.ObservedGeneration = fn.Generation
	if !equality.Semantic.DeepEqual(*oldStatus, fn.Status) {
		if err := r.Status().Update(ctx, fn); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
}

// SetupWithManager sets up the controller with the Manager.
// functionStatusEqual reports whether two KDexFunctionStatus values are equal
// ignoring per-condition LastTransitionTime. KDexFunctionStatus embeds
// KDexObjectStatus but adds function-specific fields (State, URL, Executable,
// Generator, Source, Detail, ...), so the plain objectStatusEqual helper cannot
// be used — this compares the whole function status. The origin path pulses a
// transient "Reconciling" condition every pass, bumping LastTransitionTime; this
// guard prevents that timestamp churn from triggering a status write while still
// detecting any real change. See kdex-tech/host-manager#131.
func functionStatusEqual(a, b *kdexv1alpha1.KDexFunctionStatus) bool {
	ac := a.DeepCopy()
	bc := b.DeepCopy()
	for i := range ac.Conditions {
		ac.Conditions[i].LastTransitionTime = metav1.Time{}
	}
	for i := range bc.Conditions {
		bc.Conditions[i].LastTransitionTime = metav1.Time{}
	}
	return equality.Semantic.DeepEqual(ac, bc)
}

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

	// Index KDexFunctions by their backend Service ref so Service /
	// EndpointSlice watches can map an event back to dependent functions
	// in O(1). Indexer returns nil for non-Backend functions, so Origin
	// functions don't show up in any lookup and don't get spurious
	// enqueues.
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&kdexv1alpha1.KDexFunction{},
		BackendServiceIndexKey,
		backendServiceIndexer,
	); err != nil {
		return err
	}

	mapServiceToFunctions := func(ctx context.Context, obj client.Object) []reconcile.Request {
		key := obj.GetNamespace() + "/" + obj.GetName()
		var list kdexv1alpha1.KDexFunctionList
		if err := r.List(ctx, &list, client.MatchingFields{BackendServiceIndexKey: key}); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, fn := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: fn.Name, Namespace: fn.Namespace}})
		}
		return reqs
	}

	mapEndpointSliceToFunctions := func(ctx context.Context, obj client.Object) []reconcile.Request {
		es, ok := obj.(*discoveryv1.EndpointSlice)
		if !ok {
			return nil
		}
		svcName, ok := es.Labels[discoveryv1.LabelServiceName]
		if !ok {
			return nil
		}
		key := es.Namespace + "/" + svcName
		var list kdexv1alpha1.KDexFunctionList
		if err := r.List(ctx, &list, client.MatchingFields{BackendServiceIndexKey: key}); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, fn := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKey{Name: fn.Name, Namespace: fn.Namespace}})
		}
		return reqs
	}

	// An edit to a FaaSAdaptor changes the desired observer CronJob (image,
	// schedule, tolerations, nodeSelector, env) for every function resolving
	// to it, but nothing was watching the adaptor -- so an adaptor edit
	// enqueued no reconciles and existing functions kept stale observers until
	// some unrelated event happened to touch them. See
	// kdex-tech/host-manager#143.
	mapFaaSAdaptorToFunctions := func(ctx context.Context, obj client.Object) []reconcile.Request {
		hosts := &kdexv1alpha1.KDexInternalHostList{}
		if err := r.List(ctx, hosts); err != nil {
			return nil
		}

		// Whether this adaptor is the one an unreferenced host falls back to.
		// Mirrors ResolveOrDefaultFaaSAdaptor: the oldest cluster adaptor
		// labelled kdex.dev/default=true.
		isDefault := false
		if _, ok := obj.(*kdexv1alpha1.KDexClusterFaaSAdaptor); ok {
			defaults := &kdexv1alpha1.KDexClusterFaaSAdaptorList{}
			if err := r.List(ctx, defaults, client.MatchingLabels{"kdex.dev/default": "true"}); err == nil &&
				len(defaults.Items) != 0 {
				slices.SortFunc(defaults.Items, func(a, b kdexv1alpha1.KDexClusterFaaSAdaptor) int {
					return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
				})
				isDefault = defaults.Items[0].Name == obj.GetName()
			}
		}

		adaptorKind := obj.GetObjectKind().GroupVersionKind().Kind
		if adaptorKind == "" {
			// Typed objects off the cache often carry an empty GVK.
			switch obj.(type) {
			case *kdexv1alpha1.KDexClusterFaaSAdaptor:
				adaptorKind = "KDexClusterFaaSAdaptor"
			case *kdexv1alpha1.KDexFaaSAdaptor:
				adaptorKind = "KDexFaaSAdaptor"
			}
		}

		matchedHosts := map[string]bool{}
		for _, h := range hosts.Items {
			ref := h.Spec.FaaSAdaptorRef
			if ref == nil {
				// No explicit ref -- this host uses the cluster default.
				if isDefault {
					matchedHosts[h.Namespace+"/"+h.Name] = true
				}
				continue
			}
			if ref.Kind != adaptorKind || ref.Name != obj.GetName() {
				continue
			}
			// Cluster-scoped adaptors have no namespace to disambiguate.
			if !strings.Contains(adaptorKind, "Cluster") {
				ns := ref.Namespace
				if ns == "" {
					ns = h.Namespace
				}
				if ns != obj.GetNamespace() {
					continue
				}
			}
			matchedHosts[h.Namespace+"/"+h.Name] = true
		}

		if len(matchedHosts) == 0 {
			return nil
		}

		functions := &kdexv1alpha1.KDexFunctionList{}
		if err := r.List(ctx, functions); err != nil {
			return nil
		}

		reqs := make([]reconcile.Request, 0, len(functions.Items))
		for _, fn := range functions.Items {
			// HostRef is a LocalObjectReference -- the host always lives in
			// the function's own namespace.
			if matchedHosts[fn.Namespace+"/"+fn.Spec.HostRef.Name] {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: client.ObjectKey{Name: fn.Name, Namespace: fn.Namespace},
				})
			}
		}
		return reqs
	}

	builder = builder.
		Watches(
			&kdexv1alpha1.KDexClusterFaaSAdaptor{},
			handler.EnqueueRequestsFromMapFunc(mapFaaSAdaptorToFunctions),
			// Adaptor status writes must not fan out to every function on
			// every pass; only spec changes alter the desired observer.
			ctrlbuilder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&kdexv1alpha1.KDexFaaSAdaptor{},
			handler.EnqueueRequestsFromMapFunc(mapFaaSAdaptorToFunctions),
			ctrlbuilder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(
			&kdexv1alpha1.KDexInternalHost{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexFunction{}, &kdexv1alpha1.KDexFunctionList{}, "{.Spec.HostRef}"),
			// KDexFunction resolution only consults the InternalHost spec
			// (HostRef, security). The InternalHost status subresource is
			// rewritten on every upstream reconcile (~every 5 min); without
			// this predicate each status-only bump fans out to every function
			// on the host. Generation only moves on spec changes, so this
			// drops the status-write fan-out entirely. See
			// kdex-tech/host-manager#102.
			ctrlbuilder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(mapServiceToFunctions)).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(mapEndpointSliceToFunctions)).
		WithOptions(controller.TypedOptions[reconcile.Request]{
			LogConstructor: LogConstructor("kdexfunction", mgr),
		}).
		Named("kdexfunction")

	return builder.Complete(r)
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

// resolveDefaultBuilder looks up the FaaSAdaptor's DefaultBuilderGenerator
// in the spec.Builders list and returns a Builder pointer suitable for
// constructing a kpack Image. Used by handleSourceAvailable when the
// source carries no inline Builder (the generator-mode happy path:
// codegen Jobs populate function.Status.Source.{Repository,Revision,Path}
// but not Builder). Returns an error if the default's name + language
// doesn't match any Builder in faas.Builders, so the caller can fail
// cleanly instead of nil-dereffing in build.GetOrCreateKPackImage.
func resolveDefaultBuilder(faas *kdexv1alpha1.KDexFaaSAdaptorSpec) (*kdexv1alpha1.Builder, error) {
	name, language, err := parseBuilderGenerator(faas.DefaultBuilderGenerator)
	if err != nil {
		return nil, err
	}
	for i := range faas.Builders {
		b := &faas.Builders[i]
		if b.Name == name && slices.Contains(b.Languages, language) {
			return b, nil
		}
	}
	return nil, fmt.Errorf("no Builder named %q supporting language %q found in FaaSAdaptor.spec.builders (defaultBuilderGenerator=%q)", name, language, faas.DefaultBuilderGenerator)
}

// sourceRegenerate returns true when the function's origin.source asks
// to re-run codegen on every reconcile. Default false: source is
// treated as authoritative and codegen is skipped.
func sourceRegenerate(s *kdexv1alpha1.Source) bool {
	return s != nil && s.Regenerate != nil && *s.Regenerate
}

// Attribute keys recorded on KDexFunction.Status.Attributes after a
// successful codegen run. handleBuildValid edge-triggers re-codegen
// when the live values differ from these recorded ones — letting users
// edit spec.api without manually flipping spec.origin.source.regenerate.
// See kdex-tech/host-manager#40.
const (
	AttrCodegenInputAPIHash   = "kdex.dev/codegen-input-api-hash"
	AttrCodegenInputGenerator = "kdex.dev/codegen-input-generator"
)

// codegenInputAPIHash returns a stable SHA-256 (hex) over the function's
// spec.api, used as the edge-trigger signal for re-running codegen. The
// json.Marshal of API produces canonical map-key ordering so semantically
// identical specs hash identically across reconciles.
func codegenInputAPIHash(api kdexv1alpha1.API) string {
	b, err := json.Marshal(api)
	if err != nil {
		// json.Marshal of a value-type struct cannot fail in practice;
		// return empty so the caller treats "no recorded hash" semantics
		// uniformly rather than spuriously triggering on a phantom mismatch.
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// codegenInputsChanged reports edge-trigger state for handleBuildValid.
// edgeMode is true once a prior codegen has recorded inputs (the function
// is codegen-managed). changed is true when the current spec.api hash or
// resolved generator image differs from the recorded one. Callers combine
// with sourceRegenerate / Spec.Origin.Source nil-ness to decide whether
// to enter the codegen branch.
func codegenInputsChanged(fn *kdexv1alpha1.KDexFunction) (edgeMode, changed bool) {
	currentAPIHash := codegenInputAPIHash(fn.Spec.API)
	currentGenerator := ""
	if fn.Status.Generator != nil {
		currentGenerator = fn.Status.Generator.Image
	}
	observedAPIHash := fn.Status.Attributes[AttrCodegenInputAPIHash]
	observedGenerator := fn.Status.Attributes[AttrCodegenInputGenerator]
	edgeMode = observedAPIHash != ""
	changed = currentAPIHash != observedAPIHash || currentGenerator != observedGenerator
	return
}

// shouldSkipCodegen reports whether handleBuildValid can take the
// "copy spec to status" fast path instead of running a codegen Job.
// Skip when: user supplied spec.origin.source AND didn't request
// force-regen AND (we've never recorded inputs OR recorded inputs
// match current). See kdex-tech/host-manager#40.
func shouldSkipCodegen(fn *kdexv1alpha1.KDexFunction) bool {
	if fn.Spec.Origin.Source == nil {
		return false
	}
	if sourceRegenerate(fn.Spec.Origin.Source) {
		return false
	}
	edgeMode, inputsChanged := codegenInputsChanged(fn)
	return !edgeMode || !inputsChanged
}

// isCodegenJobTerminal reports whether the Kubernetes Job has reached a
// terminal Failed state — i.e. BackoffLimit was exhausted (or any other
// condition that flipped JobFailed=True). When this returns true, the
// controller must NOT delete-and-recreate the Job (that's the retry-storm
// bug in kdex-tech/host-manager#27); instead it should mark the function
// Degraded and stop, so the operator can inspect the failed pods. The
// returned message carries the JobCondition's Reason+Message for the
// function's Degraded condition.
func isCodegenJobTerminal(job *batchv1.Job) (bool, string) {
	for _, c := range job.Status.Conditions {
		if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue {
			return true, fmt.Sprintf("%s: %s", c.Reason, c.Message)
		}
	}
	return false, ""
}

// markCodegenJobTerminallyFailed sets the function's conditions to indicate
// a permanent codegen-Job failure and returns a no-requeue ctrl.Result.
// Centralised so both handleBuildValid and handleExecutableAvailable use
// the same shape — and so the cyclomatic complexity of those handlers
// doesn't accumulate the SetConditions block twice. See
// kdex-tech/host-manager#27.
func markCodegenJobTerminallyFailed(fn *kdexv1alpha1.KDexFunction, job *batchv1.Job, msg string) (ctrl.Result, error) {
	err := fmt.Errorf("code generation job %s/%s exhausted retries: %s — inspect pods for details (Job is NOT auto-deleted)", job.Namespace, job.Name, msg)
	kdexv1alpha1.SetConditions(
		&fn.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconcileError,
		err.Error(),
	)
	return ctrl.Result{}, nil
}

// recordCodegenInputs persists the inputs a just-completed codegen Job
// ran against, so subsequent reconciles can edge-trigger on input
// changes without needing regenerate=true. See kdex-tech/host-manager#40.
func recordCodegenInputs(fn *kdexv1alpha1.KDexFunction) {
	if fn.Status.Attributes == nil {
		fn.Status.Attributes = map[string]string{}
	}
	fn.Status.Attributes[AttrCodegenInputAPIHash] = codegenInputAPIHash(fn.Spec.API)
	if fn.Status.Generator != nil {
		fn.Status.Attributes[AttrCodegenInputGenerator] = fn.Status.Generator.Image
	}
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
		// Populate Status.Executable at the same point we transition
		// state, so the invariant "state=ExecutableAvailable ⇒
		// status.executable != nil" holds for downstream handlers.
		// Deploy() depends on this in handleExecutableAvailable.
		hc.function.Status.Executable = hc.function.Spec.Origin.Executable
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateExecutableAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	} else if hc.function.Spec.Origin.Source != nil && !sourceRegenerate(hc.function.Spec.Origin.Source) {
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateSourceAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	// When source.regenerate=true, fall through to generator resolution
	// + BuildValid so the codegen Job runs. The Job ends with
	// patch_source_status writing the result into function.Status.Source.

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
		// Pair Status.Executable with the state transition — see
		// handleOpenAPIValid for the rationale.
		hc.function.Status.Executable = hc.function.Spec.Origin.Executable
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateExecutableAvailable
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	// Edge-trigger codegen on spec.api / generator changes so users don't
	// have to manually pulse spec.origin.source.regenerate. See
	// kdex-tech/host-manager#40.
	if shouldSkipCodegen(hc.function) {
		// Don't clobber a codegen-resolved SHA in Status.Source. Once codegen
		// has populated Status.Source.Revision with a concrete SHA, that SHA
		// is the build pin (see handleSourceAvailable below) — overwriting
		// it back to spec's branch ref would re-arm kpack's branch-polling
		// loop. See kdex-tech/host-manager#38.
		if hc.function.Status.Source == nil || hc.function.Status.Source.Revision == "" {
			hc.function.Status.Source = hc.function.Spec.Origin.Source
		}
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
			Client:           r.Client,
			CodegenResources: r.Configuration.Codegen.Resources,
			Config:           *hc.function.Status.Generator,
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

			// Terminal-Failed Jobs are surfaced as Degraded with no requeue
			// and (critically) without deletion — the operator needs the
			// failed pods around to diagnose. Replaces the pre-#27
			// `job.Status.Failed == 1` short-circuit which delete-and-
			// recreated the Job on every reconcile, masking the failure as
			// "still building" indefinitely. See kdex-tech/host-manager#27.
			if terminal, msg := isCodegenJobTerminal(job); terminal {
				if terminationMessage != "" {
					msg = msg + "; results: " + terminationMessage
				}
				return markCodegenJobTerminallyFailed(hc.function, job, msg)
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
			recordCodegenInputs(hc.function)

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
		// spec.origin.source carries intent (which branch to scaffold from,
		// which builder/SA/tolerations to use). status.source carries the
		// build pin — a concrete SHA captured by the codegen Job. When
		// status.source.revision is populated, pin the build to it so kpack
		// stops polling the branch HEAD and rebuilding on every unrelated
		// monorepo push. See kdex-tech/host-manager#38.
		var sourceCopy kdexv1alpha1.Source
		hasSpec := hc.function.Spec.Origin.Source != nil
		if hasSpec {
			sourceCopy = *hc.function.Spec.Origin.Source
		}
		if hc.function.Status.Source != nil && hc.function.Status.Source.Revision != "" {
			sourceCopy.Repository = hc.function.Status.Source.Repository
			sourceCopy.Revision = hc.function.Status.Source.Revision
			sourceCopy.Path = hc.function.Status.Source.Path
		}
		var source *kdexv1alpha1.Source
		if hasSpec || (hc.function.Status.Source != nil && hc.function.Status.Source.Revision != "") {
			source = &sourceCopy
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

		// If the source carries no inline Builder, resolve it from the
		// FaaSAdaptor's defaultBuilderGenerator. This is the
		// generator-mode happy path: codegen Jobs set
		// function.Status.Source.{Repository,Revision,Path} but not
		// Builder, and the kpack-Image construction below derefs the
		// Builder fields unconditionally. Resolving up front lets the
		// caller see a clean degraded condition instead of a panic
		// from build.GetOrCreateKPackImage.
		sourceForBuild := *source
		if sourceForBuild.Builder == nil {
			resolved, err := resolveDefaultBuilder(&hc.faasAdaptorSpec)
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
			sourceForBuild.Builder = resolved
		}

		// The build pod's ServiceAccount governs git-source clone and
		// registry push credentials (via the SA's .secrets[] and
		// imagePullSecrets[], or Workload Identity annotations). Honor
		// spec.origin.source.builder.serviceAccountName when set; fall
		// back to host-manager's own SA so prior behavior is preserved
		// for CRs that don't specify a build SA.
		buildSA := hc.serviceAccount
		if sourceForBuild.Builder.ServiceAccountName != "" {
			buildSA = sourceForBuild.Builder.ServiceAccountName
		}

		imagePrefix := hc.function.Spec.HostRef.Name + "/"
		if r.FunctionImagePrefix != nil {
			imagePrefix = *r.FunctionImagePrefix
		}

		builder := build.Builder{
			Client:         r.Client,
			ImageRegistry:  hc.host.Spec.Registries.ImageRegistry,
			ImagePrefix:    imagePrefix,
			Scheme:         r.Scheme,
			ServiceAccount: buildSA,
			Source:         sourceForBuild,
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

		success, failedErr := inspectKPackImageStatus(imgUnstruct)
		if failedErr != nil {
			err := fmt.Errorf("image builder job %s/%s failed: %s", imgUnstruct.GetNamespace(), imgUnstruct.GetName(), failedErr.Error())
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

	// Self-heal the state=ExecutableAvailable ⇒ Status.Executable != nil
	// invariant. Pre-fix the handler reached Deploy() with a nil
	// Executable and got stuck on "function … has no executable" forever
	// — the populate site (handleOpenAPIValid) never re-runs. Observed
	// on a 0.2.38 → 0.2.91 binary upgrade where the older version landed
	// the state without pairing the populate. Mirrors handleReady's
	// self-heal at line 1409. See kdex-tech/host-manager#77.
	if hc.function.Status.Executable == nil {
		if hc.function.Spec.Origin.Executable != nil {
			log.V(2).Info("Status.Executable is nil, re-deriving from Spec.Origin.Executable")
			hc.function.Status.Executable = hc.function.Spec.Origin.Executable
			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}
		log.V(2).Info("Status.Executable is nil and Spec has no executable, stepping back to OpenAPIValid")
		hc.function.Status.State = kdexv1alpha1.KDexFunctionStateOpenAPIValid
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	deployer := deploy.Deployer{
		Client:      r.Client,
		FaaSAdaptor: hc.faasAdaptorSpec,
		Host:        hc.host,
		// Resolved white-label API token prefix (per-host spec or Nexus
		// default), injected as PASETO_TOKEN_PREFIX. Same resolver the host's
		// TokenManager uses, so mint and verify agree.
		TokenPrefix: resolveAPITokenPrefix(hc.host.Spec.Auth, r.Configuration),
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

		// Terminal-Failed deployer Job: surface Degraded, no requeue, no
		// delete — same shape as the codegen-Job path in handleBuildValid.
		// See kdex-tech/host-manager#27.
		if terminal, msg := isCodegenJobTerminal(job); terminal {
			if terminationMessage != "" {
				msg = msg + "; results: " + terminationMessage
			}
			return markCodegenJobTerminallyFailed(hc.function, job, msg)
		}

		url, err := decodeDeployerURL(terminationMessage)
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

		hc.function.Status.URL = url
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
		// Resolved white-label API token prefix (per-host spec or Nexus
		// default), injected as PASETO_TOKEN_PREFIX. Same resolver the host's
		// TokenManager uses, so mint and verify agree.
		TokenPrefix: resolveAPITokenPrefix(hc.host.Spec.Auth, r.Configuration),
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
		// Resolved white-label API token prefix (per-host spec or Nexus
		// default), injected as PASETO_TOKEN_PREFIX. Same resolver the host's
		// TokenManager uses, so mint and verify agree.
		TokenPrefix: resolveAPITokenPrefix(hc.host.Spec.Auth, r.Configuration),
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

// decodeDeployerURL parses the deployer pod's termination message
// into the function URL. An empty URL — knative-deployer's
// Knative-Service-not-yet-admitted case, or any deployer bug
// producing success-with-empty-URL — is treated as a failure rather
// than silently accepted. Pre-#92 the empty URL was assigned to
// Status.URL, the state transitioned to FunctionDeployed → Ready=True,
// the host-handler mounted a route at an empty upstream, and end
// users got 502 Bad Gateway from a CR that looked healthy.
func decodeDeployerURL(terminationMessage string) (string, error) {
	var res struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(terminationMessage), &res); err != nil {
		return "", fmt.Errorf("failed to parse deployer results: %w", err)
	}
	if res.URL == "" {
		return "", fmt.Errorf("deployer returned empty URL; backend not admitted yet")
	}
	return res.URL, nil
}

// inspectKPackImageStatus reads the kpack Image's status.conditions
// and returns whether the build succeeded (success=true ⇔
// Ready=True observed for the CURRENT generation) and whether it
// failed (non-nil failedErr ⇔ Failed=True observed on ANY
// generation).
//
// The Failed signal is intentionally NOT gated on
// `observedGeneration == generation`. Pre-#94 the whole block was
// gated and a Failed=True on a prior generation was silently
// discarded — when kpack lagged reconciling its own Image (pod
// restart, stuck webhook), the function infinite-looped at
// Progressing=True / Degraded=False with no operator-visible signal.
// Ready stays gated because a stale Ready=True from before the
// operator's latest spec edit must not promote the function to
// success.
func inspectKPackImageStatus(imgUnstruct *unstructured.Unstructured) (success bool, failedErr error) {
	if imgUnstruct == nil || imgUnstruct.Object == nil {
		return false, nil
	}
	status, ok := imgUnstruct.Object["status"].(map[string]any)
	if !ok {
		return false, nil
	}
	conditions, ok := status["conditions"].([]any)
	if !ok {
		return false, nil
	}

	// Failed=True from ANY generation → terminal signal worth
	// surfacing.
	for _, cond := range conditions {
		c, ok := cond.(map[string]any)
		if !ok {
			continue
		}
		if c["type"] == "Failed" && c["status"] == "True" {
			msg, _ := c["message"].(string)
			if msg == "" {
				msg = "kpack reports Failed=True"
			}
			return false, fmt.Errorf("%s", msg)
		}
	}

	// Ready=True only when kpack has observed the current generation.
	observedGeneration, found, _ := unstructured.NestedInt64(imgUnstruct.Object, "status", "observedGeneration")
	if !found || observedGeneration < imgUnstruct.GetGeneration() {
		return false, nil
	}
	for _, cond := range conditions {
		c, ok := cond.(map[string]any)
		if !ok {
			continue
		}
		if c["type"] == "Ready" && c["status"] == "True" {
			return true, nil
		}
	}
	return false, nil
}

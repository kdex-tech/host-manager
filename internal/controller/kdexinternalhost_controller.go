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
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/keys"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	remoteauth "oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// KDexInternalHostReconciler reconciles a KDexInternalHost object
type KDexInternalHostReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	HostHandler         *host.HostHandler
	Port                int32
	RequeueDelay        time.Duration
	Scheme              *runtime.Scheme
	ServiceName         string

	mu                 sync.RWMutex
	memoizedDeployment *appsv1.DeploymentSpec
	memoizedHTTPRoute  *gatewayv1.HTTPRouteSpec
	memoizedIngress    *networkingv1.IngressSpec
	memoizedService    *corev1.ServiceSpec
}

// nolint:gocyclo
func (r *KDexInternalHostReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	if req.Namespace != r.ControllerNamespace {
		log.V(4).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	if req.Name != r.FocalHost {
		log.V(4).Info("skipping reconcile", "name", req.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	var internalHost kdexv1alpha1.KDexInternalHost
	if err := r.Get(ctx, req.NamespacedName, &internalHost); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if internalHost.Status.Attributes == nil {
		internalHost.Status.Attributes = make(map[string]string)
	}

	// Defer status update
	defer func() {
		internalHost.Status.ObservedGeneration = internalHost.Generation
		updateErr := r.Status().Update(ctx, &internalHost)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("status", "status", internalHost.Status, "err", err, "res", res)
	}()

	kdexv1alpha1.SetConditions(
		&internalHost.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionTrue,
			Ready:       metav1.ConditionUnknown,
		},
		kdexv1alpha1.ConditionReasonReconciling,
		"Reconciling",
	)

	backendRefs := []kdexv1alpha1.KDexObjectReference{}
	defaultBackendServerImage := r.Configuration.BackendDefault.ServerImage
	packageRefs := []kdexv1alpha1.PackageReference{}
	requiredBackends := []resolvedBackend{}
	scriptDefs := []kdexv1alpha1.ScriptDef{}
	seenPaths := map[string]bool{}
	themeAssets := []kdexv1alpha1.Asset{}

	secrets, err := ResolveSecrets(ctx, r.Client, &internalHost.Status, internalHost.Namespace, internalHost.Spec.SecretSelector)
	if err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}

	themeObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalHost, &internalHost.Status.Conditions, internalHost.Spec.ThemeRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if themeObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, themeObj)

		internalHost.Status.Attributes["theme.generation"] = fmt.Sprintf("%d", themeObj.GetGeneration())

		var themeSpec *kdexv1alpha1.KDexThemeSpec
		switch v := themeObj.(type) {
		case *kdexv1alpha1.KDexTheme:
			themeSpec = &v.Spec
		case *kdexv1alpha1.KDexClusterTheme:
			themeSpec = &v.Spec
		}

		themeAssets = themeSpec.Assets

		themeScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalHost, &internalHost.Status.Conditions, themeSpec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if themeScriptLibraryObj != nil {
			internalHost.Status.Attributes["theme.scriptLibrary.generation"] = fmt.Sprintf("%d", themeScriptLibraryObj.GetGeneration())

			var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

			switch v := themeScriptLibraryObj.(type) {
			case *kdexv1alpha1.KDexScriptLibrary:
				scriptLibrary = v.Spec
			case *kdexv1alpha1.KDexClusterScriptLibrary:
				scriptLibrary = v.Spec
			}

			if scriptLibrary.PackageReference != nil {
				packageRefs = append(packageRefs, *scriptLibrary.PackageReference)
			}
			scriptDefs = append(scriptDefs, scriptLibrary.Scripts...)
		}
	}

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalHost, &internalHost.Status.Conditions, internalHost.Spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, scriptLibraryObj)

		internalHost.Status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())

		var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

		switch v := scriptLibraryObj.(type) {
		case *kdexv1alpha1.KDexScriptLibrary:
			scriptLibrary = v.Spec
		case *kdexv1alpha1.KDexClusterScriptLibrary:
			scriptLibrary = v.Spec
		}

		if scriptLibrary.PackageReference != nil {
			packageRefs = append(packageRefs, *scriptLibrary.PackageReference)
		}
		scriptDefs = append(scriptDefs, scriptLibrary.Scripts...)
	}

	var utilityPages kdexv1alpha1.KDexInternalUtilityPageList
	if err := r.List(ctx, &utilityPages, client.InNamespace(r.ControllerNamespace), client.MatchingFields{internal.HOST_INDEX_KEY: r.FocalHost}); err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, fmt.Errorf("failed to list utility pages: %w", err))
	}

	for _, utilityPageType := range []kdexv1alpha1.KDexUtilityPageType{
		kdexv1alpha1.AnnouncementUtilityPageType,
		kdexv1alpha1.ErrorUtilityPageType,
		kdexv1alpha1.LoginUtilityPageType,
	} {
		pageHandler := r.HostHandler.GetUtilityPageHandler(utilityPageType)
		generation := 0
		if pageHandler.Name == "" {
			// check if it's supposed to be there
			expected := false
			for _, up := range utilityPages.Items {
				if up.Spec.Type == utilityPageType {
					expected = true
					generation = int(up.GetGeneration())
					break
				}
			}
			if expected {
				log.V(2).Info("waiting for host handler to warm up (utility page missing)", "type", utilityPageType)
				return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
			}
		}

		packageRefs = append(packageRefs, pageHandler.PackageReferences...)
		backendRefs = append(backendRefs, pageHandler.RequiredBackends...)
		// we don't add page scripts here, because they are added by the pages

		internalHost.Status.Attributes[fmt.Sprintf("utilityPage.%s.generation", utilityPageType)] = fmt.Sprintf("%d", generation)
	}

	if internalHost.Spec.IsConfigured(defaultBackendServerImage) {
		seenPaths[internalHost.Spec.IngressPath] = true
		requiredBackends = append(requiredBackends, resolvedBackend{
			Backend:   internalHost.Spec.Backend,
			Kind:      "KDexHost",
			Name:      internalHost.Name,
			Namespace: internalHost.Namespace,
		})
	}

	var bindings kdexv1alpha1.KDexPageList
	if err := r.List(ctx, &bindings, client.InNamespace(r.ControllerNamespace), client.MatchingFields{internal.HOST_INDEX_KEY: r.FocalHost}); err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, fmt.Errorf("failed to list page bindings: %w", err))
	}

	pageHandlers := r.HostHandler.Pages.List()
	if len(bindings.Items) != len(pageHandlers) {
		log.V(2).Info("waiting for host handler to warm up (page count mismatch)", "clusterCount", len(bindings.Items), "handlerCount", len(pageHandlers))
		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	for _, pageHandler := range pageHandlers {
		if seenPaths[pageHandler.Page.BasePath] {
			err = fmt.Errorf(
				"duplicated path %s, paths must be unique across backends and pages, obj: %s/%s, kind: %s",
				pageHandler.Page.BasePath, r.ControllerNamespace, pageHandler.Name, "KDexPage",
			)

			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}
		seenPaths[pageHandler.Page.BasePath] = true

		if pageHandler.Page.PatternPath != "" {
			if seenPaths[pageHandler.Page.PatternPath] {
				err = fmt.Errorf(
					"duplicated path %s, paths must be unique across backends and pages, obj: %s/%s, kind: %s",
					pageHandler.Page.PatternPath, r.ControllerNamespace, pageHandler.Name, "KDexPage",
				)

				return ctrl.Result{}, r.returnDegraged(&internalHost, err)
			}
			seenPaths[pageHandler.Page.PatternPath] = true
		}

		packageRefs = append(packageRefs, pageHandler.PackageReferences...)
		backendRefs = append(backendRefs, pageHandler.RequiredBackends...)
		// we don't add page scripts here, because they are added by the pages
	}

	uniqueBackendRefs := UniqueBackendRefs(backendRefs)
	uniquePackageRefs := UniquePackageRefs(packageRefs)
	uniqueScriptDefs := UniqueScriptDefs(scriptDefs)

	log.V(2).Info(
		"collected references",
		"uniqueBackendRefs", uniqueBackendRefs,
		"uniquePackageRefs", uniquePackageRefs,
		"uniqueScriptDefs", uniqueScriptDefs,
	)

	for _, ref := range uniqueBackendRefs {
		var backend kdexv1alpha1.Backend

		obj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalHost, &internalHost.Status.Conditions, &ref, r.RequeueDelay)
		if shouldReturn {
			log.Error(
				err,
				"failed to resolve backend",
				"backendRef", ref,
			)
			return r1, err
		}
		if obj == nil {
			continue
		}

		switch v := obj.(type) {
		case *kdexv1alpha1.KDexClusterApp:
			backend = v.Spec.Backend
		case *kdexv1alpha1.KDexClusterScriptLibrary:
			backend = v.Spec.Backend
		case *kdexv1alpha1.KDexClusterTheme:
			backend = v.Spec.Backend
		case *kdexv1alpha1.KDexApp:
			backend = v.Spec.Backend
		case *kdexv1alpha1.KDexScriptLibrary:
			backend = v.Spec.Backend
		case *kdexv1alpha1.KDexTheme:
			backend = v.Spec.Backend
		default:
			continue
		}

		if seenPaths[backend.IngressPath] {
			err = fmt.Errorf(
				"duplicated path %s, paths must be unique across backends and pages, obj: %s/%s, kind: %s",
				backend.IngressPath, ref.Namespace, ref.Name, ref.Kind,
			)

			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}
		seenPaths[backend.IngressPath] = true

		requiredBackends = append(requiredBackends, resolvedBackend{
			Backend:   backend,
			Kind:      ref.Kind,
			Name:      ref.Name,
			Namespace: ref.Namespace,
		})
	}

	log.V(2).Info(
		"collected backends",
		"requiredBackends", requiredBackends,
	)

	var functions kdexv1alpha1.KDexFunctionList
	if err := r.List(ctx, &functions, client.InNamespace(r.ControllerNamespace), client.MatchingFields{internal.HOST_INDEX_KEY: r.FocalHost}); err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, fmt.Errorf("failed to list functions: %w", err))
	}

	for _, function := range functions.Items {
		for routePath := range function.Spec.API.Paths {
			if seenPaths[routePath] {
				err = fmt.Errorf(
					"duplicated path %s, paths must be unique across backends and pages, obj: %s/%s, kind: %s",
					routePath, function.Namespace, function.Name, "KDexFunction",
				)

				return ctrl.Result{}, r.returnDegraged(&internalHost, err)
			}
			seenPaths[routePath] = true
		}
	}

	iprBackend, importMap, shouldReturn, r1, err := r.handleInternalPackageReferences(ctx, &internalHost, uniquePackageRefs, secrets)
	if shouldReturn {
		if r1.RequeueAfter > 0 {
			return r1, err
		}
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}

	if iprBackend != nil {
		requiredBackends = append(requiredBackends, *iprBackend)
	}

	deployments := make([]*appsv1.Deployment, 0, len(requiredBackends))
	for _, backend := range requiredBackends {
		name := fmt.Sprintf("%s-%s", internalHost.Name, backend.Name)

		_, dep, err := r.createOrUpdateBackendDeployment(ctx, &internalHost, name, backend, secrets)
		if err != nil {
			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}

		_, err = r.createOrUpdateBackendService(ctx, &internalHost, name, backend)
		if err != nil {
			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}

		deployments = append(deployments, dep)
	}

	if err := r.cleanupObsoleteBackends(ctx, &internalHost, requiredBackends); err != nil {
		log.V(2).Info("cleanup obsolete backends failed, requeueing", "err", err)

		return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	if internalHost.Spec.Routing.Strategy == kdexv1alpha1.HTTPRouteRoutingStrategy {
		_, err = r.createOrUpdateHTTPRoute(ctx, &internalHost, requiredBackends)
		if err != nil {
			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}
	} else {
		_, err = r.createOrUpdateIngress(ctx, &internalHost, requiredBackends, secrets)
		if err != nil {
			return ctrl.Result{}, r.returnDegraged(&internalHost, err)
		}
	}

	issuer := fmt.Sprintf("%s://%s", internalHost.Spec.Routing.Scheme, internalHost.Spec.Routing.Domains[0])

	authConfigBuilder := auth.NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]auth.AuthClient, error) {
			return auth.AuthClientLoader(
				secrets,
			)
		},
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) {
			return keys.LoadOrGenerateKeyPair(
				secrets,
				internalHost.Spec.DevMode,
			)
		},
	).WithOIDCClientConfigLoader(
		func() (*auth.OIDCClientConfig, error) {
			return auth.OIDCConfigLoader(
				secrets,
				internalHost.Spec.DevMode,
			)
		},
	).WithAPITokenManagerLoader(
		func() (*apitoken.TokenManager, error) {
			return apitoken.APITokenManagerLoader(
				issuer,
				secrets,
				r.HostHandler.GetCacheManager().GetCache("apitoken-revocation", cache.CacheOptions{}),
				internalHost.Spec.DevMode,
			)
		},
	).WithAudience(
		issuer,
	).WithIssuer(
		issuer,
	).WithDevMode(
		internalHost.Spec.DevMode,
	).WithCacheManager(
		r.HostHandler.GetCacheManager(),
	)

	authConfig, err := authConfigBuilder.Build(internalHost.Spec.Auth)
	if err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}

	authLookups := []auth.Lookup{
		auth.NewSecretLookup(secrets),
	}

	ldapSecret := secrets.Find(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "ldap" })
	if ldapSecret != nil {
		// Put ldap lookup first
		authLookups = append([]auth.Lookup{auth.NewLDAPLookup(*ldapSecret)}, authLookups...)
	}

	rp, err := auth.NewRoleProvider(
		ctx,
		r.Client,
		internalHost.Name,
		internalHost.Namespace,
		authLookups,
	)
	if err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}

	authExchanger, err := auth.NewExchanger(ctx, *authConfig, r.HostHandler.GetCacheManager(), rp)
	if err != nil {
		return ctrl.Result{}, r.returnDegraged(&internalHost, err)
	}

	for _, dep := range deployments {
		if dep == nil {
			continue
		}
		ready := false
		for _, cond := range dep.Status.Conditions {
			if cond.Type == appsv1.DeploymentAvailable && cond.Status == corev1.ConditionTrue {
				ready = true
			}
		}

		if !ready {
			kdexv1alpha1.SetConditions(
				&internalHost.Status.Conditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionFalse,
					Progressing: metav1.ConditionTrue,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconciling,
				fmt.Sprintf("Waiting for deployment/%s to be ready.", dep.Name),
			)

			log.V(2).Info(
				"waiting for deployments",
				"deployment", dep.Name,
				"conditions", dep.Status.Conditions,
			)

			return ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
		}

		internalHost.Status.Attributes[dep.Name+".deployment"] = "ready"
	}

	reconcileTime := time.Now()

	log.V(3).Info("deployments ready, about to set host")

	initialPaths := r.collectInitialPaths(requiredBackends, functions)

	log.V(3).Info("collected initial paths", "paths", initialPaths)

	var snif *sniffer.RequestSniffer
	if internalHost.Spec.DevMode {
		snif = &sniffer.RequestSniffer{
			BasePathRegex: (&kdexv1alpha1.API{}).BasePathRegex(),
			CreateFunc: func(obj client.Object, f controllerutil.MutateFn) (controllerutil.OperationResult, error) {
				return controllerutil.CreateOrUpdate(ctx, r.Client, obj, f)
			},
			Functions: func() []kdexv1alpha1.KDexFunction {
				return functions.Items
			},
			HostName:      internalHost.Name,
			ItemPathRegex: (&kdexv1alpha1.API{}).ItemPathRegex(),
			OpenAPIBuilder: func() *ko.Builder {
				return r.HostHandler.GetOpenAPIBuilder()
			},
			Namespace:     internalHost.Namespace,
			ReconcileTime: reconcileTime,
			SecuritySchemes: func() *openapi.SecuritySchemes {
				return r.HostHandler.SecuritySchemes()
			},
		}
	}

	r.HostHandler.SetHost(
		ctx,
		&internalHost.Spec.KDexHostSpec,
		&internalHost.Status,
		uniquePackageRefs,
		themeAssets,
		uniqueScriptDefs,
		importMap,
		initialPaths,
		functions.Items,
		authExchanger,
		authConfig,
		internalHost.Spec.Routing.Scheme,
		snif,
		reconcileTime,
	)

	log.V(3).Info("host has been set")

	kdexv1alpha1.SetConditions(
		&internalHost.Status.Conditions,
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
func (r *KDexInternalHostReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := r.indexers(mgr)
	if err != nil {
		return err
	}

	hasFocalHost := func(o client.Object) bool {
		switch t := o.(type) {
		case *kdexv1alpha1.KDexInternalHost:
			return t.Name == r.FocalHost
		case *kdexv1alpha1.KDexInternalPackageReferences:
			return t.Name == fmt.Sprintf("%s-packages", r.FocalHost)
		case *kdexv1alpha1.KDexPage:
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

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexInternalHost{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&kdexv1alpha1.KDexInternalPackageReferences{}).
		Owns(&networkingv1.Ingress{})

	ok, err := CRDExists(mgr, schema.GroupVersionKind{
		Group:   "gateway.networking.k8s.io",
		Version: "v1",
		Kind:    "HTTPRoute",
	})
	if err != nil {
		return err
	}
	if ok {
		builder = builder.Owns(&gatewayv1.HTTPRoute{})
	}

	return builder.
		Watches(
			&kdexv1alpha1.KDexFunction{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				fn, ok := o.(*kdexv1alpha1.KDexFunction)
				if !ok || fn.Spec.HostRef.Name != r.FocalHost {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      fn.Spec.HostRef.Name,
							Namespace: fn.Namespace,
						},
					},
				}
			})).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexTheme{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.ThemeRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterTheme{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.ThemeRef}")).
		Watches(
			&kdexv1alpha1.KDexInternalTranslation{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				translation, ok := o.(*kdexv1alpha1.KDexInternalTranslation)
				if !ok || translation.Spec.HostRef.Name != r.FocalHost {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      translation.Spec.HostRef.Name,
							Namespace: translation.Namespace,
						},
					},
				}
			})).
		Watches(
			&kdexv1alpha1.KDexInternalUtilityPage{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.AnnouncementRef}", "{.Spec.ErrorRef}", "{.Spec.LoginRef}")).
		Watches(
			&kdexv1alpha1.KDexPage{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				page, ok := obj.(*kdexv1alpha1.KDexPage)
				if !ok || page.Spec.HostRef.Name != r.FocalHost {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      page.Spec.HostRef.Name,
							Namespace: page.Namespace,
						},
					},
				}
			})).
		Watches(
			&kdexv1alpha1.KDexRole{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				scope, ok := obj.(*kdexv1alpha1.KDexRole)
				if !ok || scope.Spec.HostRef.Name != r.FocalHost {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      scope.Spec.HostRef.Name,
							Namespace: scope.Namespace,
						},
					},
				}
			})).
		Watches(
			&kdexv1alpha1.KDexRoleBinding{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				scopeBinding, ok := obj.(*kdexv1alpha1.KDexRoleBinding)
				if !ok || scopeBinding.Spec.HostRef.Name != r.FocalHost {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      scopeBinding.Spec.HostRef.Name,
							Namespace: scopeBinding.Namespace,
						},
					},
				}
			})).
		Watches(
			&corev1.ServiceAccount{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}, "{.Spec.ServiceAccountRef}")).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
				secret, ok := obj.(*corev1.Secret)
				if !ok || secret.Namespace != r.ControllerNamespace {
					return nil
				}

				var internalHost kdexv1alpha1.KDexInternalHost
				if err := r.Get(ctx, types.NamespacedName{Name: r.FocalHost, Namespace: r.ControllerNamespace}, &internalHost); err != nil {
					return nil
				}

				if internalHost.Spec.SecretSelector == nil {
					return nil
				}
				sel, err := metav1.LabelSelectorAsSelector(internalHost.Spec.SecretSelector)
				if err != nil {
					return nil
				}
				if !sel.Matches(labels.Set(secret.Labels)) {
					return nil
				}

				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      r.FocalHost,
							Namespace: r.ControllerNamespace,
						},
					},
				}
			})).
		WithEventFilter(enabledFilter).
		WithOptions(
			controller.TypedOptions[reconcile.Request]{
				LogConstructor: LogConstructor("kdexinternalhost", mgr),
			},
		).
		Named("kdexinternalhost").
		Complete(r)
}

func (r *KDexInternalHostReconciler) collectInitialPaths(
	backends []resolvedBackend, functions kdexv1alpha1.KDexFunctionList,
) map[string]ko.PathInfo {
	initialPaths := map[string]ko.PathInfo{}

	for _, backend := range backends {
		if backend.Backend.IngressPath == "" {
			continue
		}

		// Determine description based on backend kind
		var description string
		var summary string

		switch backend.Kind {
		case "KDexApp", "KDexClusterApp":
			summary = fmt.Sprintf("Application: %s", backend.Name)
			description = fmt.Sprintf("Backend service for KDex application %s", backend.Name)
		case "KDexFunction":
			summary = fmt.Sprintf("Function: %s", backend.Name)
			description = fmt.Sprintf("Backend service for KDex function %s", backend.Name)
		case "KDexTheme", "KDexClusterTheme":
			summary = fmt.Sprintf("Theme Assets: %s", backend.Name)
			description = fmt.Sprintf("Backend service for KDex theme %s assets", backend.Name)
		case "KDexScriptLibrary", "KDexClusterScriptLibrary":
			summary = fmt.Sprintf("Script Library: %s", backend.Name)
			description = fmt.Sprintf("Backend service for KDex script library %s", backend.Name)
		case "KDexInternalPackageReferences":
			summary = "Package Modules"
			description = "Backend service for serving npm package modules"
		default:
			summary = fmt.Sprintf("Backend: %s", backend.Name)
			description = fmt.Sprintf("Backend service for %s", backend.Name)
		}

		// Register wildcard path for static assets
		// Ensure path ends with slash before appending wildcard
		basePath := backend.Backend.IngressPath
		if !strings.HasSuffix(basePath, "/") {
			basePath += "/"
		}
		wildcardPath := basePath + "{path...}"

		pathInfo := ko.PathInfo{
			API: ko.OpenAPI{
				BasePath: basePath,
				Paths: map[string]ko.PathItem{
					wildcardPath: {
						Description: description,
						// Create generic GET operation for static content
						Get: &openapi.Operation{
							Description: "GET " + description,
							OperationID: backend.Name + "-get",
							Parameters: openapi.Parameters{
								ko.WildcardPathParam("path", "The path to the static resource"),
							},
							Responses: openapi.NewResponses(
								openapi.WithName("200", &openapi.Response{
									Content: openapi.NewContentWithSchema(
										&openapi.Schema{
											Format: "binary",
											Type:   &openapi.Types{openapi.TypeString},
										},
										[]string{"*/*"},
									),
									Description: new("Static content"),
									Headers: openapi.Headers{
										"Content-Type": &openapi.HeaderRef{
											Value: &openapi.Header{
												Parameter: openapi.Parameter{
													Description: "The MIME type of the file (image/png, text/css, text/html, etc.)",
													Schema: openapi.NewSchemaRef("", &openapi.Schema{
														Type: &openapi.Types{openapi.TypeString},
													}),
												},
											},
										},
									},
								}),
								openapi.WithName("404", &openapi.Response{
									Description: new("Resource not found"),
								}),
							),
							Summary: "GET " + summary,
							Tags:    []string{"backend"},
						},
						Summary: summary,
					},
				},
			},
			Type: ko.BackendPathType,
		}

		initialPaths[pathInfo.API.BasePath] = pathInfo
	}

	for _, function := range functions.Items {
		pathInfo := ko.PathInfo{
			API:           *ko.FromKDexAPI(&function.Spec.API),
			AutoGenerated: function.Spec.Metadata.AutoGenerated,
			Metadata:      function.Spec.Metadata.Metadata,
			Type:          ko.FunctionPathType,
		}
		initialPaths[function.Spec.API.BasePath] = pathInfo
	}

	return initialPaths
}

func (r *KDexInternalHostReconciler) createIPRBackend(
	internalHost *kdexv1alpha1.KDexInternalHost,
	image string,
) resolvedBackend {
	be := kdexv1alpha1.Backend{
		IngressPath:           internal.MODULE_PATH,
		StaticImage:           image,
		StaticImagePullPolicy: corev1.PullIfNotPresent,
	}

	if internalHost.Spec.Env != nil {
		be.Env = append(be.Env, internalHost.Spec.Env...)
	}

	// Synthetic Backend for the packages
	packagesBackend := resolvedBackend{
		Backend: be,
		Name:    "packages",
		Kind:    "KDexInternalPackageReferences",
	}

	return packagesBackend
}

func (r *KDexInternalHostReconciler) createOrUpdatePackageReferences(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	internalPackageReferences *kdexv1alpha1.KDexInternalPackageReferences,
	packageReferences []kdexv1alpha1.PackageReference,
) (bool, error) {
	log := logf.FromContext(ctx)

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		internalPackageReferences,
		func() error {
			if internalPackageReferences.CreationTimestamp.IsZero() {
				internalPackageReferences.Annotations = make(map[string]string)
				maps.Copy(internalPackageReferences.Annotations, internalHost.Annotations)
				internalPackageReferences.Labels = make(map[string]string)
				maps.Copy(internalPackageReferences.Labels, internalHost.Labels)

				internalPackageReferences.Labels["kdex.dev/packages"] = internalPackageReferences.Name

				internalPackageReferences.Spec.HostRef = corev1.LocalObjectReference{
					Name: internalHost.Name,
				}
			}

			internalPackageReferences.Spec.PackageReferences = packageReferences

			return ctrl.SetControllerReference(internalHost, internalPackageReferences, r.Scheme)
		},
	)

	log.V(2).Info(
		"createOrUpdatePackageReferences",
		"op", op,
		"attributes", internalPackageReferences.Status.Attributes,
		"generation", internalPackageReferences.Generation,
		"observedGeneration", internalPackageReferences.Status.ObservedGeneration,
		"packageReferences", internalPackageReferences.Spec.PackageReferences,
		"error", err,
	)

	if err != nil {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileSuccess,
			err.Error(),
		)

		return true, err
	}

	return false, nil
}

func (r *KDexInternalHostReconciler) createOrUpdateIngress(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	backends []resolvedBackend,
	secrets kdexv1alpha1.Secrets,
) (controllerutil.OperationResult, error) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      internalHost.Name,
			Namespace: internalHost.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		ingress,
		func() error {
			if ingress.Annotations == nil {
				ingress.Annotations = make(map[string]string)
			}
			maps.Copy(ingress.Annotations, internalHost.Annotations)
			if ingress.Labels == nil {
				ingress.Labels = make(map[string]string)
			}
			maps.Copy(ingress.Labels, internalHost.Labels)

			if ingress.CreationTimestamp.IsZero() {
				ingress.Labels["kdex.dev/ingress"] = ingress.Name

				ingress.Spec = *r.getMemoizedIngress().DeepCopy()

				if ingress.Spec.DefaultBackend == nil {
					ingress.Spec.DefaultBackend = &networkingv1.IngressBackend{}
				}

				if ingress.Spec.DefaultBackend.Service == nil {
					ingress.Spec.DefaultBackend.Service = &networkingv1.IngressServiceBackend{}
				}

				ingress.Spec.DefaultBackend.Service.Name = r.ServiceName

				ingress.Spec.DefaultBackend.Service.Port.Name = "server"
				ingress.Spec.IngressClassName = internalHost.Spec.Routing.IngressClassName
			}

			pathType := networkingv1.PathTypePrefix
			rules := make([]networkingv1.IngressRule, 0, len(internalHost.Spec.Routing.Domains))

			for _, domain := range internalHost.Spec.Routing.Domains {
				rules = append(rules, networkingv1.IngressRule{
					Host: domain,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: r.ServiceName,
											Port: networkingv1.ServiceBackendPort{
												Name: "server",
											},
										},
									},
								},
							},
						},
					},
				})
			}

			for _, rb := range backends {
				name := fmt.Sprintf("%s-%s", internalHost.Name, rb.Name)
				for _, rule := range rules {
					rule.HTTP.Paths = append(rule.HTTP.Paths,
						networkingv1.HTTPIngressPath{
							Path:     rb.Backend.IngressPath,
							PathType: &pathType,
							Backend: networkingv1.IngressBackend{
								Service: &networkingv1.IngressServiceBackend{
									Name: name,
									Port: networkingv1.ServiceBackendPort{
										Name: "server",
									},
								},
							},
						},
					)
				}
			}

			memoizedRules := r.getMemoizedIngress().Rules
			ingress.Spec.Rules = make([]networkingv1.IngressRule, len(memoizedRules), len(memoizedRules)+len(rules))
			copy(ingress.Spec.Rules, memoizedRules)
			ingress.Spec.Rules = append(ingress.Spec.Rules, rules...)

			memoizedTLS := r.getMemoizedIngress().TLS
			ingress.Spec.TLS = make([]networkingv1.IngressTLS, len(memoizedTLS))
			copy(ingress.Spec.TLS, memoizedTLS)

			if internalHost.Spec.Routing.Scheme == "https" {
				tlsSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Type == corev1.SecretTypeTLS })
				if len(tlsSecrets) > 0 {
					ingress.Spec.TLS = append(ingress.Spec.TLS, networkingv1.IngressTLS{
						Hosts:      internalHost.Spec.Routing.Domains,
						SecretName: tlsSecrets[0].Name,
					})
				} else if issuer, ok := internalHost.Annotations["cert-manager.io/cluster-issuer"]; ok && issuer != "" {
					ingress.Spec.TLS = append(ingress.Spec.TLS, networkingv1.IngressTLS{
						Hosts:      internalHost.Spec.Routing.Domains,
						SecretName: internalHost.Name + "-tls",
					})
				} else if issuer, ok := internalHost.Annotations["cert-manager.io/issuer"]; ok && issuer != "" {
					ingress.Spec.TLS = append(ingress.Spec.TLS, networkingv1.IngressTLS{
						Hosts:      internalHost.Spec.Routing.Domains,
						SecretName: internalHost.Name + "-tls",
					})
				}
			}

			return ctrl.SetControllerReference(internalHost, ingress, r.Scheme)
		},
	)

	if err != nil {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return controllerutil.OperationResultNone, err
	}

	if len(ingress.Status.LoadBalancer.Ingress) > 0 {
		var addresses strings.Builder
		separator := ""
		for _, ing := range ingress.Status.LoadBalancer.Ingress {
			if ing.IP != "" {
				addresses.WriteString(separator)
				addresses.WriteString(ing.IP)
				separator = ","
			} else if ing.Hostname != "" {
				addresses.WriteString(separator)
				addresses.WriteString(ing.Hostname)
				separator = ","
			}
		}
		internalHost.Status.Attributes["ingress"] = addresses.String()
	}

	return op, nil
}

// createOrUpdateHTTPRoute is the Gateway API counterpart to createOrUpdateIngress.
// It produces an HTTPRoute attached to platform-provisioned Gateway(s), with the
// same routing surface as the Ingress builder: a catch-all "/" route to the
// host-manager Service and one route per resolved backend mounted at its
// IngressPath. TLS is intentionally not handled here - HTTPRoute does not
// terminate TLS; that is the Gateway listener's responsibility.
//
// ParentRefs precedence (CR override > chart default):
//  1. KDexInternalHost.Spec.Routing.ParentRefs when non-empty
//  2. BackendDefault.HttpRoute.ParentRefs from the controller's loaded
//     configuration (chart-supplied via /config.yaml)
//
// When neither is set, the HTTPRoute is created without parentRefs; the route
// will be orphaned and the Gateway API status will surface the misconfiguration
// rather than reconciliation failing here.
func (r *KDexInternalHostReconciler) createOrUpdateHTTPRoute(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	backends []resolvedBackend,
) (controllerutil.OperationResult, error) {
	httpRoute := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      internalHost.Name,
			Namespace: internalHost.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		httpRoute,
		func() error {
			if httpRoute.Annotations == nil {
				httpRoute.Annotations = make(map[string]string)
			}
			maps.Copy(httpRoute.Annotations, internalHost.Annotations)
			if httpRoute.Labels == nil {
				httpRoute.Labels = make(map[string]string)
			}
			maps.Copy(httpRoute.Labels, internalHost.Labels)

			if httpRoute.CreationTimestamp.IsZero() {
				httpRoute.Labels["kdex.dev/httproute"] = httpRoute.Name
				httpRoute.Spec = *r.getMemoizedHTTPRoute().DeepCopy()
			}

			// Hostnames mirror routing.domains 1:1. The Routing.Scheme field is
			// not consulted here - Gateway API hostnames are scheme-agnostic;
			// the listener on the parent Gateway determines TLS/HTTP.
			hostnames := make([]gatewayv1.Hostname, len(internalHost.Spec.Routing.Domains))
			for i, domain := range internalHost.Spec.Routing.Domains {
				hostnames[i] = gatewayv1.Hostname(domain)
			}
			httpRoute.Spec.Hostnames = hostnames

			// ParentRefs: CR-level override beats chart default.
			if len(internalHost.Spec.Routing.ParentRefs) > 0 {
				httpRoute.Spec.ParentRefs = internalHost.Spec.Routing.ParentRefs
			} else {
				httpRoute.Spec.ParentRefs = r.getMemoizedHTTPRoute().ParentRefs
			}

			pathPrefix := gatewayv1.PathMatchPathPrefix
			controllerServiceName := gatewayv1.ObjectName(r.ServiceName)
			// gatewayv1.PortNumber is a type alias for int32 in gateway-api
			// v1.5.0, so r.Port (int32) and r.backendServicePort()'s return
			// value are directly usable as *gatewayv1.PortNumber without
			// explicit conversion.
			controllerPort := r.Port
			backendPort := r.backendServicePort()
			rootPath := "/"

			// Per-backend rules come first so the controller-runtime serialized
			// rule order matches user expectations (most specific paths first).
			// Gateway API also tie-breaks identical PathPrefix matches by rule
			// order, so this is the safe ordering for paths like "/-/app" vs "/".
			rules := make([]gatewayv1.HTTPRouteRule, 0, 1+len(backends))

			for _, rb := range backends {
				backendName := gatewayv1.ObjectName(fmt.Sprintf("%s-%s", internalHost.Name, rb.Name))
				path := rb.Backend.IngressPath
				rules = append(rules, gatewayv1.HTTPRouteRule{
					Matches: []gatewayv1.HTTPRouteMatch{
						{
							Path: &gatewayv1.HTTPPathMatch{
								Type:  &pathPrefix,
								Value: &path,
							},
						},
					},
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: backendName,
									Port: &backendPort,
								},
							},
						},
					},
				})
			}

			// Catch-all "/" → controller service. Last so backend-specific
			// prefixes win on ties.
			rules = append(rules, gatewayv1.HTTPRouteRule{
				Matches: []gatewayv1.HTTPRouteMatch{
					{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  &pathPrefix,
							Value: &rootPath,
						},
					},
				},
				BackendRefs: []gatewayv1.HTTPBackendRef{
					{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: controllerServiceName,
								Port: &controllerPort,
							},
						},
					},
				},
			})

			// Prepend memoized system rules (BackendDefault.HttpRoute.Rules)
			// the same way the Ingress builder treats memoized rules.
			memoizedRules := r.getMemoizedHTTPRoute().Rules
			httpRoute.Spec.Rules = make([]gatewayv1.HTTPRouteRule, len(memoizedRules), len(memoizedRules)+len(rules))
			copy(httpRoute.Spec.Rules, memoizedRules)
			httpRoute.Spec.Rules = append(httpRoute.Spec.Rules, rules...)

			return ctrl.SetControllerReference(internalHost, httpRoute, r.Scheme)
		},
	)

	if err != nil {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return controllerutil.OperationResultNone, err
	}

	// Surface the attached parents in Status.Attributes["httproute"] - mirrors
	// the "ingress" attribute used by the Ingress branch (which records LB IPs).
	// For HTTPRoute the analogous human-readable signal is which Gateway(s)
	// accepted the route.
	if len(httpRoute.Status.Parents) > 0 {
		var parents strings.Builder
		separator := ""
		for _, p := range httpRoute.Status.Parents {
			parents.WriteString(separator)
			if p.ParentRef.Namespace != nil {
				parents.WriteString(string(*p.ParentRef.Namespace))
				parents.WriteByte('/')
			}
			parents.WriteString(string(p.ParentRef.Name))
			separator = ","
		}
		internalHost.Status.Attributes["httproute"] = parents.String()
	}

	return op, nil
}

func (r *KDexInternalHostReconciler) createOrUpdateBackendDeployment(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	name string,
	resolvedBackend resolvedBackend,
	secrets kdexv1alpha1.Secrets,
) (controllerutil.OperationResult, *appsv1.Deployment, error) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: internalHost.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		deployment,
		func() error {
			if deployment.CreationTimestamp.IsZero() {
				deployment.Annotations = make(map[string]string)
				maps.Copy(deployment.Annotations, internalHost.Annotations)
				deployment.Labels = make(map[string]string)
				maps.Copy(deployment.Labels, internalHost.Labels)

				deployment.Labels["kdex.dev/type"] = internal.BACKEND
				deployment.Labels["kdex.dev/backend"] = resolvedBackend.Name
				deployment.Labels["kdex.dev/host"] = internalHost.Name
				deployment.Labels["kdex.dev/kind"] = resolvedBackend.Kind

				deployment.Spec = *r.getMemoizedBackendDeployment().DeepCopy()

				deployment.Spec.Selector.MatchLabels["kdex.dev/type"] = internal.BACKEND
				deployment.Spec.Selector.MatchLabels["kdex.dev/backend"] = resolvedBackend.Name
				deployment.Spec.Selector.MatchLabels["kdex.dev/host"] = internalHost.Name
				deployment.Spec.Selector.MatchLabels["kdex.dev/kind"] = resolvedBackend.Kind

				deployment.Spec.Template.Labels["kdex.dev/type"] = internal.BACKEND
				deployment.Spec.Template.Labels["kdex.dev/backend"] = resolvedBackend.Name
				deployment.Spec.Template.Labels["kdex.dev/host"] = internalHost.Name
				deployment.Spec.Template.Labels["kdex.dev/kind"] = resolvedBackend.Kind
			}

			deployment.Spec.Template.Spec.Containers[0].Name = "backend"

			// Rebuild env, imagePullSecrets, volumes, and volumeMounts from scratch
			// each reconcile so removals in the desired spec propagate to the live
			// Deployment and so per-reconcile entries can't accumulate. Start from
			// the memoized template defaults (POD_NAME/POD_NAMESPACE/POD_IP env,
			// the scratch volume + mount) so those baseline entries are preserved.
			defaultSpec := r.getMemoizedBackendDeployment().DeepCopy().Template.Spec

			var defaultContainerEnv []corev1.EnvVar
			var defaultContainerMounts []corev1.VolumeMount
			if len(defaultSpec.Containers) > 0 {
				defaultContainerEnv = defaultSpec.Containers[0].Env
				defaultContainerMounts = defaultSpec.Containers[0].VolumeMounts
			}

			env := append([]corev1.EnvVar{}, defaultContainerEnv...)
			env = append(env, resolvedBackend.Backend.Env...)
			env = append(env, corev1.EnvVar{
				Name:  "PATH_PREFIX",
				Value: resolvedBackend.Backend.IngressPath,
			})
			deployment.Spec.Template.Spec.Containers[0].Env = env

			dockerSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Type == corev1.SecretTypeDockerConfigJson })
			imagePullSecretRefs := make([]corev1.LocalObjectReference, 0, len(dockerSecrets))
			for _, sec := range dockerSecrets {
				imagePullSecretRefs = append(imagePullSecretRefs, corev1.LocalObjectReference{Name: sec.Name})
			}
			deployment.Spec.Template.Spec.ImagePullSecrets = imagePullSecretRefs

			if resolvedBackend.Backend.Replicas != nil {
				deployment.Spec.Replicas = resolvedBackend.Backend.Replicas
			}

			if resolvedBackend.Backend.Resources.Size() > 0 {
				deployment.Spec.Template.Spec.Containers[0].Resources = resolvedBackend.Backend.Resources
			}

			if resolvedBackend.Backend.ServerImage != "" {
				deployment.Spec.Template.Spec.Containers[0].Image = resolvedBackend.Backend.ServerImage
			} else {
				deployment.Spec.Template.Spec.Containers[0].Image = r.Configuration.BackendDefault.ServerImage
			}

			if resolvedBackend.Backend.ServerImagePullPolicy != "" {
				deployment.Spec.Template.Spec.Containers[0].ImagePullPolicy = resolvedBackend.Backend.ServerImagePullPolicy
			} else {
				deployment.Spec.Template.Spec.Containers[0].ImagePullPolicy = r.Configuration.BackendDefault.ServerImagePullPolicy
			}

			volumes := append([]corev1.Volume{}, defaultSpec.Volumes...)
			volumeMounts := append([]corev1.VolumeMount{}, defaultContainerMounts...)
			if resolvedBackend.Backend.StaticImage != "" {
				volumes = append(volumes, corev1.Volume{
					Name: internal.OCI_IMAGE,
					VolumeSource: corev1.VolumeSource{
						Image: &corev1.ImageVolumeSource{
							Reference:  resolvedBackend.Backend.StaticImage,
							PullPolicy: resolvedBackend.Backend.StaticImagePullPolicy,
						},
					},
				})
				volumeMounts = append(volumeMounts, corev1.VolumeMount{
					Name:      internal.OCI_IMAGE,
					MountPath: "/public",
					ReadOnly:  true,
				})
			}
			deployment.Spec.Template.Spec.Volumes = volumes
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts = volumeMounts

			return ctrl.SetControllerReference(internalHost, deployment, r.Scheme)
		},
	)

	if err != nil {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return controllerutil.OperationResultNone, nil, err
	}

	return op, deployment, nil
}

func (r *KDexInternalHostReconciler) createOrUpdateBackendService(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	name string,
	resolvedBackend resolvedBackend,
) (controllerutil.OperationResult, error) {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: internalHost.Namespace,
		},
	}

	op, err := ctrl.CreateOrUpdate(
		ctx,
		r.Client,
		service,
		func() error {
			if service.CreationTimestamp.IsZero() {
				service.Annotations = make(map[string]string)
				maps.Copy(service.Annotations, internalHost.Annotations)
				service.Labels = make(map[string]string)
				maps.Copy(service.Labels, internalHost.Labels)

				service.Labels["kdex.dev/type"] = internal.BACKEND
				service.Labels["kdex.dev/backend"] = resolvedBackend.Name
				service.Labels["kdex.dev/host"] = internalHost.Name
				service.Labels["kdex.dev/kind"] = resolvedBackend.Kind

				service.Spec = *r.getMemoizedService().DeepCopy()

				service.Spec.Selector = make(map[string]string)

				service.Spec.Selector["kdex.dev/type"] = internal.BACKEND
				service.Spec.Selector["kdex.dev/backend"] = resolvedBackend.Name
				service.Spec.Selector["kdex.dev/host"] = internalHost.Name
				service.Spec.Selector["kdex.dev/kind"] = resolvedBackend.Kind
			}

			return ctrl.SetControllerReference(internalHost, service, r.Scheme)
		},
	)

	if err != nil {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return controllerutil.OperationResultNone, err
	}

	return op, nil
}

func (r *KDexInternalHostReconciler) cleanupObsoleteBackends(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	backends []resolvedBackend,
) error {
	backendNames := make(map[string]bool)
	for _, rb := range backends {
		name := fmt.Sprintf("%s-%s", internalHost.Name, rb.Name)
		backendNames[name] = true
	}

	labelSelector := client.MatchingLabels{
		"kdex.dev/type": internal.BACKEND,
		"kdex.dev/host": internalHost.Name,
	}

	// Cleanup Deployments
	deploymentList := &appsv1.DeploymentList{}
	if err := r.List(ctx, deploymentList, client.InNamespace(internalHost.Namespace), labelSelector); err != nil {
		return err
	}

	for _, deployment := range deploymentList.Items {
		if !backendNames[deployment.Name] {
			if err := r.Delete(ctx, &deployment); err != nil {
				return err
			}
			delete(internalHost.Status.Attributes, deployment.Name+".deployment")
		}
	}

	// Cleanup Services
	serviceList := &corev1.ServiceList{}
	if err := r.List(ctx, serviceList, client.InNamespace(internalHost.Namespace), labelSelector); err != nil {
		return err
	}

	for _, service := range serviceList.Items {
		if !backendNames[service.Name] {
			if err := r.Delete(ctx, &service); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *KDexInternalHostReconciler) getMemoizedBackendDeployment() *appsv1.DeploymentSpec {
	r.mu.RLock()

	if r.memoizedDeployment != nil {
		r.mu.RUnlock()
		return r.memoizedDeployment
	}

	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.memoizedDeployment = r.Configuration.BackendDefault.Deployment.DeepCopy()

	return r.memoizedDeployment
}

func (r *KDexInternalHostReconciler) getMemoizedIngress() *networkingv1.IngressSpec {
	r.mu.RLock()

	if r.memoizedIngress != nil {
		r.mu.RUnlock()
		return r.memoizedIngress
	}

	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.memoizedIngress = r.Configuration.BackendDefault.Ingress.DeepCopy()

	return r.memoizedIngress
}

func (r *KDexInternalHostReconciler) getMemoizedHTTPRoute() *gatewayv1.HTTPRouteSpec {
	r.mu.RLock()

	if r.memoizedHTTPRoute != nil {
		r.mu.RUnlock()
		return r.memoizedHTTPRoute
	}

	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.memoizedHTTPRoute = r.Configuration.BackendDefault.HttpRoute.DeepCopy()

	return r.memoizedHTTPRoute
}

// backendServicePort returns the numeric port to address backend Services on.
// Gateway API BackendObjectReference takes a *PortNumber (no named-port support
// in v1), so we resolve from the BackendDefault.Service template: prefer the
// port named "server" (matches the Ingress builder's convention), fall back to
// the first port, default to 80 if neither is available.
func (r *KDexInternalHostReconciler) backendServicePort() gatewayv1.PortNumber {
	ports := r.Configuration.BackendDefault.Service.Ports
	for _, p := range ports {
		if p.Name == "server" {
			return p.Port
		}
	}
	if len(ports) > 0 {
		return ports[0].Port
	}
	return 80
}

func (r *KDexInternalHostReconciler) getMemoizedService() *corev1.ServiceSpec {
	r.mu.RLock()

	if r.memoizedService != nil {
		r.mu.RUnlock()
		return r.memoizedService
	}

	r.mu.RUnlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.memoizedService = r.Configuration.BackendDefault.Service.DeepCopy()

	return r.memoizedService
}

func (r *KDexInternalHostReconciler) handleInternalPackageReferences(
	ctx context.Context,
	internalHost *kdexv1alpha1.KDexInternalHost,
	uniquePackageRefs []kdexv1alpha1.PackageReference,
	secrets kdexv1alpha1.Secrets,
) (*resolvedBackend, string, bool, ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// TODO: when there is no package image and the only packageRef is @kdex-tech/ui use a prebuilt image.
	// There should be a configuration that holds the default image reference.

	if internalHost.Spec.PackagesImage != "" {
		importMap, err := r.PullImportMap(ctx, internalHost.Spec.PackagesImage, secrets)
		if err != nil {
			return nil, "", true, ctrl.Result{}, fmt.Errorf("failed to pull importmap from %s: %w", internalHost.Spec.PackagesImage, err)
		}

		internalHost.Status.Attributes["packages.image"] = internalHost.Spec.PackagesImage
		internalHost.Status.Attributes["packages.importmap"] = importMap

		packagesBackend := r.createIPRBackend(internalHost, internalHost.Spec.PackagesImage)

		return &packagesBackend, importMap, false, ctrl.Result{}, nil
	}

	internalPackageReferences := &kdexv1alpha1.KDexInternalPackageReferences{
		ObjectMeta: metav1.ObjectMeta{
			Name:      internalHost.Name,
			Namespace: internalHost.Namespace,
		},
	}

	if len(uniquePackageRefs) == 0 {
		log.V(2).Info("host has no package references")

		if err := r.Delete(ctx, internalPackageReferences); client.IgnoreNotFound(err) != nil {
			return nil, "", true, ctrl.Result{}, err
		}

		delete(internalHost.Status.Attributes, "packages.image")
		delete(internalHost.Status.Attributes, "packages.importmap")

		return nil, "", false, ctrl.Result{}, nil
	}

	shouldReturn, err := r.createOrUpdatePackageReferences(ctx, internalHost, internalPackageReferences, uniquePackageRefs)
	if shouldReturn {
		return nil, "", true, ctrl.Result{}, err
	}

	if meta.IsStatusConditionFalse(internalPackageReferences.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady)) {
		kdexv1alpha1.SetConditions(
			&internalHost.Status.Conditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionFalse,
				Progressing: metav1.ConditionTrue,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileSuccess,
			"image not available yet, requeueing",
		)

		return nil, "", true, ctrl.Result{RequeueAfter: r.RequeueDelay}, nil
	}

	internalHost.Status.Attributes["packages.image"] = internalPackageReferences.Status.Attributes["image"]
	internalHost.Status.Attributes["packages.importmap"] = internalPackageReferences.Status.Attributes["importmap"]

	packagesBackend := r.createIPRBackend(internalHost, internalPackageReferences.Status.Attributes["image"])

	return &packagesBackend, internalPackageReferences.Status.Attributes["importmap"], false, ctrl.Result{}, nil
}

func (r *KDexInternalHostReconciler) returnDegraged(internalHost *kdexv1alpha1.KDexInternalHost, err error) error {
	kdexv1alpha1.SetConditions(
		&internalHost.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		kdexv1alpha1.ConditionReasonReconcileError,
		err.Error(),
	)

	return err
}

func (r *KDexInternalHostReconciler) PullImportMap(ctx context.Context, imageRef string, secrets kdexv1alpha1.Secrets) (string, error) {
	log := logf.FromContext(ctx)

	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return "", fmt.Errorf("failed to create repository client: %w", err)
	}

	log.V(3).Info("[PullImportMap]", "registry", repo.Reference.Registry)

	registryURL, err := url.Parse("//" + repo.Reference.Registry)
	if err != nil {
		return "", fmt.Errorf("failed to parse registry URL: %w", err)
	}

	log.V(3).Info("[PullImportMap]", "hostname", registryURL.Hostname())

	// Determine if we should use HTTP for local registries
	if strings.HasSuffix(registryURL.Hostname(), ".local") {
		repo.PlainHTTP = true
	}

	// Handle Authentication
	cred := r.getRegistryCredential(repo.Reference.Registry, secrets)
	if cred.Username != "" {
		repo.Client = &remoteauth.Client{
			Client: retry.DefaultClient,
			Cache:  remoteauth.NewCache(),
			Credential: func(ctx context.Context, s string) (remoteauth.Credential, error) {
				return cred, nil
			},
		}
	}

	log.V(3).Info("[PullImportMap]", "repo.reference", repo.Reference.String())

	// 1. Resolve to a manifest (handles OCI index/multi-arch)
	descriptor, err := oras.Resolve(ctx, repo, repo.Reference.Reference, oras.ResolveOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to resolve image: %w", err)
	}

	// 2. Fetch Manifest
	rc, err := repo.Fetch(ctx, descriptor)
	if err != nil {
		return "", fmt.Errorf("failed to fetch manifest: %w", err)
	}
	manifestData, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return "", fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return "", fmt.Errorf("failed to parse manifest: %w", err)
	}

	// 3. Find our importmap layer
	var layerDescriptor ocispec.Descriptor
	for _, layer := range manifest.Layers {
		// Accept both tar+gzip (the new correct format) and raw json (legacy/direct)
		if layer.MediaType == "application/json" ||
			layer.MediaType == "application/vnd.kdex.importmap+json" ||
			layer.MediaType == "application/vnd.oci.image.layer.v1.tar+gzip" {
			layerDescriptor.MediaType = layer.MediaType
			layerDescriptor.Digest = digest.Digest(layer.Digest)
			layerDescriptor.Size = layer.Size
			break
		}
	}

	if layerDescriptor.Digest == "" {
		return "", fmt.Errorf("could not find importmap layer in image %s", imageRef)
	}

	// 4. Fetch the Blob
	rc, err = repo.Fetch(ctx, layerDescriptor)
	if err != nil {
		return "", fmt.Errorf("failed to fetch importmap blob: %w", err)
	}
	defer func() { _ = rc.Close() }()

	// If it's a tarball, we need to extract the json file
	if strings.Contains(layerDescriptor.MediaType, "tar") {
		gr, err := gzip.NewReader(rc)
		if err != nil {
			return "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer func() { _ = gr.Close() }()

		tr := tar.NewReader(gr)
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", fmt.Errorf("failed to read tar: %w", err)
			}
			// Clean the path to handle potential './' prefixes or other variations
			cleanName := path.Clean(header.Name)
			if cleanName == "importmap.json" || strings.HasSuffix(cleanName, "/importmap.json") {
				data, err := io.ReadAll(tr)
				if err != nil {
					return "", fmt.Errorf("failed to read file from tar: %w", err)
				}
				return string(data), nil
			}
		}
		return "", fmt.Errorf("importmap.json not found in tarball layer")
	}

	// Otherwise, assume it's raw data
	blobData, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("failed to read importmap blob: %w", err)
	}

	return string(blobData), nil
}

func (r *KDexInternalHostReconciler) getRegistryCredential(registry string, secrets kdexv1alpha1.Secrets) remoteauth.Credential {
	dockerSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Type == corev1.SecretTypeDockerConfigJson })

	for _, s := range dockerSecrets {
		var config struct {
			Auths map[string]struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Auth     string `json:"auth"`
			} `json:"auths"`
		}

		if err := json.Unmarshal(s.Data[corev1.DockerConfigJsonKey], &config); err != nil {
			continue
		}

		a, ok := config.Auths[registry]
		if !ok {
			continue
		}

		if a.Username == "" && a.Password == "" && a.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				continue
			}
			i := strings.IndexByte(string(decoded), ':')
			if i < 0 {
				continue
			}
			a.Username = string(decoded[:i])
			a.Password = string(decoded[i+1:])
		}

		return remoteauth.Credential{Username: a.Username, Password: a.Password}
	}

	return remoteauth.EmptyCredential
}

type resolvedBackend struct {
	Backend   kdexv1alpha1.Backend
	Kind      string
	Name      string
	Namespace string
}

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
	"fmt"
	"maps"
	"time"

	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/page"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const UTILITY_PAGE_FINALIZER = "kdex-tech/kdex-host-utility-page-finalizer"

// KDexInternalUtilityPageReconciler reconciles a KDexInternalUtilityPage object
type KDexInternalUtilityPageReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	HostHandler         *host.HostHandler
	RequeueDelay        time.Duration
	Scheme              *runtime.Scheme
}

// nolint:gocyclo
func (r *KDexInternalUtilityPageReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	if req.Namespace != r.ControllerNamespace {
		log.V(4).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	var internalUtilityPage kdexv1alpha1.KDexInternalUtilityPage
	if err := r.Get(ctx, req.NamespacedName, &internalUtilityPage); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Only process utility pages for the focal host
	if internalUtilityPage.Spec.HostRef.Name != r.FocalHost {
		log.V(4).Info("skipping reconcile", "host", internalUtilityPage.Spec.HostRef.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	if internalUtilityPage.Status.Attributes == nil {
		internalUtilityPage.Status.Attributes = make(map[string]string)
	}

	// Defer status update
	defer func() {
		internalUtilityPage.Status.ObservedGeneration = internalUtilityPage.Generation
		updateErr := r.Status().Update(ctx, &internalUtilityPage)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("status", "status", internalUtilityPage.Status, "err", err, "res", res)
	}()

	if internalUtilityPage.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&internalUtilityPage, UTILITY_PAGE_FINALIZER) {
			controllerutil.AddFinalizer(&internalUtilityPage, UTILITY_PAGE_FINALIZER)
			if err := r.Update(ctx, &internalUtilityPage); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		if controllerutil.ContainsFinalizer(&internalUtilityPage, UTILITY_PAGE_FINALIZER) {
			r.HostHandler.RemoveUtilityPage(internalUtilityPage.Name)

			controllerutil.RemoveFinalizer(&internalUtilityPage, UTILITY_PAGE_FINALIZER)
			if err := r.Update(ctx, &internalUtilityPage); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	kdexv1alpha1.SetConditions(
		&internalUtilityPage.Status.Conditions,
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
	scriptDefs := []kdexv1alpha1.ScriptDef{}

	archetypeObj, shouldReturn, r1, err := ResolveOrDefaultPageArchetype(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, internalUtilityPage.Spec.PageArchetypeRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	internalUtilityPage.Status.Attributes["archetype.generation"] = fmt.Sprintf("%d", archetypeObj.GetGeneration())

	var pageArchetypeSpec kdexv1alpha1.KDexPageArchetypeSpec

	switch v := archetypeObj.(type) {
	case *kdexv1alpha1.KDexPageArchetype:
		pageArchetypeSpec = v.Spec
	case *kdexv1alpha1.KDexClusterPageArchetype:
		pageArchetypeSpec = v.Spec
	}

	archetypeScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, pageArchetypeSpec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if archetypeScriptLibraryObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, archetypeScriptLibraryObj)

		internalUtilityPage.Status.Attributes["archetype.scriptLibrary.generation"] = fmt.Sprintf("%d", archetypeScriptLibraryObj.GetGeneration())

		var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

		switch v := archetypeScriptLibraryObj.(type) {
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

	contents, shouldReturn, response, err := ResolveContents(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, internalUtilityPage.Spec.ContentEntries, r.RequeueDelay)
	if shouldReturn {
		return response, err
	}

	contentsMap := map[string]page.PackedContent{}
	for slot, content := range contents {
		contentsMap[slot] = content.Content

		if content.App != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, content.AppObj)

			internalUtilityPage.Status.Attributes[slot+".content.generation"] = content.Content.AppGeneration

			switch v := content.AppObj.(type) {
			case *kdexv1alpha1.KDexApp:
				packageRefs = append(packageRefs, v.Spec.PackageReference)
				scriptDefs = append(scriptDefs, v.Spec.Scripts...)
			case *kdexv1alpha1.KDexClusterApp:
				packageRefs = append(packageRefs, v.Spec.PackageReference)
				scriptDefs = append(scriptDefs, v.Spec.Scripts...)
			}
		}
	}

	footerContent := ""
	footerRef := internalUtilityPage.Spec.OverrideFooterRef
	if footerRef == nil {
		footerRef = pageArchetypeSpec.DefaultFooterRef
	}
	footerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, footerRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if footerObj != nil {
		internalUtilityPage.Status.Attributes["footer.generation"] = fmt.Sprintf("%d", footerObj.GetGeneration())

		var footerSpec kdexv1alpha1.KDexPageFooterSpec
		switch v := footerObj.(type) {
		case *kdexv1alpha1.KDexPageFooter:
			footerContent = v.Spec.Content
			footerSpec = v.Spec
		case *kdexv1alpha1.KDexClusterPageFooter:
			footerContent = v.Spec.Content
			footerSpec = v.Spec
		}

		footerScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, footerSpec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if footerScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, footerScriptLibraryObj)

			internalUtilityPage.Status.Attributes["footer.scriptLibrary.generation"] = fmt.Sprintf("%d", footerScriptLibraryObj.GetGeneration())

			var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

			switch v := footerScriptLibraryObj.(type) {
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

	headerContent := ""
	headerRef := internalUtilityPage.Spec.OverrideHeaderRef
	if headerRef == nil {
		headerRef = pageArchetypeSpec.DefaultHeaderRef
	}
	headerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, headerRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if headerObj != nil {
		internalUtilityPage.Status.Attributes["header.generation"] = fmt.Sprintf("%d", headerObj.GetGeneration())

		var headerSpec kdexv1alpha1.KDexPageHeaderSpec
		switch v := headerObj.(type) {
		case *kdexv1alpha1.KDexPageHeader:
			headerContent = v.Spec.Content
			headerSpec = v.Spec
		case *kdexv1alpha1.KDexClusterPageHeader:
			headerContent = v.Spec.Content
			headerSpec = v.Spec
		}

		headerScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, headerSpec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if headerScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, headerScriptLibraryObj)

			internalUtilityPage.Status.Attributes["header.scriptLibrary.generation"] = fmt.Sprintf("%d", headerScriptLibraryObj.GetGeneration())

			var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

			switch v := headerScriptLibraryObj.(type) {
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

	navigationRefs := maps.Clone(pageArchetypeSpec.DefaultNavigationRefs)
	if len(internalUtilityPage.Spec.OverrideNavigationRefs) > 0 {
		if navigationRefs == nil {
			navigationRefs = make(map[string]*kdexv1alpha1.KDexObjectReference)
		}
		maps.Copy(navigationRefs, internalUtilityPage.Spec.OverrideNavigationRefs)
	}
	navigations, shouldReturn, r1, err := ResolvePageNavigations(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, navigationRefs, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	navigationsMap := map[string]string{}
	for slot, navigation := range navigations {
		navigationsMap[slot] = navigation.Spec.Content

		internalUtilityPage.Status.Attributes[slot+".navigation.generation"] = fmt.Sprintf("%d", navigation.Generation)

		navigationScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, navigation.Spec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if navigationScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, navigationScriptLibraryObj)

			internalUtilityPage.Status.Attributes[slot+".navigation.scriptLibrary.generation"] = fmt.Sprintf("%d", navigationScriptLibraryObj.GetGeneration())

			var scriptLibrary kdexv1alpha1.KDexScriptLibrarySpec

			switch v := navigationScriptLibraryObj.(type) {
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

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &internalUtilityPage, &internalUtilityPage.Status.Conditions, internalUtilityPage.Spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, scriptLibraryObj)

		internalUtilityPage.Status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())

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

	// Utility pages must not resolve the host otherwise the host cannot start
	// successfully.

	uniqueBackendRefs := UniqueBackendRefs(backendRefs)
	uniquePackageRefs := UniquePackageRefs(packageRefs)
	uniqueScriptDefs := UniqueScriptDefs(scriptDefs)

	log.V(2).Info(
		"collected references",
		"uniqueBackendRefs", uniqueBackendRefs,
		"uniquePackageRefs", uniquePackageRefs,
		"uniqueScriptDefs", uniqueScriptDefs,
	)

	r.HostHandler.AddOrUpdateUtilityPage(buildUtilityPagePageHandler(
		&internalUtilityPage,
		pageArchetypeSpec.Content,
		contentsMap,
		footerContent,
		headerContent,
		navigationsMap,
		uniquePackageRefs,
		uniqueBackendRefs,
		uniqueScriptDefs,
	))

	kdexv1alpha1.SetConditions(
		&internalUtilityPage.Status.Conditions,
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
func (r *KDexInternalUtilityPageReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexInternalUtilityPage{}).
		Watches(
			&kdexv1alpha1.KDexApp{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.ContentEntries[*].AppRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterApp{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.ContentEntries[*].AppRef}")).
		Watches(
			&kdexv1alpha1.KDexInternalHost{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.HostRef}")).
		Watches(
			&kdexv1alpha1.KDexPageArchetype{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.PageArchetypeRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageArchetype{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.PageArchetypeRef}")).
		Watches(
			&kdexv1alpha1.KDexPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideFooterRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideFooterRef}")).
		Watches(
			&kdexv1alpha1.KDexPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideHeaderRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideHeaderRef}")).
		Watches(
			&kdexv1alpha1.KDexPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideNavigationRefs.*}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.OverrideNavigationRefs.*}")).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}, "{.Spec.ScriptLibraryRef}")).
		WithOptions(
			controller.TypedOptions[reconcile.Request]{
				LogConstructor: LogConstructor("kdexinternalutilitypage", mgr),
			},
		).
		Named("kdexinternalutilitypage").
		Complete(r)
}

// buildUtilityPagePageHandler assembles the PageHandler the reconciler
// hands to HostHandler.AddOrUpdateUtilityPage. The Status field — wired
// here — is what lets PageHandler.Checksum (and therefore the
// utility-page render-cache key) fold in the referenced-resource
// generations the reconciler writes into Status.Attributes. Without it,
// CacheKey collapses to "<name>::<lang>" and the cache never invalidates
// on theme / header / footer / app / navigation / script-library
// changes. See kdex-tech/host-manager#55.
//
// Mirror of the inline `Status: &page.Status` field in
// kdexpage_controller.go.
func buildUtilityPagePageHandler(
	internalUtilityPage *kdexv1alpha1.KDexInternalUtilityPage,
	mainTemplate string,
	contentsMap map[string]page.PackedContent,
	footerContent string,
	headerContent string,
	navigationsMap map[string]string,
	packageReferences []kdexv1alpha1.PackageReference,
	requiredBackends []kdexv1alpha1.KDexObjectReference,
	scripts []kdexv1alpha1.ScriptDef,
) page.PageHandler {
	return page.PageHandler{
		Content:           contentsMap,
		Footer:            footerContent,
		Header:            headerContent,
		MainTemplate:      mainTemplate,
		Name:              internalUtilityPage.Name,
		Navigations:       navigationsMap,
		PackageReferences: packageReferences,
		RequiredBackends:  requiredBackends,
		Scripts:           scripts,
		Status:            &internalUtilityPage.Status,
		UtilityPage:       &internalUtilityPage.Spec.KDexUtilityPageSpec,
	}
}

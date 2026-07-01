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
	"reflect"
	"time"

	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/host"
	pages "github.com/kdex-tech/host-manager/internal/page"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// KDexPageReconciler reconciles a KDexPage object
type KDexPageReconciler struct {
	client.Client
	Configuration       configuration.NexusConfiguration
	ControllerNamespace string
	FocalHost           string
	HostHandler         *host.HostHandler
	RequeueDelay        time.Duration
	Scheme              *runtime.Scheme
}

//nolint:gocyclo
func (r *KDexPageReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	if req.Namespace != r.ControllerNamespace {
		log.V(4).Info("skipping reconcile", "namespace", req.Namespace, "controllerNamespace", r.ControllerNamespace)
		return ctrl.Result{}, nil
	}

	var page kdexv1alpha1.KDexPage
	if err := r.Get(ctx, req.NamespacedName, &page); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if page.Spec.HostRef.Name != r.FocalHost {
		log.V(4).Info("skipping reconcile", "host", page.Spec.HostRef.Name, "focalHost", r.FocalHost)
		return ctrl.Result{}, nil
	}

	if page.Status.Attributes == nil {
		page.Status.Attributes = make(map[string]string)
	}

	// Snapshot the observed status so the deferred write can be made
	// conditional on an actual change.
	observedStatus := page.Status.DeepCopy()

	// Defer status update
	defer func() {
		page.Status.ObservedGeneration = page.Generation

		// Only write status when it actually changed. The reconciler pulses a
		// transient "Reconciling" condition at the top of every pass, which
		// bumps LastTransitionTime on Ready/Progressing even when the net
		// settled status is unchanged. An unconditional Status().Update() would
		// then bump resourceVersion every reconcile, re-firing the controller's
		// own For() watch and self-looping (~25 reconciles/sec, pegging a CPU
		// core). See kdex-tech/host-manager#126.
		if !objectStatusEqual(observedStatus, &page.Status) {
			updateErr := r.Status().Update(ctx, &page)
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

		if meta.IsStatusConditionFalse(page.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady)) {
			r.HostHandler.Pages.Delete(page.Name)
		}

		log.V(3).Info("status", "status", page.Status, "err", err, "res", res)
	}()

	if page.DeletionTimestamp.IsZero() {
		if !controllerutil.ContainsFinalizer(&page, internal.PAGE_FINALIZER) {
			controllerutil.AddFinalizer(&page, internal.PAGE_FINALIZER)
			if err := r.Update(ctx, &page); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
	} else {
		if controllerutil.ContainsFinalizer(&page, internal.PAGE_FINALIZER) {
			r.HostHandler.Pages.Delete(page.Name)

			controllerutil.RemoveFinalizer(&page, internal.PAGE_FINALIZER)
			if err := r.Update(ctx, &page); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
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

	archetypeObj, shouldReturn, r1, err := ResolveOrDefaultPageArchetype(ctx, r.Client, &page, &page.Status.Conditions, page.Spec.PageArchetypeRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	page.Status.Attributes["archetype.generation"] = fmt.Sprintf("%d", archetypeObj.GetGeneration())

	var pageArchetypeSpec kdexv1alpha1.KDexPageArchetypeSpec

	switch v := archetypeObj.(type) {
	case *kdexv1alpha1.KDexPageArchetype:
		pageArchetypeSpec = v.Spec
	case *kdexv1alpha1.KDexClusterPageArchetype:
		pageArchetypeSpec = v.Spec
	}

	archetypeScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, pageArchetypeSpec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if archetypeScriptLibraryObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, archetypeScriptLibraryObj)

		page.Status.Attributes["archetype.scriptLibrary.generation"] = fmt.Sprintf("%d", archetypeScriptLibraryObj.GetGeneration())

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

	contents, shouldReturn, r1, err := ResolveContents(ctx, r.Client, &page, &page.Status.Conditions, page.Spec.ContentEntries, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	contentsMap := map[string]pages.PackedContent{}
	for slot, content := range contents {
		contentsMap[slot] = content.Content

		if content.App != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, content.AppObj)

			page.Status.Attributes[slot+".content.generation"] = content.Content.AppGeneration

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
	footerRef := page.Spec.OverrideFooterRef
	if footerRef == nil {
		footerRef = pageArchetypeSpec.DefaultFooterRef
	}
	footerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, footerRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if footerObj != nil {
		page.Status.Attributes["footer.generation"] = fmt.Sprintf("%d", footerObj.GetGeneration())

		var footerSpec kdexv1alpha1.KDexPageFooterSpec
		switch v := footerObj.(type) {
		case *kdexv1alpha1.KDexPageFooter:
			footerContent = v.Spec.Content
			footerSpec = v.Spec
		case *kdexv1alpha1.KDexClusterPageFooter:
			footerContent = v.Spec.Content
			footerSpec = v.Spec
		}

		footerScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, footerSpec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if footerScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, footerScriptLibraryObj)

			page.Status.Attributes["footer.scriptLibrary.generation"] = fmt.Sprintf("%d", footerScriptLibraryObj.GetGeneration())

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
	headerRef := page.Spec.OverrideHeaderRef
	if headerRef == nil {
		headerRef = pageArchetypeSpec.DefaultHeaderRef
	}
	headerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, headerRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if headerObj != nil {
		page.Status.Attributes["header.generation"] = fmt.Sprintf("%d", headerObj.GetGeneration())

		var headerSpec kdexv1alpha1.KDexPageHeaderSpec
		switch v := headerObj.(type) {
		case *kdexv1alpha1.KDexPageHeader:
			headerContent = v.Spec.Content
			headerSpec = v.Spec
		case *kdexv1alpha1.KDexClusterPageHeader:
			headerContent = v.Spec.Content
			headerSpec = v.Spec
		}

		headerScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, headerSpec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if headerScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, headerScriptLibraryObj)

			page.Status.Attributes["header.scriptLibrary.generation"] = fmt.Sprintf("%d", headerScriptLibraryObj.GetGeneration())

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
	if len(page.Spec.OverrideNavigationRefs) > 0 {
		if navigationRefs == nil {
			navigationRefs = make(map[string]*kdexv1alpha1.KDexObjectReference)
		}
		maps.Copy(navigationRefs, page.Spec.OverrideNavigationRefs)
	}
	navigations, shouldReturn, r1, err := ResolvePageNavigations(ctx, r.Client, &page, &page.Status.Conditions, navigationRefs, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	navigationsMap := map[string]string{}
	for slot, navigation := range navigations {
		navigationsMap[slot] = navigation.Spec.Content

		page.Status.Attributes[slot+".navigation.generation"] = fmt.Sprintf("%d", navigation.Generation)

		navigationScriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, navigation.Spec.ScriptLibraryRef, r.RequeueDelay)
		if shouldReturn {
			return r1, err
		}

		if navigationScriptLibraryObj != nil {
			CollectBackend(defaultBackendServerImage, &backendRefs, navigationScriptLibraryObj)

			page.Status.Attributes[slot+".navigation.scriptLibrary.generation"] = fmt.Sprintf("%d", navigationScriptLibraryObj.GetGeneration())

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

	parentPageObj, shouldReturn, r1, err := ResolvePage(ctx, r.Client, &page, &page.Status.Conditions, page.Spec.ParentPageRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if parentPageObj != nil {
		page.Status.Attributes["parent.page.generation"] = fmt.Sprintf("%d", parentPageObj.GetGeneration())
	}

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, &page, &page.Status.Conditions, page.Spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		CollectBackend(defaultBackendServerImage, &backendRefs, scriptLibraryObj)

		page.Status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())

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

	uniqueBackendRefs := UniqueBackendRefs(backendRefs)
	uniquePackageRefs := UniquePackageRefs(packageRefs)
	uniqueScriptDefs := UniqueScriptDefs(scriptDefs)

	log.V(2).Info(
		"collected references",
		"uniqueBackendRefs", uniqueBackendRefs,
		"uniquePackageRefs", uniquePackageRefs,
		"uniqueScriptDefs", uniqueScriptDefs,
	)

	r.HostHandler.Pages.Set(pages.PageHandler{
		Content:           contentsMap,
		Footer:            footerContent,
		Header:            headerContent,
		MainTemplate:      pageArchetypeSpec.Content,
		Name:              page.Name,
		Navigations:       navigationsMap,
		PackageReferences: uniquePackageRefs,
		Page:              &page.Spec,
		RequiredBackends:  uniqueBackendRefs,
		Scripts:           uniqueScriptDefs,
		// Pass Status so PageHandler.Checksum (used to compose the page-render
		// cache key) mixes in the reference generations the controller writes
		// to Status.Attributes. Without this the cache key collapses to just
		// "<name>::<lang>" and never invalidates on theme/header/footer/app
		// changes.
		Status: &page.Status,
	})

	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
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

// referencedResourcePredicate filters updates to the resources a page
// references (apps, headers, footers, navigations, archetypes, script
// libraries, the host) so a noisy upstream operator can't peg the renderer.
// It re-enqueues on any meaningful change but drops updates whose ONLY
// differences are pure noise: metadata.resourceVersion, metadata.managedFields,
// and per-condition status.conditions[*].LastTransitionTime. That is exactly
// the churn observed in kdex-tech/host-manager#129 (nexus-manager rewriting
// KDexApp condition timestamps ~2x/sec), which pre-fix re-rendered every page
// ~4x/sec and pegged a CPU core even though host-manager itself wrote nothing.
//
// A plain GenerationChangedPredicate is too blunt here: indirect dependency
// edits propagate through an intermediate resource's *status* (e.g. an
// archetype re-publishing a referenced header's generation into
// status.Attributes), which carries no generation bump. Filtering that would
// break "updates when an indirect dependency is updated". This predicate keeps
// those — it drops only timestamp/bookkeeping churn. Create/Delete still pass
// (a newly-appearing dependency can settle a page; a removed one degrades it).
// This is the watch-side complement to the #126 status-write guard.
var referencedResourcePredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		if e.ObjectOld == nil || e.ObjectNew == nil {
			return true
		}
		return !referencedResourceNoiseOnly(e.ObjectOld, e.ObjectNew)
	},
}

// referencedResourceNoiseOnly reports whether old and new differ only by
// fields that carry no meaning for page rendering: resourceVersion,
// managedFields, and per-condition LastTransitionTime. It is the watch-level
// analog of objectStatusEqual (the #126 status-write guard).
func referencedResourceNoiseOnly(oldObj, newObj client.Object) bool {
	return equality.Semantic.DeepEqual(
		normalizeReferencedResource(oldObj),
		normalizeReferencedResource(newObj),
	)
}

// normalizeReferencedResource returns a deep copy with the noisy fields zeroed
// so two revisions that differ only by churn compare equal. Status.Conditions
// is reached by reflection because every referenced type embeds the same
// KDexObjectStatus but exposes no shared Go interface for it (the same reason
// ResolveKDexObjectReference reflects over Status.Conditions).
func normalizeReferencedResource(obj client.Object) client.Object {
	c, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		return obj
	}
	c.SetResourceVersion("")
	c.SetManagedFields(nil)

	v := reflect.ValueOf(c)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return c
	}
	statusField := v.Elem().FieldByName("Status")
	if !statusField.IsValid() {
		return c
	}
	conditionsField := statusField.FieldByName("Conditions")
	if !conditionsField.IsValid() || !conditionsField.CanInterface() {
		return c
	}
	if conditions, ok := conditionsField.Interface().([]metav1.Condition); ok {
		for i := range conditions {
			conditions[i].LastTransitionTime = metav1.Time{}
		}
	}
	return c
}

// SetupWithManager sets up the controller with the Manager.
func (r *KDexPageReconciler) SetupWithManager(mgr ctrl.Manager) error {
	l := LogConstructor("kdexpage", mgr)(nil)

	hasFocalHost := func(o client.Object) bool {
		l.V(3).Info("hasFocalHost", "object", o)
		switch t := o.(type) {
		case *kdexv1alpha1.KDexInternalHost:
			return t.Name == r.FocalHost
		case *kdexv1alpha1.KDexInternalPackageReferences:
			return t.Name == fmt.Sprintf("%s-packages", r.FocalHost)
		case *kdexv1alpha1.KDexInternalTranslation:
			return t.Spec.HostRef.Name == r.FocalHost
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

	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexPage{}).
		Watches(
			&kdexv1alpha1.KDexApp{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.ContentEntries[*].AppRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterApp{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.ContentEntries[*].AppRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexInternalHost{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.HostRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexPageArchetype{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.PageArchetypeRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterPageArchetype{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.PageArchetypeRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexPage{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.ParentPageRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideFooterRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideFooterRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideHeaderRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideHeaderRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideNavigationRefs.*}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.OverrideNavigationRefs.*}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.ScriptLibraryRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}, "{.Spec.ScriptLibraryRef}"),
			builder.WithPredicates(referencedResourcePredicate)).
		WithEventFilter(enabledFilter).
		WithOptions(
			controller.TypedOptions[reconcile.Request]{
				LogConstructor: LogConstructor("kdexpage", mgr),
			},
		).
		Named("kdexpage").
		Complete(r)
}

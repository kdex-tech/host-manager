package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type MockPageArchetypeReconciler struct {
	client.Client
	RequeueDelay time.Duration
	Scheme       *runtime.Scheme
}

func (r *MockPageArchetypeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	var status *kdexv1alpha1.KDexObjectStatus
	var spec kdexv1alpha1.KDexPageArchetypeSpec
	var om metav1.ObjectMeta
	var o client.Object

	if req.Namespace == "" {
		var clusterPageArchetype kdexv1alpha1.KDexClusterPageArchetype
		if err := r.Get(ctx, req.NamespacedName, &clusterPageArchetype); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &clusterPageArchetype.Status
		spec = clusterPageArchetype.Spec
		om = clusterPageArchetype.ObjectMeta
		o = &clusterPageArchetype
	} else {
		var pageArchetype kdexv1alpha1.KDexPageArchetype
		if err := r.Get(ctx, req.NamespacedName, &pageArchetype); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &pageArchetype.Status
		spec = pageArchetype.Spec
		om = pageArchetype.ObjectMeta
		o = &pageArchetype
	}

	if status.Attributes == nil {
		status.Attributes = make(map[string]string)
	}

	log := logf.Log.WithName("MockPageArchetypeReconciler")

	// Defer status update
	defer func() {
		status.ObservedGeneration = om.Generation
		updateErr := r.Status().Update(ctx, o)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("print status", "status", status, "err", err, "res", res)
	}()

	footerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.DefaultFooterRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if footerObj != nil {
		status.Attributes["footer.generation"] = fmt.Sprintf("%d", footerObj.GetGeneration())
	}

	headerObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.DefaultHeaderRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if headerObj != nil {
		status.Attributes["header.generation"] = fmt.Sprintf("%d", headerObj.GetGeneration())
	}

	navigations, shouldReturn, r1, err := ResolvePageNavigations(ctx, r.Client, o, &status.Conditions, spec.DefaultNavigationRefs, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	for k, navigation := range navigations {
		status.Attributes[k+".navigation.generation"] = fmt.Sprintf("%d", navigation.Generation)
	}

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())
	}

	kdexv1alpha1.SetConditions(
		&status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	return ctrl.Result{}, nil
}

func (r *MockPageArchetypeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexPageArchetype{}).
		Watches(
			&kdexv1alpha1.KDexClusterPageArchetype{},
			&handler.EnqueueRequestForObject{}).
		Watches(
			&kdexv1alpha1.KDexPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultFooterRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultFooterRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageFooter{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexClusterPageArchetype{}, &kdexv1alpha1.KDexClusterPageArchetypeList{}, "{.Spec.DefaultFooterRef}")).
		Watches(
			&kdexv1alpha1.KDexPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultHeaderRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultHeaderRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageHeader{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexClusterPageArchetype{}, &kdexv1alpha1.KDexClusterPageArchetypeList{}, "{.Spec.DefaultHeaderRef}")).
		Watches(
			&kdexv1alpha1.KDexPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultNavigationRefs.*}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.DefaultNavigationRefs.*}")).
		Watches(
			&kdexv1alpha1.KDexClusterPageNavigation{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexClusterPageArchetype{}, &kdexv1alpha1.KDexClusterPageArchetypeList{}, "{.Spec.DefaultNavigationRefs.*}")).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexClusterPageArchetype{}, &kdexv1alpha1.KDexClusterPageArchetypeList{}, "{.Spec.ScriptLibraryRef}")).
		Named("mockpagearchetypereconciler").
		Complete(r)
}

type MockPageFooterReconciler struct {
	client.Client
	RequeueDelay time.Duration
	Scheme       *runtime.Scheme
}

func (r *MockPageFooterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	var status *kdexv1alpha1.KDexObjectStatus
	var spec kdexv1alpha1.KDexPageFooterSpec
	var om metav1.ObjectMeta
	var o client.Object

	if req.Namespace == "" {
		var clusterPageFooter kdexv1alpha1.KDexClusterPageFooter
		if err := r.Get(ctx, req.NamespacedName, &clusterPageFooter); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &clusterPageFooter.Status
		spec = clusterPageFooter.Spec
		om = clusterPageFooter.ObjectMeta
		o = &clusterPageFooter
	} else {
		var pageFooter kdexv1alpha1.KDexPageFooter
		if err := r.Get(ctx, req.NamespacedName, &pageFooter); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &pageFooter.Status
		spec = pageFooter.Spec
		om = pageFooter.ObjectMeta
		o = &pageFooter
	}

	if status.Attributes == nil {
		status.Attributes = make(map[string]string)
	}

	log := logf.Log.WithName("MockPageFooterReconciler")

	// Defer status update
	defer func() {
		status.ObservedGeneration = om.Generation
		updateErr := r.Status().Update(ctx, o)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("print status", "status", status, "err", err, "res", res)
	}()

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())
	}

	kdexv1alpha1.SetConditions(
		&status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	return ctrl.Result{}, nil
}

func (r *MockPageFooterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexPageFooter{}).
		Watches(
			&kdexv1alpha1.KDexClusterPageFooter{},
			&handler.EnqueueRequestForObject{}).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageFooter{}, &kdexv1alpha1.KDexPageFooterList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageFooter{}, &kdexv1alpha1.KDexPageFooterList{}, "{.Spec.ScriptLibraryRef}")).
		Named("mockpagefooterreconciler").
		Complete(r)
}

type MockPageHeaderReconciler struct {
	client.Client
	RequeueDelay time.Duration
	Scheme       *runtime.Scheme
}

func (r *MockPageHeaderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	var status *kdexv1alpha1.KDexObjectStatus
	var spec kdexv1alpha1.KDexPageHeaderSpec
	var om metav1.ObjectMeta
	var o client.Object

	if req.Namespace == "" {
		var clusterPageHeader kdexv1alpha1.KDexClusterPageHeader
		if err := r.Get(ctx, req.NamespacedName, &clusterPageHeader); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &clusterPageHeader.Status
		spec = clusterPageHeader.Spec
		om = clusterPageHeader.ObjectMeta
		o = &clusterPageHeader
	} else {
		var pageHeader kdexv1alpha1.KDexPageHeader
		if err := r.Get(ctx, req.NamespacedName, &pageHeader); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &pageHeader.Status
		spec = pageHeader.Spec
		om = pageHeader.ObjectMeta
		o = &pageHeader
	}

	if status.Attributes == nil {
		status.Attributes = make(map[string]string)
	}

	log := logf.Log.WithName("MockPageHeaderReconciler")

	// Defer status update
	defer func() {
		status.ObservedGeneration = om.Generation
		updateErr := r.Status().Update(ctx, o)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("print status", "status", status, "err", err, "res", res)
	}()

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())
	}

	kdexv1alpha1.SetConditions(
		&status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	return ctrl.Result{}, nil
}

func (r *MockPageHeaderReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexPageHeader{}).
		Watches(
			&kdexv1alpha1.KDexClusterPageHeader{},
			&handler.EnqueueRequestForObject{}).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageHeader{}, &kdexv1alpha1.KDexPageHeaderList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageHeader{}, &kdexv1alpha1.KDexPageHeaderList{}, "{.Spec.ScriptLibraryRef}")).
		Named("mockpageheaderreconciler").
		Complete(r)
}

type MockPageNavigationReconciler struct {
	client.Client
	RequeueDelay time.Duration
	Scheme       *runtime.Scheme
}

func (r *MockPageNavigationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	var status *kdexv1alpha1.KDexObjectStatus
	var spec kdexv1alpha1.KDexPageNavigationSpec
	var om metav1.ObjectMeta
	var o client.Object

	if req.Namespace == "" {
		var clusterPageNavigation kdexv1alpha1.KDexClusterPageNavigation
		if err := r.Get(ctx, req.NamespacedName, &clusterPageNavigation); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &clusterPageNavigation.Status
		spec = clusterPageNavigation.Spec
		om = clusterPageNavigation.ObjectMeta
		o = &clusterPageNavigation
	} else {
		var pageNavigation kdexv1alpha1.KDexPageNavigation
		if err := r.Get(ctx, req.NamespacedName, &pageNavigation); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &pageNavigation.Status
		spec = pageNavigation.Spec
		om = pageNavigation.ObjectMeta
		o = &pageNavigation
	}

	if status.Attributes == nil {
		status.Attributes = make(map[string]string)
	}

	log := logf.Log.WithName("MockPageNavigationReconciler")

	// Defer status update
	defer func() {
		status.ObservedGeneration = om.Generation
		updateErr := r.Status().Update(ctx, o)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("print status", "status", status, "err", err, "res", res)
	}()

	scriptLibraryObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, r.Client, o, &status.Conditions, spec.ScriptLibraryRef, r.RequeueDelay)
	if shouldReturn {
		return r1, err
	}

	if scriptLibraryObj != nil {
		status.Attributes["scriptLibrary.generation"] = fmt.Sprintf("%d", scriptLibraryObj.GetGeneration())
	}

	kdexv1alpha1.SetConditions(
		&status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	return ctrl.Result{}, nil
}

func (r *MockPageNavigationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexPageNavigation{}).
		Watches(
			&kdexv1alpha1.KDexClusterPageNavigation{},
			&handler.EnqueueRequestForObject{}).
		Watches(
			&kdexv1alpha1.KDexScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageNavigation{}, &kdexv1alpha1.KDexPageNavigationList{}, "{.Spec.ScriptLibraryRef}")).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexPageNavigation{}, &kdexv1alpha1.KDexPageNavigationList{}, "{.Spec.ScriptLibraryRef}")).
		Named("mockpagenavigationreconciler").
		Complete(r)
}

type MockScriptLibraryReconciler struct {
	client.Client
	RequeueDelay time.Duration
	Scheme       *runtime.Scheme
}

func (r *MockScriptLibraryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (res ctrl.Result, err error) {
	var status *kdexv1alpha1.KDexObjectStatus
	var om metav1.ObjectMeta
	var o client.Object

	if req.Namespace == "" {
		var clusterScriptLibrary kdexv1alpha1.KDexClusterScriptLibrary
		if err := r.Get(ctx, req.NamespacedName, &clusterScriptLibrary); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &clusterScriptLibrary.Status
		om = clusterScriptLibrary.ObjectMeta
		o = &clusterScriptLibrary
	} else {
		var scriptLibrary kdexv1alpha1.KDexScriptLibrary
		if err := r.Get(ctx, req.NamespacedName, &scriptLibrary); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(err)
		}
		status = &scriptLibrary.Status
		om = scriptLibrary.ObjectMeta
		o = &scriptLibrary
	}

	if status.Attributes == nil {
		status.Attributes = make(map[string]string)
	}

	log := logf.Log.WithName("MockScriptLibraryReconciler")

	// Defer status update
	defer func() {
		status.ObservedGeneration = om.Generation
		updateErr := r.Status().Update(ctx, o)
		if updateErr != nil {
			if kerrors.IsConflict(updateErr) {
				err = nil
				res = ctrl.Result{RequeueAfter: 50 * time.Millisecond}
			} else {
				err = updateErr
				res = ctrl.Result{}
			}
		}

		log.V(3).Info("print status", "status", status, "err", err, "res", res)
	}()

	kdexv1alpha1.SetConditions(
		&status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionFalse,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionTrue,
		},
		kdexv1alpha1.ConditionReasonReconcileSuccess,
		"Reconciliation successful",
	)

	return ctrl.Result{}, nil
}

func (r *MockScriptLibraryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kdexv1alpha1.KDexScriptLibrary{}).
		Watches(
			&kdexv1alpha1.KDexClusterScriptLibrary{},
			&handler.EnqueueRequestForObject{}).
		Watches(
			&corev1.Secret{},
			MakeHandlerByReferencePath(r.Client, r.Scheme, &kdexv1alpha1.KDexScriptLibrary{}, &kdexv1alpha1.KDexScriptLibraryList{}, "{.Spec.PackageReference.SecretRef}")).
		Named("mockscriptlibraryreconciler").
		Complete(r)
}

package controller

import (
	"context"
	"fmt"

	pages "github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/rewrite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Rewrite-mode Degraded reasons (#217). Controller-local for the same reason
// as routeCollisionConditionReason: ConditionReason is a bare string type, so
// a kdex-crds constant would cost a release for strings only this controller
// emits.
const (
	rewriteTargetIsRewriteReason    kdexv1alpha1.ConditionReason = "RewriteTargetIsRewrite"
	rewriteTargetInternalReason     kdexv1alpha1.ConditionReason = "RewriteTargetInternal"
	rewriteUnknownPlaceholderReason kdexv1alpha1.ConditionReason = "RewriteUnknownPlaceholder"
)

// reconcileRewrite handles a KDexPage in rewrite mode. It has no archetype,
// header, footer, navigation, content or script library, so none of those are
// resolved; only the target (and parentPageRef, which navigation placement
// uses) are.
func (r *KDexPageReconciler) reconcileRewrite(ctx context.Context, page *kdexv1alpha1.KDexPage) (ctrl.Result, error) {
	rw := page.Spec.Rewrite

	if unknown := rewrite.UnknownPlaceholders(rw.Path, page.Spec.PatternPath); len(unknown) > 0 {
		setRewriteDegraded(page, rewriteUnknownPlaceholderReason, fmt.Sprintf(
			"rewrite.path placeholders %v are not wildcards of patternPath %q", unknown, page.Spec.PatternPath))
		return ctrl.Result{}, nil
	}

	// Targets resolve in the page's own namespace; targetRef.namespace is
	// deliberately ignored (cross-namespace targets would cross hosts).
	ref := kdexv1alpha1.KDexObjectReference{Kind: rw.TargetRef.Kind, Name: rw.TargetRef.Name}
	targetObj, shouldReturn, res, err := ResolveKDexObjectReference(
		ctx, r.Client, page, &page.Status.Conditions, &ref, r.RequeueDelay)

	// A static problem with a target that EXISTS outranks its readiness: it
	// will not clear when the target becomes Ready, so it must not hide behind
	// the resolver's generic "not ready" Degraded.
	if targetObj != nil {
		if reason, msg := rewriteTargetProblem(targetObj); reason != "" {
			setRewriteDegraded(page, reason, msg)
			return ctrl.Result{}, nil
		}
	}
	if shouldReturn {
		return res, err
	}
	page.Status.Attributes["rewrite.target.generation"] = fmt.Sprintf("%d", targetObj.GetGeneration())

	parentPageObj, shouldReturn, res, err := ResolvePage(
		ctx, r.Client, page, &page.Status.Conditions, page.Spec.ParentPageRef, r.RequeueDelay)
	if shouldReturn {
		return res, err
	}
	if parentPageObj != nil {
		page.Status.Attributes["parent.page.generation"] = fmt.Sprintf("%d", parentPageObj.GetGeneration())
	}

	r.HostHandler.Pages.Set(pages.PageHandler{
		Name:   page.Name,
		Page:   &page.Spec,
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
	return ctrl.Result{}, nil
}

// rewriteTargetProblem reports a static reason the resolved target can never
// serve as a rewrite target, or "" when it can.
func rewriteTargetProblem(obj client.Object) (kdexv1alpha1.ConditionReason, string) {
	switch t := obj.(type) {
	case *kdexv1alpha1.KDexPage:
		if t.Spec.Rewrite != nil {
			return rewriteTargetIsRewriteReason, fmt.Sprintf(
				"rewrite target KDexPage %s is itself a rewrite page; only one hop is allowed", t.Name)
		}
	case *kdexv1alpha1.KDexFunction:
		if t.Spec.Internal {
			return rewriteTargetInternalReason, fmt.Sprintf(
				"rewrite target KDexFunction %s is internal and is not served by the host", t.Name)
		}
	}
	return "", ""
}

func setRewriteDegraded(page *kdexv1alpha1.KDexPage, reason kdexv1alpha1.ConditionReason, msg string) {
	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{
			Degraded:    metav1.ConditionTrue,
			Progressing: metav1.ConditionFalse,
			Ready:       metav1.ConditionFalse,
		},
		reason,
		msg,
	)
}

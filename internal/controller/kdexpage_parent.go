package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// parentPageRef Degraded reasons. Controller-local: ConditionReason is a bare
// string type (see routeCollisionConditionReason).
const (
	parentPageCycleReason        kdexv1alpha1.ConditionReason = "ParentPageCycle"
	parentPageHostMismatchReason kdexv1alpha1.ConditionReason = "ParentPageHostMismatch"
)

// parentPageChainLimit bounds the parentPageRef walk. A menu deeper than this
// is not a real site; the walk stops without a finding rather than loop.
const parentPageChainLimit = 32

// parentPageProblem reports why page, whose parentPageRef resolved to parent,
// can never appear in a menu, or "" when it can. The page tree is built at
// render time from the host's page store, bucketed by parent name, so a page
// whose parent is on another host, or whose parent chain loops back to it,
// is served but sits under no root. Neither clears by waiting, so neither
// blocks the page; the caller reports it as Degraded on a Ready page.
func parentPageProblem(
	ctx context.Context,
	c client.Client,
	page *kdexv1alpha1.KDexPage,
	parent *kdexv1alpha1.KDexPage,
) (kdexv1alpha1.ConditionReason, string, error) {
	if parent == nil {
		return "", "", nil
	}
	if parent.Spec.HostRef.Name != page.Spec.HostRef.Name {
		return parentPageHostMismatchReason, fmt.Sprintf(
			"parent KDexPage %s belongs to host %q, not %q; the page is served but appears in no menu",
			parent.Name, parent.Spec.HostRef.Name, page.Spec.HostRef.Name), nil
	}

	chain := []string{page.Name}
	visited := map[string]bool{page.Name: true}
	cur := parent
	for range parentPageChainLimit {
		if cur.Name == page.Name {
			return parentPageCycleReason, fmt.Sprintf(
				"parentPageRef cycle %s; the page is served but appears in no menu",
				strings.Join(append(chain, page.Name), " -> ")), nil
		}
		// A cycle further up that does not pass through page is reported
		// by the pages on it, not here.
		if visited[cur.Name] {
			return "", "", nil
		}
		visited[cur.Name] = true
		chain = append(chain, cur.Name)

		ref := cur.Spec.ParentPageRef
		if ref == nil || ref.Name == "" {
			return "", "", nil
		}
		var next kdexv1alpha1.KDexPage
		if err := c.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: page.Namespace}, &next); err != nil {
			if errors.IsNotFound(err) {
				return "", "", nil
			}
			return "", "", err
		}
		cur = &next
	}
	return "", "", nil
}

// setParentPageDegraded marks a served page Degraded for a parentPageRef
// problem. It sets only Degraded, so it must run after the reconcile's final
// SetConditions: the page stays Ready, as a host with a route collision does
// (see setRouteCollisionCondition). Ready=False would drop the page from the
// page store and stop serving a route that works.
func setParentPageDegraded(page *kdexv1alpha1.KDexPage, reason kdexv1alpha1.ConditionReason, msg string) {
	if reason == "" {
		return
	}
	kdexv1alpha1.SetConditions(
		&page.Status.Conditions,
		kdexv1alpha1.ConditionStatuses{Degraded: metav1.ConditionTrue},
		reason,
		msg,
	)
}

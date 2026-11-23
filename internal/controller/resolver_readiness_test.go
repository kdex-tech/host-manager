package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A referrer blocked on a reference that is not Ready carries the reason on
// ITS OWN conditions, naming the reference (#300). It stays Ready=Unknown, not
// False: a page whose Ready is False is dropped from the host's page store,
// and a wait on a dependency is not a reason to stop serving the last good
// render.
func TestResolveKDexObjectReference_NotReadyMarksTheReferrer(t *testing.T) {
	withReferenceNamespaces(t)
	scheme := functionTestScheme(t)
	app := &kdexv1alpha1.KDexApp{ObjectMeta: metav1.ObjectMeta{Name: "app-admin", Namespace: "dev"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(app).Build()

	page := &kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "dev"}}
	var conditions []metav1.Condition
	obj, shouldReturn, res, err := ResolveKDexObjectReference(context.Background(), c, page, &conditions,
		&kdexv1alpha1.KDexObjectReference{Kind: "KDexApp", Name: "app-admin"}, 7)

	require.NoError(t, err)
	assert.True(t, shouldReturn)
	assert.NotNil(t, obj)
	assert.EqualValues(t, 7, res.RequeueAfter)

	degraded := meta.FindStatusCondition(conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, degraded, "the referrer must carry the not-ready reason")
	assert.Equal(t, metav1.ConditionTrue, degraded.Status)
	assert.Equal(t, string(referenceNotReadyReason), degraded.Reason)
	assert.Equal(t, "referenced KDexApp app-admin is not ready", degraded.Message)

	ready := meta.FindStatusCondition(conditions, string(kdexv1alpha1.ConditionTypeReady))
	require.NotNil(t, ready)
	assert.Equal(t, metav1.ConditionUnknown, ready.Status)

	var stored kdexv1alpha1.KDexApp
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "app-admin", Namespace: "dev"}, &stored))
	assert.Empty(t, stored.Status.Conditions, "the referenced object is never written")
}

// A parent page need only exist (#300): a child reads nothing its parent's
// reconcile computes, and requiring the parent Ready is what closed the
// rewrite-parent/child cycle.
func TestResolvePage_ParentNeedOnlyExist(t *testing.T) {
	scheme := functionTestScheme(t)
	parent := &kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: "group", Namespace: "dev"}}
	meta.SetStatusCondition(&parent.Status.Conditions, metav1.Condition{
		Type: string(kdexv1alpha1.ConditionTypeReady), Status: metav1.ConditionUnknown, Reason: "Reconciling",
	})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent).Build()

	child := &kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "dev"}}
	var conditions []metav1.Condition
	got, shouldReturn, _, err := ResolvePage(context.Background(), c, child, &conditions,
		&corev1.LocalObjectReference{Name: "group"}, 0)

	require.NoError(t, err)
	assert.False(t, shouldReturn)
	require.NotNil(t, got)
	assert.Equal(t, "group", got.Name)
	assert.Empty(t, conditions)
}

// A missing parent still blocks, and says so.
func TestResolvePage_MissingParentDegradesTheChild(t *testing.T) {
	scheme := functionTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	child := &kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: "child", Namespace: "dev"}}
	var conditions []metav1.Condition
	_, shouldReturn, _, err := ResolvePage(context.Background(), c, child, &conditions,
		&corev1.LocalObjectReference{Name: "group"}, 0)

	require.NoError(t, err)
	assert.True(t, shouldReturn)
	assert.True(t, meta.IsStatusConditionTrue(conditions, string(kdexv1alpha1.ConditionTypeDegraded)))
	assert.True(t, meta.IsStatusConditionFalse(conditions, string(kdexv1alpha1.ConditionTypeReady)))
}

// degradedTransition reports a Degraded message only when it is new relative
// to the persisted status, so the default-level log fires once per transition
// and not on every requeue.
func TestDegradedTransition(t *testing.T) {
	degraded := func(status metav1.ConditionStatus, msg string) []metav1.Condition {
		return []metav1.Condition{{Type: string(kdexv1alpha1.ConditionTypeDegraded), Status: status, Reason: "R", Message: msg}}
	}

	msg, ok := degradedTransition(nil, degraded(metav1.ConditionTrue, "referenced KDexApp a is not ready"))
	assert.True(t, ok)
	assert.Equal(t, "referenced KDexApp a is not ready", msg)

	_, ok = degradedTransition(degraded(metav1.ConditionTrue, "m"), degraded(metav1.ConditionTrue, "m"))
	assert.False(t, ok, "an unchanged Degraded message is not a transition")

	msg, ok = degradedTransition(degraded(metav1.ConditionTrue, "m"), degraded(metav1.ConditionTrue, "n"))
	assert.True(t, ok)
	assert.Equal(t, "n", msg)

	_, ok = degradedTransition(degraded(metav1.ConditionTrue, "m"), degraded(metav1.ConditionFalse, "ok"))
	assert.False(t, ok, "clearing Degraded is not logged as a degradation")
}

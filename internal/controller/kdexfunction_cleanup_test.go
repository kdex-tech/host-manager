package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/deploy"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// functionTestScheme is a scheme for fake-client KDexFunction reconciler
// tests: the core and batch kinds plus kdex.dev.
func functionTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, kdexv1alpha1.AddToScheme(scheme))
	return scheme
}

// cleanupJobs with a keep name deletes every finished deployer Job the
// function controls but that one, whatever its generation label, so the Jobs
// an adaptor bump leaves (same function generation, new name) are reaped. A
// running Job is never touched, nor is a Job the function does not control,
// even one carrying its labels. See #282.
func TestCleanupJobs_KeepsOnlyTheCurrentDeployerJob(t *testing.T) {
	scheme := functionTestScheme(t)

	fn := &kdexv1alpha1.KDexFunction{ObjectMeta: metav1.ObjectMeta{Name: "billing", Namespace: "dev", Generation: 3, UID: "fn-uid"}}
	other := &kdexv1alpha1.KDexFunction{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "dev", UID: "other-uid"}}
	job := func(name string, owner *kdexv1alpha1.KDexFunction, gen string, succeeded, active int32) *batchv1.Job {
		j := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "dev", Labels: map[string]string{
				deploy.LabelApp: deploy.AppDeployer, deploy.LabelFunction: owner.Name, internal.ANNOTATION_GENERATION: gen,
			}},
			Status: batchv1.JobStatus{Succeeded: succeeded, Active: active},
		}
		require.NoError(t, controllerutil.SetControllerReference(owner, j, scheme))
		return j
	}
	foreign := job("billing-deployer-3-foreign", fn, "1", 1, 0)
	foreign.OwnerReferences = nil // carries billing's labels, but billing does not control it
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		job("billing-deployer-3-current", fn, "3", 1, 0),
		job("billing-deployer-3-oldadaptor", fn, "3", 1, 0),
		job("billing-deployer-2-oldgen", fn, "2", 1, 0),
		job("billing-deployer-3-running", fn, "3", 0, 1),
		job("other-deployer-3-x", other, "3", 1, 0),
		foreign,
	).Build()
	r := &KDexFunctionReconciler{Client: cl, Scheme: scheme}

	require.NoError(t, r.cleanupJobs(context.Background(), fn, deploy.AppDeployer, "billing-deployer-3-current"))

	var left batchv1.JobList
	require.NoError(t, cl.List(context.Background(), &left, client.InNamespace("dev")))
	var names []string
	for _, j := range left.Items {
		names = append(names, j.Name)
	}
	assert.ElementsMatch(t, []string{
		"billing-deployer-3-current", "billing-deployer-3-running", "other-deployer-3-x", "billing-deployer-3-foreign",
	}, names)
}

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
)

// cleanupJobs with a keep name deletes every finished deployer Job but that
// one, whatever its generation label, so the Jobs an adaptor bump leaves
// (same function generation, new name) are reaped. A running Job is never
// touched, and another function's Jobs are not this function's. See #282.
func TestCleanupJobs_KeepsOnlyTheCurrentDeployerJob(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, kdexv1alpha1.AddToScheme(scheme))

	fn := &kdexv1alpha1.KDexFunction{ObjectMeta: metav1.ObjectMeta{Name: "billing", Namespace: "dev", Generation: 3}}
	job := func(name, fnName, gen string, succeeded, active int32) *batchv1.Job {
		return &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "dev", Labels: map[string]string{
				"app": "deployer", "function": fnName, internal.ANNOTATION_GENERATION: gen,
			}},
			Status: batchv1.JobStatus{Succeeded: succeeded, Active: active},
		}
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		job("billing-deployer-3-current", "billing", "3", 1, 0),
		job("billing-deployer-3-oldadaptor", "billing", "3", 1, 0),
		job("billing-deployer-2-oldgen", "billing", "2", 1, 0),
		job("billing-deployer-3-running", "billing", "3", 0, 1),
		job("other-deployer-3-x", "other", "3", 1, 0),
	).Build()
	r := &KDexFunctionReconciler{Client: cl, Scheme: scheme}

	require.NoError(t, r.cleanupJobs(context.Background(), fn, "deployer", "billing-deployer-3-current"))

	var left batchv1.JobList
	require.NoError(t, cl.List(context.Background(), &left, client.InNamespace("dev")))
	var names []string
	for _, j := range left.Items {
		names = append(names, j.Name)
	}
	assert.ElementsMatch(t, []string{"billing-deployer-3-current", "billing-deployer-3-running", "other-deployer-3-x"}, names)
}

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// The deployer Job and observer CronJob run as the function-deployer
// ServiceAccount, never as host-manager's own.
func TestDeployer_UsesFunctionDeployerServiceAccount(t *testing.T) {
	r := &KDexFunctionReconciler{}
	hc := handlerContext{
		serviceAccount:         "rsi-dev",
		deployerServiceAccount: "rsi-dev-function-deployer",
	}
	assert.Equal(t, "rsi-dev-function-deployer", r.deployer(hc).ServiceAccount)
}

// An old chart does not set FUNCTION_DEPLOYER_SERVICE_ACCOUNT: the function is
// marked Degraded and nothing is deployed.
func TestRefuseMissingDeployerServiceAccount(t *testing.T) {
	r := &KDexFunctionReconciler{}
	hc := handlerContext{function: &kdexv1alpha1.KDexFunction{}, serviceAccount: "rsi-dev"}

	require.True(t, r.refuseMissingDeployerServiceAccount(hc))
	cond := meta.FindStatusCondition(hc.function.Status.Conditions, "Degraded")
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Equal(t, "FUNCTION_DEPLOYER_SERVICE_ACCOUNT is not set; upgrade the host-manager chart", cond.Message)

	hc.deployerServiceAccount = "rsi-dev-function-deployer"
	assert.False(t, r.refuseMissingDeployerServiceAccount(hc))
}

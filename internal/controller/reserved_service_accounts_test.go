package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestReservedServiceAccount(t *testing.T) {
	labelled := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Labels: map[string]string{"app.kubernetes.io/name": "host-manager"}}}
	plain := &corev1.ServiceAccount{}

	tests := []struct {
		name    string
		sa      string
		account *corev1.ServiceAccount
		want    bool
	}{
		{"installer", InstallerServiceAccountName, nil, true},
		{"host-manager", "rsi-dev", nil, true},
		{"deployer", "rsi-dev-function-deployer", nil, true},
		{"labelled", "other-host", labelled, true},
		{"builder", "kdex-builder", plain, false},
		{"default", "default", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, reservedServiceAccount(tt.sa, "rsi-dev", "rsi-dev-function-deployer", tt.account))
		})
	}
}

// With no build ServiceAccount anywhere, the build must not fall back to
// host-manager's own: the function is Degraded and no kpack Image exists.
func TestBuild_EmptyServiceAccountRefused(t *testing.T) {
	scheme := functionTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &KDexFunctionReconciler{Client: c, Scheme: scheme}
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "dev"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			Origin: &kdexv1alpha1.FunctionOrigin{
				Source: &kdexv1alpha1.Source{Repository: "https://example.com/r.git", Revision: "main"},
			},
		},
	}
	hc := handlerContext{
		ctx:            context.Background(),
		function:       fn,
		serviceAccount: "rsi-dev",
		faasAdaptorSpec: kdexv1alpha1.KDexFaaSAdaptorSpec{
			DefaultBuilderGenerator: "tiny/go",
			Builders: []kdexv1alpha1.Builder{{
				Name:       "tiny",
				Languages:  []string{"go"},
				BuilderRef: kdexv1alpha1.KDexObjectReference{Kind: "ClusterBuilder", Name: "tiny-builder"},
			}},
		},
	}

	_, err := r.handleSourceAvailable(hc)
	require.NoError(t, err)

	cond := meta.FindStatusCondition(fn.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, cond)
	assert.Equal(t, metav1.ConditionTrue, cond.Status)
	assert.Contains(t, cond.Message, "no build ServiceAccount")

	images := &unstructured.UnstructuredList{}
	images.SetAPIVersion("kpack.io/v1alpha2")
	images.SetKind("ImageList")
	require.NoError(t, c.List(context.Background(), images))
	assert.Empty(t, images.Items)
}

// A faasAdaptorRef into a namespace the host does not list is refused: the
// referrer goes Degraded and nothing (no Job) is created. The privilege
// redesign relies on this to keep the deployer SA from running foreign specs.
func TestFaaSAdaptor_OtherNamespaceRefused(t *testing.T) {
	withReferenceNamespaces(t)
	scheme := functionTestScheme(t)
	adaptor := &kdexv1alpha1.KDexFaaSAdaptor{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "other"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(adaptor).Build()

	internalHost := &kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev"},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: kdexv1alpha1.KDexHostSpec{
				FaaSAdaptorRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexFaaSAdaptor", Name: "a", Namespace: "other"},
			},
		},
	}
	var conditions []metav1.Condition
	_, shouldReturn, _, err := ResolveOrDefaultFaaSAdaptor(context.Background(), c, internalHost, &conditions, internalHost, 0)

	require.Error(t, err)
	assert.True(t, shouldReturn)
	degraded := meta.FindStatusCondition(conditions, string(kdexv1alpha1.ConditionTypeDegraded))
	require.NotNil(t, degraded)
	assert.Contains(t, degraded.Message, "spec.referenceNamespaces")

	jobs := &batchv1.JobList{}
	require.NoError(t, c.List(context.Background(), jobs))
	assert.Empty(t, jobs.Items)
}

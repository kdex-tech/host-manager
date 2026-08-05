package deploy

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestDeploy_SteersDeployerJobPodViaJobSchedulingFields is the wire-up for
// kdex-tech/host-manager#164 (consuming the kdex-crds Deployer.JobNodeSelector /
// JobTolerations fields): the deployer JOB pod's own PodSpec must carry those
// fields so operators can steer the deployer Job onto a specific node pool on a
// cluster whose pools are all tainted by purpose. Deployer.NodeSelector /
// Tolerations are deliberately NOT the source here — those are payload forwarded
// to the Knative runtime pod, a different pod entirely. Mirrors
// TestObserve_SteersObserverPodsViaNodeSelectorAndTolerations.
func TestDeploy_SteersDeployerJobPodViaJobSchedulingFields(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, batchv1.AddToScheme, kdexv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	tolerations := []corev1.Toleration{
		{Key: "component", Operator: corev1.TolerationOpEqual, Value: "workload", Effect: corev1.TaintEffectNoSchedule},
	}
	nodeSelector := map[string]string{"kubernetes.io/arch": "arm64"}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "user-service-admin", Namespace: "dev", Generation: 3, UID: "fn-uid"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "rsi-dev"},
			API:     kdexv1alpha1.API{BasePath: "/v1/admin"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			KDexObjectStatus: kdexv1alpha1.KDexObjectStatus{
				Attributes: map[string]string{"faasAdaptor.generation": "1"},
			},
			Executable: &kdexv1alpha1.Executable{Image: "registry.example/admin@sha256:abcd"},
		},
	}

	host := kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{Name: "rsi-dev", Namespace: "dev"},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: kdexv1alpha1.KDexHostSpec{
				Routing: kdexv1alpha1.Routing{Scheme: "https", Domains: []string{"dev.knowdrive.ai"}},
			},
		},
	}

	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		FaaSAdaptor: kdexv1alpha1.KDexFaaSAdaptorSpec{
			Deployer: kdexv1alpha1.Deployer{
				Image:           "ghcr.io/kdex-tech/knative-deployer:test",
				JobNodeSelector: nodeSelector,
				JobTolerations:  tolerations,
			},
		},
		Host:           host,
		Scheme:         scheme,
		ServiceAccount: "deployer-sa",
	}

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	podSpec := job.Spec.Template.Spec
	if podSpec.NodeSelector["kubernetes.io/arch"] != "arm64" {
		t.Errorf("deployer Job NodeSelector not propagated from JobNodeSelector: %+v", podSpec.NodeSelector)
	}
	if len(podSpec.Tolerations) != 1 ||
		podSpec.Tolerations[0].Key != "component" ||
		podSpec.Tolerations[0].Value != "workload" ||
		podSpec.Tolerations[0].Effect != corev1.TaintEffectNoSchedule {
		t.Errorf("deployer Job Tolerations not propagated from JobTolerations: %+v", podSpec.Tolerations)
	}
}

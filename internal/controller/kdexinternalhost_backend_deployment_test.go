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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtimeschemepkg "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newBackendTemplate produces a minimal DeploymentSpec suitable as a memoized
// backend template. Tests mutate the returned object to simulate chart-side
// template changes between reconciles.
func newBackendTemplate(containerPort int32, runAsNonRoot bool) *appsv1.DeploymentSpec {
	return &appsv1.DeploymentSpec{
		Replicas: ptr.To[int32](1),
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{},
			},
			Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: ptr.To(runAsNonRoot),
				},
				Containers: []corev1.Container{{
					Name: "placeholder",
					Ports: []corev1.ContainerPort{{
						Name:          "http",
						ContainerPort: containerPort,
						Protocol:      corev1.ProtocolTCP,
					}},
				}},
			},
		},
	}
}

var _ = Describe("createOrUpdateBackendDeployment template propagation", func() {
	const (
		hostName       = "test-host"
		hostNamespace  = "default"
		deploymentName = "test-host-backend"
	)

	ctx := context.Background()

	buildScheme := func() *runtimeschemepkg.Scheme {
		s := runtimeschemepkg.NewScheme()
		Expect(appsv1.AddToScheme(s)).To(Succeed())
		Expect(corev1.AddToScheme(s)).To(Succeed())
		Expect(kdexv1alpha1.AddToScheme(s)).To(Succeed())
		return s
	}

	internalHost := func() *kdexv1alpha1.KDexInternalHost {
		return &kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{
				Name:      hostName,
				Namespace: hostNamespace,
				UID:       "test-host-uid",
			},
		}
	}

	resolved := resolvedBackend{
		Backend: kdexv1alpha1.Backend{
			IngressPath: "/",
			ServerImage: "ghcr.io/example/backend:test",
		},
		Kind: "KDexHost",
		Name: hostName,
	}

	// markAsCreated stamps CreationTimestamp on the live Deployment so the
	// next createOrUpdateBackendDeployment call enters the "post-create"
	// path. fake.NewClientBuilder doesn't set CreationTimestamp on Create
	// the way a real API server does, so the IsZero gate would otherwise
	// always evaluate true in unit tests and mask the bug.
	markAsCreated := func(c client.Client, name, namespace string) {
		var d appsv1.Deployment
		Expect(c.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, &d)).To(Succeed())
		d.CreationTimestamp = metav1.NewTime(time.Now())
		Expect(c.Update(ctx, &d)).To(Succeed())
	}

	It("propagates a containerPort change in the memoized template to the live Deployment", func() {
		scheme := buildScheme()
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &KDexInternalHostReconciler{Client: c, Scheme: scheme}

		// First reconcile: template carries port 8080.
		r.memoizedDeployment = newBackendTemplate(8080, false)
		_, err := r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		markAsCreated(c, deploymentName, hostNamespace)

		var deployed appsv1.Deployment
		Expect(c.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: hostNamespace}, &deployed)).To(Succeed())
		Expect(deployed.Spec.Template.Spec.Containers[0].Ports).To(HaveLen(1))
		Expect(deployed.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(int32(8080)))

		// Simulate a chart upgrade: memoized template now carries port 9090.
		r.memoizedDeployment = newBackendTemplate(9090, true)

		_, err = r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(c.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: hostNamespace}, &deployed)).To(Succeed())
		Expect(deployed.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort).To(Equal(int32(9090)),
			"kdex-tech/host-manager#17: containerPort must follow memoized template on subsequent reconciles")
	})

	It("propagates a securityContext change in the memoized template to the live Deployment", func() {
		scheme := buildScheme()
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &KDexInternalHostReconciler{Client: c, Scheme: scheme}

		r.memoizedDeployment = newBackendTemplate(8080, false)
		_, err := r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		markAsCreated(c, deploymentName, hostNamespace)

		// Chart upgrade flips RunAsNonRoot to true.
		r.memoizedDeployment = newBackendTemplate(8080, true)

		_, err = r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		var deployed appsv1.Deployment
		Expect(c.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: hostNamespace}, &deployed)).To(Succeed())
		Expect(deployed.Spec.Template.Spec.SecurityContext).NotTo(BeNil())
		Expect(deployed.Spec.Template.Spec.SecurityContext.RunAsNonRoot).NotTo(BeNil())
		Expect(*deployed.Spec.Template.Spec.SecurityContext.RunAsNonRoot).To(BeTrue(),
			"kdex-tech/host-manager#17: SecurityContext.RunAsNonRoot must follow memoized template on subsequent reconciles")
	})

	It("preserves the existing immutable Selector on subsequent reconciles", func() {
		scheme := buildScheme()
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &KDexInternalHostReconciler{Client: c, Scheme: scheme}

		r.memoizedDeployment = newBackendTemplate(8080, false)
		_, err := r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		markAsCreated(c, deploymentName, hostNamespace)

		var first appsv1.Deployment
		Expect(c.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: hostNamespace}, &first)).To(Succeed())
		initialSelector := first.Spec.Selector.DeepCopy()

		// Second reconcile with a template carrying empty selector labels —
		// must not clobber the existing Selector (it's immutable post-create;
		// the real API server would reject the update).
		r.memoizedDeployment = newBackendTemplate(9090, false)
		_, err = r.createOrUpdateBackendDeployment(ctx, internalHost(), deploymentName, resolved, nil)
		Expect(err).NotTo(HaveOccurred())

		var second appsv1.Deployment
		Expect(c.Get(ctx, client.ObjectKey{Name: deploymentName, Namespace: hostNamespace}, &second)).To(Succeed())
		Expect(second.Spec.Selector).To(Equal(initialSelector))
	})
})

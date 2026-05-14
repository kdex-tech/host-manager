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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var _ = Describe("KDexInternalHost Controller", func() {
	Context("When reconciling a resource", func() {
		const namespace = "default"

		ctx := context.Background()

		AfterEach(func() {
			cleanupResources(namespace)
		})

		It("should successfully reconcile the resource", func() {
			resource := &kdexv1alpha1.KDexInternalHost{
				ObjectMeta: metav1.ObjectMeta{
					Name:      focalHost,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexInternalHostSpec{
					KDexHostSpec: kdexv1alpha1.KDexHostSpec{
						BrandName:    "KDex Tech",
						DevMode:      true,
						ModulePolicy: kdexv1alpha1.LooseModulePolicy,
						Organization: "KDex Tech Inc.",
						Routing: kdexv1alpha1.Routing{
							Domains: []string{"foo.bar"},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)
		})

		It("should produce an HTTPRoute when routing.strategy is HTTPRoute", func() {
			gatewayNamespace := gatewayv1.Namespace("traefik")
			resource := &kdexv1alpha1.KDexInternalHost{
				ObjectMeta: metav1.ObjectMeta{
					Name:      focalHost,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexInternalHostSpec{
					KDexHostSpec: kdexv1alpha1.KDexHostSpec{
						BrandName:    "KDex Tech",
						DevMode:      true,
						ModulePolicy: kdexv1alpha1.LooseModulePolicy,
						Organization: "KDex Tech Inc.",
						Routing: kdexv1alpha1.Routing{
							Domains:  []string{"foo.bar", "baz.bar"},
							Strategy: kdexv1alpha1.HTTPRouteRoutingStrategy,
							ParentRefs: []gatewayv1.ParentReference{
								{
									Name:      "rsi-gateway",
									Namespace: &gatewayNamespace,
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			// The controller names the HTTPRoute after the InternalHost.
			httpRoute := &gatewayv1.HTTPRoute{}
			Eventually(func(g Gomega) {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      focalHost,
					Namespace: namespace,
				}, httpRoute)
				g.Expect(err).NotTo(HaveOccurred())
			}, "5s").Should(Succeed())

			By("setting hostnames from routing.domains")
			Expect(httpRoute.Spec.Hostnames).To(Equal([]gatewayv1.Hostname{
				"foo.bar", "baz.bar",
			}))

			By("propagating CR-level parentRefs ahead of any chart default")
			Expect(httpRoute.Spec.ParentRefs).To(HaveLen(1))
			Expect(httpRoute.Spec.ParentRefs[0].Name).To(Equal(gatewayv1.ObjectName("rsi-gateway")))
			Expect(httpRoute.Spec.ParentRefs[0].Namespace).NotTo(BeNil())
			Expect(*httpRoute.Spec.ParentRefs[0].Namespace).To(Equal(gatewayNamespace))

			By("producing a catch-all `/` rule pointing at the controller service")
			Expect(httpRoute.Spec.Rules).NotTo(BeEmpty())
			catchAll := httpRoute.Spec.Rules[len(httpRoute.Spec.Rules)-1]
			Expect(catchAll.Matches).To(HaveLen(1))
			Expect(catchAll.Matches[0].Path).NotTo(BeNil())
			Expect(catchAll.Matches[0].Path.Value).NotTo(BeNil())
			Expect(*catchAll.Matches[0].Path.Value).To(Equal("/"))
			Expect(catchAll.BackendRefs).To(HaveLen(1))
			Expect(catchAll.BackendRefs[0].Name).To(Equal(gatewayv1.ObjectName(focalHost)))

			By("owning the HTTPRoute via controller reference for GC")
			Expect(httpRoute.OwnerReferences).To(HaveLen(1))
			Expect(httpRoute.OwnerReferences[0].Name).To(Equal(focalHost))
			Expect(httpRoute.OwnerReferences[0].Kind).To(Equal("KDexInternalHost"))
		})
	})
})

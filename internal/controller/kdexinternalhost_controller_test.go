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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

		// The warm-up list is pinned by the utilityPage.Consent.generation
		// status attribute, which the host writes only for listed types. The
		// {.Spec.ConsentRef} watch is not pinned here: indexing happens in the
		// utility page reconciler whether or not the host watches the page.
		It("should index a Consent utility page the host references", func() {
			consentPageName := focalHost + "-consent"

			addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
				ObjectMeta: metav1.ObjectMeta{Name: "consent-archetype", Namespace: namespace},
				Spec: kdexv1alpha1.KDexPageArchetypeSpec{
					Content: "<main>[[ .Content.main ]]</main>",
				},
			})
			assertResourceReady(
				ctx, k8sClient, "consent-archetype", namespace,
				&kdexv1alpha1.KDexPageArchetype{}, true)

			Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexInternalUtilityPage{
				ObjectMeta: metav1.ObjectMeta{Name: consentPageName, Namespace: namespace},
				Spec: kdexv1alpha1.KDexInternalUtilityPageSpec{
					HostRef: corev1.LocalObjectReference{Name: focalHost},
					KDexUtilityPageSpec: kdexv1alpha1.KDexUtilityPageSpec{
						Type: kdexv1alpha1.ConsentUtilityPageType,
						ContentEntries: []kdexv1alpha1.ContentEntry{{
							Slot: "main",
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "[[ .Extra.consent.Block ]]",
							},
						}},
						PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
							Kind: "KDexPageArchetype",
							Name: "consent-archetype",
						},
					},
				},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexInternalHost{
				ObjectMeta: metav1.ObjectMeta{Name: focalHost, Namespace: namespace},
				Spec: kdexv1alpha1.KDexInternalHostSpec{
					ConsentRef: &corev1.LocalObjectReference{Name: consentPageName},
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
			})).To(Succeed())

			Eventually(func() string {
				return hostHandler.GetUtilityPageHandler(kdexv1alpha1.ConsentUtilityPageType).Name
			}, "10s").Should(Equal(consentPageName))

			assertResourceReady(
				ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			By("warming up the Consent utility page with the others")
			Eventually(func(g Gomega) {
				internalHost := &kdexv1alpha1.KDexInternalHost{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, internalHost)).To(Succeed())
				g.Expect(internalHost.Status.Attributes).To(HaveKey("utilityPage.Consent.generation"))
			}, "5s").Should(Succeed())
		})
	})
})

var _ = Describe("KDexInternalHost SecretSelector", func() {
	Context("When spec.secretSelector matches Secrets", func() {
		const namespace = "default"

		ctx := context.Background()

		AfterEach(func() {
			cleanupResources(namespace)
			// also delete any test Secrets
			secretList := &corev1.SecretList{}
			Expect(k8sClient.List(ctx, secretList, &client.ListOptions{Namespace: namespace})).To(Succeed())
			for i := range secretList.Items {
				_ = k8sClient.Delete(ctx, &secretList.Items[i])
			}
		})

		It("resolves Secrets that carry the host's label", func() {
			By("creating a labeled Secret in the host's namespace")
			matched := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "matched-secret",
					Namespace: namespace,
					Labels:    map[string]string{"kdex.dev/host": focalHost},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"k": []byte("v")},
			}
			Expect(k8sClient.Create(ctx, matched)).To(Succeed())

			By("creating an unlabeled Secret in the same namespace")
			ignored := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ignored-secret",
					Namespace: namespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"k": []byte("v")},
			}
			Expect(k8sClient.Create(ctx, ignored)).To(Succeed())

			By("creating the KDexInternalHost with the matching selector")
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
						SecretSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kdex.dev/host": focalHost},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			By("populating status.attributes for the matched Secret only")
			Eventually(func(g Gomega) {
				ih := &kdexv1alpha1.KDexInternalHost{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, ih)).To(Succeed())
				g.Expect(ih.Status.Attributes).To(HaveKey("matched-secret.secret.generation"))
				g.Expect(ih.Status.Attributes).NotTo(HaveKey("ignored-secret.secret.generation"))
			}, "5s").Should(Succeed())
		})

		It("re-reconciles when a Secret is labeled to match", func() {
			By("creating an initially-unlabeled Secret")
			s := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rotated-secret",
					Namespace: namespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"k": []byte("v")},
			}
			Expect(k8sClient.Create(ctx, s)).To(Succeed())

			By("creating the host with a selector that doesn't yet match")
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
						SecretSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kdex.dev/host": focalHost},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			By("confirming the Secret is not initially in status.attributes")
			ih := &kdexv1alpha1.KDexInternalHost{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, ih)).To(Succeed())
			Expect(ih.Status.Attributes).NotTo(HaveKey("rotated-secret.secret.generation"))

			By("labeling the Secret to match the host's selector")
			updated := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "rotated-secret", Namespace: namespace}, updated)).To(Succeed())
			if updated.Labels == nil {
				updated.Labels = map[string]string{}
			}
			updated.Labels["kdex.dev/host"] = focalHost
			Expect(k8sClient.Update(ctx, updated)).To(Succeed())

			By("expecting the Secret watch to trigger a reconcile that picks the Secret up")
			Eventually(func(g Gomega) {
				ih := &kdexv1alpha1.KDexInternalHost{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, ih)).To(Succeed())
				g.Expect(ih.Status.Attributes).To(HaveKey("rotated-secret.secret.generation"))
			}, "5s").Should(Succeed())
		})
	})
})

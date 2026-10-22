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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
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

		// Consent is in the utility page loop (it does not block warm-up, see
		// the next spec); that is pinned by the utilityPage.Consent.generation
		// status attribute, which the host writes only for listed types and,
		// for Consent, only while its handler is registered, with the internal
		// page's generation. The {.Spec.ConsentRef} watch is not pinned here:
		// indexing happens in the utility page reconciler whether or not the
		// host watches the page.
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

			By("recording the Consent utility page's generation with the others")
			consentPage := &kdexv1alpha1.KDexInternalUtilityPage{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: consentPageName, Namespace: namespace}, consentPage)).To(Succeed())
			Expect(consentPage.Generation).NotTo(BeZero())
			Eventually(func(g Gomega) {
				internalHost := &kdexv1alpha1.KDexInternalHost{}
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, internalHost)).To(Succeed())
				g.Expect(internalHost.Status.Attributes).To(HaveKeyWithValue("utilityPage.Consent.generation", fmt.Sprintf("%d", consentPage.Generation)))
			}, "5s").Should(Succeed())
		})

		// The consent flow falls back to the built-in page when the host has
		// no Consent handler, so a Consent page that never registers (here its
		// archetype does not exist) must not hold the host back from Ready.
		It("should not wait for a Consent utility page that never registers", func() {
			consentPageName := focalHost + "-consent"

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
							Name: "no-such-archetype",
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

			assertResourceReady(
				ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			Expect(hostHandler.GetUtilityPageHandler(kdexv1alpha1.ConsentUtilityPageType).Name).To(BeEmpty())
			internalHost := &kdexv1alpha1.KDexInternalHost{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, internalHost)).To(Succeed())
			Expect(internalHost.Status.Attributes).NotTo(HaveKey("utilityPage.Consent.generation"))
		})
	})
})

// #246: a page imports only the packages its own CRs declare, while the
// host-wide aggregate still drives the packages image (the KIPR).
var _ = Describe("KDexInternalHost page imports", func() {
	const namespace = "default"

	ctx := context.Background()

	AfterEach(func() {
		cleanupResources(namespace)
	})

	It("narrows each page's head imports to its own packages but keeps the full aggregate in the KIPR", func() {
		newApp := func(name, pkg string) {
			app := &kdexv1alpha1.KDexApp{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: kdexv1alpha1.KDexAppSpec{
					CustomElements: []kdexv1alpha1.CustomElement{{Name: name + "-el", Description: name}},
					PackageReference: kdexv1alpha1.PackageReference{
						Name:    pkg,
						Version: "1.0.0",
					},
				},
			}
			Expect(k8sClient.Create(ctx, app)).To(Succeed())
			// No KDexApp reconciler runs in this suite; mark it Ready the
			// way the real one would so pages can resolve it.
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, app)).To(Succeed())
				meta.SetStatusCondition(&app.Status.Conditions, metav1.Condition{
					Type:   string(kdexv1alpha1.ConditionTypeReady),
					Status: metav1.ConditionTrue,
					Reason: "Test",
				})
				g.Expect(k8sClient.Status().Update(ctx, app)).To(Succeed())
			}, "5s").Should(Succeed())
		}
		newApp("app-a", "@x/app-a")
		newApp("app-b", "@x/app-b")

		Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexScriptLibrary{
			ObjectMeta: metav1.ObjectMeta{Name: "host-lib", Namespace: namespace},
			Spec: kdexv1alpha1.KDexScriptLibrarySpec{
				PackageReference: &kdexv1alpha1.PackageReference{Name: "@x/host-lib", Version: "1.0.0"},
			},
		})).To(Succeed())
		assertResourceReady(ctx, k8sClient, "host-lib", namespace, &kdexv1alpha1.KDexScriptLibrary{}, true)

		addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
			ObjectMeta: metav1.ObjectMeta{Name: "imports-archetype", Namespace: namespace},
			Spec:       kdexv1alpha1.KDexPageArchetypeSpec{Content: "<main>[[ .Content.main ]]</main>"},
		})
		assertResourceReady(ctx, k8sClient, "imports-archetype", namespace, &kdexv1alpha1.KDexPageArchetype{}, true)

		newPage := func(name, basePath, app string) {
			Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{{
						Slot: "main",
						ContentEntryApp: kdexv1alpha1.ContentEntryApp{
							AppRef:            &kdexv1alpha1.KDexObjectReference{Kind: "KDexApp", Name: app},
							CustomElementName: app + "-el",
						},
					}},
					HostRef:          corev1.LocalObjectReference{Name: focalHost},
					Label:            name,
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "imports-archetype"},
					Paths:            kdexv1alpha1.Paths{BasePath: basePath},
				},
			})).To(Succeed())
		}
		newPage("page-a", "/a", "app-a")
		newPage("page-b", "/b", "app-b")

		Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: focalHost, Namespace: namespace},
			Spec: kdexv1alpha1.KDexInternalHostSpec{
				KDexHostSpec: kdexv1alpha1.KDexHostSpec{
					BrandName:        "KDex Tech",
					DevMode:          true,
					ModulePolicy:     kdexv1alpha1.LooseModulePolicy,
					Organization:     "KDex Tech Inc.",
					Routing:          kdexv1alpha1.Routing{Domains: []string{"foo.bar"}},
					ScriptLibraryRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexScriptLibrary", Name: "host-lib"},
				},
			},
		})).To(Succeed())

		By("aggregating both packages into the KIPR")
		kipr := &kdexv1alpha1.KDexInternalPackageReferences{}
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, kipr)).To(Succeed())
			names := []string{}
			for _, pr := range kipr.Spec.PackageReferences {
				names = append(names, pr.Name)
			}
			g.Expect(names).To(ConsistOf("@x/app-a", "@x/app-b", "@x/host-lib"))
		}, "15s").Should(Succeed())

		By("marking the packages image as still building so the host proceeds to SetHost")
		// No KIPR reconciler runs in this suite and there is no registry to
		// pull an importmap from; Ready=False is the "Building" outcome, which
		// continues the host reconcile with an empty importmap.
		Eventually(func(g Gomega) {
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, kipr)).To(Succeed())
			meta.SetStatusCondition(&kipr.Status.Conditions, metav1.Condition{
				Type:   string(kdexv1alpha1.ConditionTypeReady),
				Status: metav1.ConditionFalse,
				Reason: "Building",
			})
			g.Expect(k8sClient.Status().Update(ctx, kipr)).To(Succeed())
		}, "5s").Should(Succeed())

		By("rendering each page head with only its own package")
		var headA, headB string
		Eventually(func(g Gomega) {
			a, okA := hostHandler.Pages.Get("page-a")
			b, okB := hostHandler.Pages.Get("page-b")
			g.Expect(okA && okB).To(BeTrue())
			headA = hostHandler.HeadScriptToHTML(a)
			headB = hostHandler.HeadScriptToHTML(b)
			// The host-scope ref only appears once SetHost has run, so
			// waiting on it keeps the negative assertions below from
			// passing vacuously before the host is installed.
			hostLib := kdexv1alpha1.PackageReference{Name: "@x/host-lib"}
			g.Expect(headA).To(ContainSubstring(hostLib.ToImportStatement()))
			g.Expect(headB).To(ContainSubstring(hostLib.ToImportStatement()))
		}, "15s").Should(Succeed())

		appA := kdexv1alpha1.PackageReference{Name: "@x/app-a"}
		appB := kdexv1alpha1.PackageReference{Name: "@x/app-b"}
		Expect(headA).To(ContainSubstring(appA.ToImportStatement()))
		Expect(headA).NotTo(ContainSubstring(appB.ToImportStatement()))
		Expect(headB).To(ContainSubstring(appB.ToImportStatement()))
		Expect(headB).NotTo(ContainSubstring(appA.ToImportStatement()))
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

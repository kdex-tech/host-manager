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
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage Controller", func() {
	Context("When reconciling a resource", func() {
		const namespace = "default"
		const resourceName = "test-resource"

		ctx := context.Background()

		AfterEach(func() {
			cleanupResources(namespace)
		})

		It("with empty content entries should not succeed", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{},
					HostRef: corev1.LocalObjectReference{
						Name: "non-existent-host",
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).NotTo(Succeed())
		})

		It("with content entries should succeed", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: "non-existent-host",
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
		})

		It("with missing references should not succeed", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)
			addOrUpdateInternalHost(
				ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
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
								Domains: []string{
									"example.com",
								},
							},
						},
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)
		})

		It("with override references", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					OverrideFooterRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageFooter",
						Name: "non-existent-footer",
					},
					OverrideHeaderRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageHeader",
						Name: "non-existent-header",
					},
					OverrideNavigationRefs: map[string]*kdexv1alpha1.KDexObjectReference{
						"main": {
							Kind: "KDexPageNavigation",
							Name: "non-existent-navigation",
						},
					},
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)
			addOrUpdateInternalHost(
				ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
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
								Domains: []string{
									"example.com",
								},
							},
						},
					},
				},
			)
			addOrUpdatePageFooter(ctx, k8sClient,
				kdexv1alpha1.KDexPageFooter{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-footer",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageFooterSpec{
						Content: "<h1>Hello, from down under!</h1>",
					},
				},
			)
			addOrUpdatePageHeader(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageHeader{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-header",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageHeaderSpec{
						Content: "<h1>Hello, from up north!</h1>",
					},
				},
			)
			addOrUpdatePageNavigation(ctx, k8sClient,
				kdexv1alpha1.KDexPageNavigation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-navigation",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageNavigationSpec{
						Content: "<h1>Hello, from up north!</h1>",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)
		})

		It("with parent page reference", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					ParentPageRef: &corev1.LocalObjectReference{
						Name: "non-existent-page-binding",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/child",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)
			addOrUpdateInternalHost(
				ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
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
								Domains: []string{
									"example.com",
								},
							},
						},
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			referencedPage := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "non-existent-page-binding",
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/",
					},
				},
			}

			Expect(k8sClient.Create(ctx, referencedPage)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)
		})

		It("updates when a dependency is updated", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					OverrideHeaderRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageHeader",
						Name: "non-existent-header",
					},
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)
			addOrUpdateInternalHost(
				ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
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
								Domains: []string{
									"example.com",
								},
							},
						},
					},
				},
			)
			addOrUpdatePageHeader(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageHeader{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-header",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageHeaderSpec{
						Content: "BEFORE",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)

			pageHandler, ok := hostHandler.Pages.Get(resource.Name)
			Expect(ok).To(BeTrue())

			Expect(pageHandler.Header).To(Equal("BEFORE"))

			addOrUpdatePageHeader(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageHeader{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-header",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageHeaderSpec{
						Content: "AFTER",
					},
				},
			)

			check := func(g Gomega) {
				pageHandler, ok = hostHandler.Pages.Get(resource.Name)
				g.Expect(ok).To(BeTrue())

				g.Expect(pageHandler.Header).To(Equal("AFTER"))
			}

			Eventually(check).Should(Succeed())
		})

		It("updates when an indirect dependency is updated", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdatePageHeader(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageHeader{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-header",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageHeaderSpec{
						Content: "BEFORE",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, "non-existent-header", namespace,
				&kdexv1alpha1.KDexPageHeader{}, true)

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
						DefaultHeaderRef: &kdexv1alpha1.KDexObjectReference{
							Kind: "KDexPageHeader",
							Name: "non-existent-header",
						},
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, "non-existent-page-archetype", namespace,
				&kdexv1alpha1.KDexPageArchetype{}, true)

			addOrUpdateInternalHost(
				ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
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
								Domains: []string{
									"example.com",
								},
							},
						},
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, focalHost, namespace,
				&kdexv1alpha1.KDexInternalHost{}, true)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)

			pageHandler, ok := hostHandler.Pages.Get(resource.Name)
			Expect(ok).To(BeTrue())

			Expect(pageHandler.Header).To(Equal("BEFORE"))

			addOrUpdatePageHeader(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageHeader{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-header",
						Namespace: namespace,
					},
					Spec: kdexv1alpha1.KDexPageHeaderSpec{
						Content: "AFTER",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, "non-existent-header", namespace,
				&kdexv1alpha1.KDexPageHeader{}, true)

			check := func(g Gomega) {
				pageHandler, ok = hostHandler.Pages.Get(resource.Name)
				g.Expect(ok).To(BeTrue())

				g.Expect(pageHandler.Header).To(Equal("AFTER"))
			}

			Eventually(check).Should(Succeed())
		})

		It("cross namespace reference", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind:      "KDexPageArchetype",
						Name:      "non-existent-page-archetype",
						Namespace: secondNamespace,
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdatePageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "non-existent-page-archetype",
						Namespace: secondNamespace,
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, "non-existent-page-archetype", secondNamespace,
				&kdexv1alpha1.KDexPageArchetype{}, true)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)
		})

		It("cluster reference", func() {
			resource := &kdexv1alpha1.KDexPage{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexPageSpec{
					ContentEntries: []kdexv1alpha1.ContentEntry{
						{
							ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{
								RawHTML: "<h1>Hello, World!</h1>",
							},
							Slot: "main",
						},
					},
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					Label: "foo",
					PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{
						Kind: "KDexClusterPageArchetype",
						Name: "non-existent-page-archetype",
					},
					Paths: kdexv1alpha1.Paths{
						BasePath: "/foo",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, false)

			addOrUpdateClusterPageArchetype(
				ctx, k8sClient,
				kdexv1alpha1.KDexClusterPageArchetype{
					ObjectMeta: metav1.ObjectMeta{
						Name: "non-existent-page-archetype",
					},
					Spec: kdexv1alpha1.KDexPageArchetypeSpec{
						Content: "<h1>Hello, World!</h1>",
					},
				},
			)

			assertResourceReady(
				ctx, k8sClient, "non-existent-page-archetype", "",
				&kdexv1alpha1.KDexClusterPageArchetype{}, true)

			assertResourceReady(
				ctx, k8sClient, resourceName, namespace,
				&kdexv1alpha1.KDexPage{}, true)
		})
	})
})

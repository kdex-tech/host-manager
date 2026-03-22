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
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexInternalTranslation Controller", func() {
	Context("When reconciling a resource", func() {
		const namespace = "default"
		const resourceName = "test-resource"

		ctx := context.Background()

		AfterEach(func() {
			By("Cleanup all the test resource instances")
			cleanupResources(namespace)
		})

		It("should successfully reconcile the resource", func() {
			resource := &kdexv1alpha1.KDexInternalTranslation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: kdexv1alpha1.KDexInternalTranslationSpec{
					HostRef: corev1.LocalObjectReference{
						Name: focalHost,
					},
					KDexTranslationSpec: kdexv1alpha1.KDexTranslationSpec{
						Translations: []kdexv1alpha1.Translation{
							{
								Lang: "en",
								KeysAndValues: map[string]string{
									"key-1": "KEY_1_ENGLISH",
									"key-2": "KEY_2_ENGLISH",
								},
							},
							{
								Lang: "fr",
								KeysAndValues: map[string]string{
									"key-1": "KEY_1_FRENCH",
									"key-2": "KEY_2_FRENCH",
								},
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

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
						InternalTranslationRefs: []corev1.LocalObjectReference{
							{
								Name: resource.Name,
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
				&kdexv1alpha1.KDexInternalTranslation{}, true)

			mp_en := message.NewPrinter(
				language.English,
				message.Catalog(hostHandler.Translations.Catalog()),
			)
			Expect(mp_en.Sprintf("key-1")).To(Equal("KEY_1_ENGLISH"))

			mp_fr := message.NewPrinter(
				language.French,
				message.Catalog(hostHandler.Translations.Catalog()),
			)
			Expect(mp_fr.Sprintf("key-1")).To(Equal("KEY_1_FRENCH"))
		})
	})
})

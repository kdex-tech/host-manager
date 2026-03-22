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
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
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
	})
})

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

// These specs characterize the rule-level CEL added to KDexRole.PolicyRule in
// kdex-crds (STRUCTURED-XOR-OPAQUE, plus the colon-in-opaque-scope
// restriction). They exercise real apiserver admission via envtest, not a
// unit test of Go code. Each deny case asserts both that Create fails AND
// that the error surfaces the specific CEL message, so a CRD lacking the CEL
// (which would just prune the unknown-shaped fields and admit the object)
// would fail these specs rather than passing vacuously.
var _ = Describe("KDexRole PolicyRule CEL validation", func() {
	ctx := context.Background()

	newRole := func(name string, rules []kdexv1alpha1.PolicyRule) *kdexv1alpha1.KDexRole {
		return &kdexv1alpha1.KDexRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: kdexv1alpha1.KDexRoleSpec{
				HostRef: corev1.LocalObjectReference{Name: "foo"},
				Rules:   rules,
			},
		}
	}

	It("admits a structured rule (resources + verbs)", func() {
		role := newRole("kdexrole-admit-structured", []kdexv1alpha1.PolicyRule{
			{
				Resources: []string{"vector_stores"},
				Verbs:     []string{"read"},
			},
		})

		Expect(k8sClient.Create(ctx, role)).To(Succeed())
	})

	It("admits a structured rule with resourceNames", func() {
		role := newRole("kdexrole-admit-structured-resourcenames", []kdexv1alpha1.PolicyRule{
			{
				Resources:     []string{"vector_stores"},
				ResourceNames: []string{"vs_alice"},
				Verbs:         []string{"read"},
			},
		})

		Expect(k8sClient.Create(ctx, role)).To(Succeed())
	})

	It("admits an opaque rule (scopes only)", func() {
		role := newRole("kdexrole-admit-opaque", []kdexv1alpha1.PolicyRule{
			{
				Scopes: []string{"vector_stores_create"},
			},
		})

		Expect(k8sClient.Create(ctx, role)).To(Succeed())
	})

	It("rejects a rule with both resources+verbs and scopes set", func() {
		role := newRole("kdexrole-deny-both", []kdexv1alpha1.PolicyRule{
			{
				Resources: []string{"vector_stores"},
				Verbs:     []string{"read"},
				Scopes:    []string{"x"},
			},
		})

		err := k8sClient.Create(ctx, role)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("either resources+verbs or scopes"))
	})

	It("rejects an empty rule (neither resources+verbs nor scopes)", func() {
		role := newRole("kdexrole-deny-neither", []kdexv1alpha1.PolicyRule{
			{},
		})

		err := k8sClient.Create(ctx, role)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("either resources+verbs or scopes"))
	})

	It("rejects an opaque scope containing a colon", func() {
		role := newRole("kdexrole-deny-colon", []kdexv1alpha1.PolicyRule{
			{
				Scopes: []string{"a:b"},
			},
		})

		err := k8sClient.Create(ctx, role)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("an opaque scope must not contain"))
	})

	It("rejects scopes combined with verbs", func() {
		role := newRole("kdexrole-deny-scopes-with-verbs", []kdexv1alpha1.PolicyRule{
			{
				Scopes: []string{"x"},
				Verbs:  []string{"read"},
			},
		})

		err := k8sClient.Create(ctx, role)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("scopes cannot be combined with verbs or resourceNames"))
	})

	It("rejects resources without verbs", func() {
		role := newRole("kdexrole-deny-resources-no-verbs", []kdexv1alpha1.PolicyRule{
			{
				Resources: []string{"vector_stores"},
			},
		})

		err := k8sClient.Create(ctx, role)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("resources requires verbs"))
	})
})

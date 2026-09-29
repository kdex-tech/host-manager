package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage rewrite-mode admission (CEL)", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	rewritePage := func(name string, mutate func(*kdexv1alpha1.KDexPageSpec)) *kdexv1alpha1.KDexPage {
		p := &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				HostRef: corev1.LocalObjectReference{Name: "some-host"},
				Label:   "alias",
				Paths:   kdexv1alpha1.Paths{BasePath: "/alias"},
				Rewrite: &kdexv1alpha1.RewriteSpec{
					TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "target"},
				},
			},
		}
		if mutate != nil {
			mutate(&p.Spec)
		}
		return p
	}

	It("accepts a minimal rewrite page with no contentEntries", func() {
		Expect(k8sClient.Create(ctx, rewritePage("ok-min", nil))).To(Succeed())
	})

	It("accepts a KDexFunction target with a placeholder path", func() {
		Expect(k8sClient.Create(ctx, rewritePage("ok-fn", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PatternPath = "/alias/{id}"
			s.Rewrite.TargetRef.Kind = "KDexFunction"
			s.Rewrite.Path = "{id}"
		}))).To(Succeed())
	})

	It("rejects rewrite together with contentEntries", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-content", func(s *kdexv1alpha1.KDexPageSpec) {
			s.ContentEntries = []kdexv1alpha1.ContentEntry{{
				ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<p>x</p>"},
				Slot:               "main",
			}}
		}))).NotTo(Succeed())
	})

	It("rejects rewrite together with mimeType/body", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-text", func(s *kdexv1alpha1.KDexPageSpec) {
			s.MimeType = "txt"
			s.Body = "x"
		}))).NotTo(Succeed())
	})

	It("rejects rewrite together with pageArchetypeRef", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-arch", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PageArchetypeRef = &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "a"}
		}))).NotTo(Succeed())
	})

	It("rejects a targetRef kind other than KDexPage/KDexFunction", func() {
		Expect(k8sClient.Create(ctx, rewritePage("bad-kind", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite.TargetRef.Kind = "KDexApp"
		}))).NotTo(Succeed())
	})

	DescribeTable("rejects unsafe rewrite.path values",
		func(p string) {
			Expect(k8sClient.Create(ctx, rewritePage("bad-path", func(s *kdexv1alpha1.KDexPageSpec) {
				s.Rewrite.Path = p
			}))).NotTo(Succeed())
		},
		Entry("double slash", "a//b"),
		Entry("dot-dot segment", "a/../b"),
		Entry("leading dot-dot", "../b"),
		Entry("dot segment", "./b"),
		Entry("scheme", "https:x"),
		Entry("query", "a?b"),
		Entry("fragment", "a#b"),
	)

	It("rejects a text page that sets patternPath (#201)", func() {
		p := rewritePage("bad-text-pattern", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite = nil
			s.MimeType = "txt"
			s.Body = "x"
			s.PatternPath = "/alias/{x}"
		})
		Expect(k8sClient.Create(ctx, p)).NotTo(Succeed())
	})

	It("still rejects an HTML page without a main slot", func() {
		p := rewritePage("bad-html", func(s *kdexv1alpha1.KDexPageSpec) { s.Rewrite = nil })
		Expect(k8sClient.Create(ctx, p)).NotTo(Succeed())
	})
})

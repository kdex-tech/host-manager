package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage rewrite-mode admission (CEL)", func() {
	const namespace = "default"
	ctx := context.Background()

	const (
		msgRewriteExcl = "a rewrite page must not set contentEntries, pageArchetypeRef"
		msgMimeExcl    = "rewrite and mimeType are mutually exclusive"
		msgKind        = "'kind' must be either KDexPage or KDexFunction"
		msgPath        = "rewrite.path must not contain '//', '.' or '..' segments"
		msgTextPattern = "a text page (mimeType set) must not set patternPath"
		msgMain        = "an HTML page (no mimeType, no rewrite) must declare contentEntries"
	)

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

	// expectInvalid asserts the apiserver rejected the object as Invalid with
	// the specific validation message, so unrelated failures cannot pass.
	expectInvalid := func(p *kdexv1alpha1.KDexPage, substr string) {
		GinkgoHelper()
		err := k8sClient.Create(ctx, p)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid, got: %v", err)
		Expect(err.Error()).To(ContainSubstring(substr))
	}

	textPage := func(name string, mutate func(*kdexv1alpha1.KDexPageSpec)) *kdexv1alpha1.KDexPage {
		return rewritePage(name, func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite = nil
			s.MimeType = "txt"
			s.Body = "x"
			if mutate != nil {
				mutate(s)
			}
		})
	}

	mainEntry := func(slot string) []kdexv1alpha1.ContentEntry {
		return []kdexv1alpha1.ContentEntry{{
			ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<p>x</p>"},
			Slot:               slot,
		}}
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
		expectInvalid(rewritePage("bad-content", func(s *kdexv1alpha1.KDexPageSpec) {
			s.ContentEntries = mainEntry("main")
		}), msgRewriteExcl)
	})

	It("rejects rewrite together with mimeType/body", func() {
		expectInvalid(rewritePage("bad-text", func(s *kdexv1alpha1.KDexPageSpec) {
			s.MimeType = "txt"
			s.Body = "x"
		}), msgMimeExcl)
	})

	It("rejects rewrite together with pageArchetypeRef", func() {
		expectInvalid(rewritePage("bad-arch", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PageArchetypeRef = &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "a"}
		}), msgRewriteExcl)
	})

	It("rejects a targetRef kind other than KDexPage/KDexFunction", func() {
		expectInvalid(rewritePage("bad-kind", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite.TargetRef.Kind = "KDexApp"
		}), msgKind)
	})

	DescribeTable("rejects unsafe rewrite.path values",
		func(p, msg string) {
			expectInvalid(rewritePage("bad-path", func(s *kdexv1alpha1.KDexPageSpec) {
				s.Rewrite.Path = p
			}), msg)
		},
		Entry("double slash", "a//b", msgPath),
		Entry("dot-dot segment", "a/../b", msgPath),
		Entry("leading dot-dot", "../b", msgPath),
		Entry("dot segment", "./b", msgPath),
		// scheme/query/fragment are rejected by the OpenAPI pattern, not CEL.
		Entry("scheme", "https:x", "should match"),
		Entry("query", "a?b", "should match"),
		Entry("fragment", "a#b", "should match"),
	)

	It("accepts a text page without patternPath", func() {
		Expect(k8sClient.Create(ctx, textPage("ok-text", nil))).To(Succeed())
	})

	It("rejects a text page that sets patternPath (#201)", func() {
		expectInvalid(textPage("bad-text-pattern", func(s *kdexv1alpha1.KDexPageSpec) {
			s.PatternPath = "/alias/{x}"
		}), msgTextPattern)
	})

	It("accepts an HTML page with a main slot", func() {
		Expect(k8sClient.Create(ctx, rewritePage("ok-html", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite = nil
			s.ContentEntries = mainEntry("main")
		}))).To(Succeed())
	})

	It("rejects an HTML page with no contentEntries", func() {
		expectInvalid(rewritePage("bad-html", func(s *kdexv1alpha1.KDexPageSpec) { s.Rewrite = nil }), msgMain)
	})

	It("rejects an HTML page whose only slot is not main", func() {
		expectInvalid(rewritePage("bad-html-no-main", func(s *kdexv1alpha1.KDexPageSpec) {
			s.Rewrite = nil
			s.ContentEntries = mainEntry("other")
		}), msgMain)
	})
})

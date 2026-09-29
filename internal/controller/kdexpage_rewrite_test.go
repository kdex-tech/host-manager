package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var _ = Describe("KDexPage rewrite-mode reconcile", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	htmlPage := func(name, basePath string) *kdexv1alpha1.KDexPage {
		return &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				ContentEntries: []kdexv1alpha1.ContentEntry{{
					ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<h1>t</h1>"},
					Slot:               "main",
				}},
				HostRef:          corev1.LocalObjectReference{Name: focalHost},
				Label:            name,
				PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "rw-archetype"},
				Paths:            kdexv1alpha1.Paths{BasePath: basePath},
			},
		}
	}
	aliasPage := func(name string, ref kdexv1alpha1.KDexObjectReference, pattern, path string) *kdexv1alpha1.KDexPage {
		return &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				HostRef: corev1.LocalObjectReference{Name: focalHost},
				Label:   name,
				Paths:   kdexv1alpha1.Paths{BasePath: "/" + name, PatternPath: pattern},
				Rewrite: &kdexv1alpha1.RewriteSpec{TargetRef: ref, Path: path},
			},
		}
	}
	degradedReason := func(name string) func() string {
		return func() string {
			var p kdexv1alpha1.KDexPage
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &p); err != nil {
				return ""
			}
			c := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
			if c == nil || c.Status != metav1.ConditionTrue {
				return ""
			}
			return c.Reason
		}
	}
	// seedArchetype seeds what an HTML target page needs to reach Ready: its
	// archetype and the focal internal host (same fixture shape as the
	// existing "with parent page reference" spec).
	seedArchetype := func() {
		addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
			ObjectMeta: metav1.ObjectMeta{Name: "rw-archetype", Namespace: namespace},
			Spec:       kdexv1alpha1.KDexPageArchetypeSpec{Content: "<h1>x</h1>"},
		})
		addOrUpdateInternalHost(ctx, k8sClient, kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: focalHost, Namespace: namespace},
			Spec: kdexv1alpha1.KDexInternalHostSpec{
				KDexHostSpec: kdexv1alpha1.KDexHostSpec{
					BrandName:    "KDex Tech",
					DevMode:      true,
					ModulePolicy: kdexv1alpha1.LooseModulePolicy,
					Organization: "KDex Tech Inc.",
					Routing:      kdexv1alpha1.Routing{Domains: []string{"example.com"}},
				},
			},
		})
	}

	It("becomes Ready once its KDexPage target is Ready, and waits while it is missing", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, aliasPage("latest",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "docs-v3"}, "", ""))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "latest", namespace, &kdexv1alpha1.KDexPage{}, false)

		Expect(k8sClient.Create(ctx, htmlPage("docs-v3", "/docs/v3"))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "latest", namespace, &kdexv1alpha1.KDexPage{}, true)
	})

	It("is Degraded(RewriteTargetIsRewrite) when the target is itself a rewrite page", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, htmlPage("real", "/real"))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("hop1",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "real"}, "", ""))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("hop2",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "hop1"}, "", ""))).To(Succeed())
		Eventually(degradedReason("hop2"), 10*time.Second).Should(Equal("RewriteTargetIsRewrite"))
	})

	It("is Degraded(RewriteTargetInternal) when the target function is internal", func() {
		fn := &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "internal-fn", Namespace: namespace},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				HostRef:  corev1.LocalObjectReference{Name: focalHost},
				Internal: true,
				API: kdexv1alpha1.API{
					BasePath: "/api/internal",
					Paths:    map[string]kdexv1alpha1.PathItem{"/api/internal/test": {}},
				},
			},
		}
		Expect(k8sClient.Create(ctx, fn)).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("to-internal",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "internal-fn"}, "", ""))).To(Succeed())
		Eventually(degradedReason("to-internal"), 10*time.Second).Should(Equal("RewriteTargetInternal"))
	})

	It("is Degraded(RewriteUnknownPlaceholder) when path uses a name patternPath lacks", func() {
		Expect(k8sClient.Create(ctx, aliasPage("bad-ph",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "whatever"}, "/bad-ph/{user}", "{id}"))).To(Succeed())
		Eventually(degradedReason("bad-ph"), 10*time.Second).Should(Equal("RewriteUnknownPlaceholder"))
	})

	It("re-reconciles when the target switches into rewrite mode", func() {
		seedArchetype()
		Expect(k8sClient.Create(ctx, htmlPage("real2", "/real2"))).To(Succeed())
		Expect(k8sClient.Create(ctx, htmlPage("mid", "/mid"))).To(Succeed())
		Expect(k8sClient.Create(ctx, aliasPage("front",
			kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "mid"}, "", ""))).To(Succeed())
		assertResourceReady(ctx, k8sClient, "front", namespace, &kdexv1alpha1.KDexPage{}, true)

		var mid kdexv1alpha1.KDexPage
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "mid", Namespace: namespace}, &mid)).To(Succeed())
		mid.Spec.ContentEntries = nil
		mid.Spec.PageArchetypeRef = nil
		mid.Spec.Rewrite = &kdexv1alpha1.RewriteSpec{TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: "real2"}}
		Expect(k8sClient.Update(ctx, &mid)).To(Succeed())

		Eventually(degradedReason("front"), 10*time.Second).Should(Equal("RewriteTargetIsRewrite"))
	})
})

package controller

import (
	"context"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A parentPageRef only places a page in the menu, so a page whose parent
// chain loops back to itself, or whose parent is bound to another host, is
// served but appears in no menu. It must say so (#300 quad).
var _ = Describe("KDexPage parentPageRef problems", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	seed := func() {
		addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
			ObjectMeta: metav1.ObjectMeta{Name: "pp-archetype", Namespace: namespace},
			Spec:       kdexv1alpha1.KDexPageArchetypeSpec{Content: "<main>[[ .Content.main ]]</main>"},
		})
		addOrUpdateInternalHost(ctx, k8sClient, defaultInternalHost(namespace))
	}
	rawPage := func(name, hostName, parent string) *kdexv1alpha1.KDexPage {
		p := &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				ContentEntries: []kdexv1alpha1.ContentEntry{{
					Slot:               "main",
					ContentEntryStatic: kdexv1alpha1.ContentEntryStatic{RawHTML: "<p>" + name + "</p>"},
				}},
				HostRef:          corev1.LocalObjectReference{Name: hostName},
				Label:            name,
				PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "pp-archetype"},
				Paths:            kdexv1alpha1.Paths{BasePath: "/" + name},
			},
		}
		if parent != "" {
			p.Spec.ParentPageRef = &corev1.LocalObjectReference{Name: parent}
		}
		return p
	}
	// expectServedButDegraded asserts the page stays Ready (it is served)
	// with Degraded=True for reason, and with a message containing msg.
	expectServedButDegraded := func(name string, reason kdexv1alpha1.ConditionReason, msg string) {
		Eventually(func(g Gomega) {
			var p kdexv1alpha1.KDexPage
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &p)).To(Succeed())
			g.Expect(meta.IsStatusConditionTrue(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady))).To(BeTrue())
			d := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
			g.Expect(d).NotTo(BeNil())
			g.Expect(d.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(d.Reason).To(Equal(string(reason)))
			g.Expect(d.Message).To(ContainSubstring(msg))
		}, "15s").Should(Succeed())
		_, ok := hostHandler.Pages.Get(name)
		Expect(ok).To(BeTrue(), "a page with a parentPageRef problem is still served")
	}
	expectClean := func(name string) {
		Eventually(func(g Gomega) {
			var p kdexv1alpha1.KDexPage
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &p)).To(Succeed())
			g.Expect(meta.IsStatusConditionTrue(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady))).To(BeTrue())
			g.Expect(meta.IsStatusConditionFalse(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))).To(BeTrue())
		}, "15s").Should(Succeed())
	}

	It("flags a page that is its own parent", func() {
		seed()
		Expect(k8sClient.Create(ctx, rawPage("pp-self", focalHost, "pp-self"))).To(Succeed())
		expectServedButDegraded("pp-self", parentPageCycleReason, "pp-self -> pp-self")
	})

	It("flags both pages of a two-page parent cycle, and clears when it is broken", func() {
		seed()
		Expect(k8sClient.Create(ctx, rawPage("pp-a", focalHost, "pp-b"))).To(Succeed())
		Expect(k8sClient.Create(ctx, rawPage("pp-b", focalHost, "pp-a"))).To(Succeed())
		expectServedButDegraded("pp-a", parentPageCycleReason, "pp-a -> pp-b -> pp-a")
		expectServedButDegraded("pp-b", parentPageCycleReason, "pp-b -> pp-a -> pp-b")

		By("breaking the cycle at pp-b")
		Eventually(func(g Gomega) {
			var p kdexv1alpha1.KDexPage
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "pp-b", Namespace: namespace}, &p)).To(Succeed())
			p.Spec.ParentPageRef = nil
			g.Expect(k8sClient.Update(ctx, &p)).To(Succeed())
		}, "5s").Should(Succeed())
		expectClean("pp-b")
		expectClean("pp-a")
	})

	It("flags a page whose parent is bound to another host", func() {
		seed()
		Expect(k8sClient.Create(ctx, rawPage("pp-foreign", "other-host", ""))).To(Succeed())
		Expect(k8sClient.Create(ctx, rawPage("pp-child", focalHost, "pp-foreign"))).To(Succeed())
		expectServedButDegraded("pp-child", parentPageHostMismatchReason, `parent KDexPage pp-foreign belongs to host "other-host", not "`+focalHost+`"`)
	})
})

func TestStalePackagesMessage(t *testing.T) {
	assert.Equal(t, "package set may be stale: pages [a, b] not Ready", stalePackagesMessage([]string{"b", "a"}))

	names := []string{}
	for i := range 8 {
		names = append(names, fmt.Sprintf("p%d", i))
	}
	assert.Equal(t, "package set may be stale: pages [p0, p1, p2, p3, p4] and 3 more not Ready", stalePackagesMessage(names))
}

func TestPagesNotCurrent(t *testing.T) {
	page := func(name string, gen, observed int64, ready metav1.ConditionStatus) kdexv1alpha1.KDexPage {
		p := kdexv1alpha1.KDexPage{ObjectMeta: metav1.ObjectMeta{Name: name, Generation: gen}}
		p.Status.ObservedGeneration = observed
		if ready != "" {
			meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
				Type: string(kdexv1alpha1.ConditionTypeReady), Status: ready, Reason: "Test",
			})
		}
		return p
	}
	got := pagesNotCurrent([]kdexv1alpha1.KDexPage{
		page("ready", 2, 2, metav1.ConditionTrue),
		page("blocked", 1, 1, metav1.ConditionUnknown),
		page("unreconciled-edit", 3, 2, metav1.ConditionTrue),
		page("never-reconciled", 1, 0, ""),
	})
	assert.Equal(t, []string{"blocked", "unreconciled-edit", "never-reconciled"}, got)
}

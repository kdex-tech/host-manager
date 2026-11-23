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

// #300: a rewrite page whose target is its own child (the nav-surrogate group
// page of #217) used to wait for the child to be Ready while the child waited
// for its parent to be Ready. Once either persisted a non-Ready status, both
// requeued forever and the host's package set froze.
var _ = Describe("KDexPage readiness across a rewrite parent and its child (#300)", func() {
	const namespace = "default"
	ctx := context.Background()

	AfterEach(func() { cleanupResources(namespace) })

	seed := func() {
		addOrUpdatePageArchetype(ctx, k8sClient, kdexv1alpha1.KDexPageArchetype{
			ObjectMeta: metav1.ObjectMeta{Name: "rd-archetype", Namespace: namespace},
			Spec:       kdexv1alpha1.KDexPageArchetypeSpec{Content: "<main>[[ .Content.main ]]</main>"},
		})
		addOrUpdateInternalHost(ctx, k8sClient, defaultInternalHost(namespace))
	}
	newApp := func(name, version string) {
		Expect(k8sClient.Create(ctx, &kdexv1alpha1.KDexApp{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexAppSpec{
				CustomElements:   []kdexv1alpha1.CustomElement{{Name: name + "-el", Description: name}},
				PackageReference: kdexv1alpha1.PackageReference{Name: "@x/" + name, Version: version},
			},
		})).To(Succeed())
	}
	appPage := func(name, basePath, app string, parent string) *kdexv1alpha1.KDexPage {
		p := &kdexv1alpha1.KDexPage{
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
				PageArchetypeRef: &kdexv1alpha1.KDexObjectReference{Kind: "KDexPageArchetype", Name: "rd-archetype"},
				Paths:            kdexv1alpha1.Paths{BasePath: basePath},
			},
		}
		if parent != "" {
			p.Spec.ParentPageRef = &corev1.LocalObjectReference{Name: parent}
		}
		return p
	}
	groupPage := func(name, target string) *kdexv1alpha1.KDexPage {
		return &kdexv1alpha1.KDexPage{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: kdexv1alpha1.KDexPageSpec{
				HostRef: corev1.LocalObjectReference{Name: focalHost},
				Label:   name,
				Paths:   kdexv1alpha1.Paths{BasePath: "/" + name},
				Rewrite: &kdexv1alpha1.RewriteSpec{
					TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexPage", Name: target},
				},
			},
		}
	}
	readyStatus := func(name string) func() metav1.ConditionStatus {
		return func() metav1.ConditionStatus {
			var p kdexv1alpha1.KDexPage
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &p); err != nil {
				return ""
			}
			if c := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady)); c != nil {
				return c.Status
			}
			return ""
		}
	}
	kiprPackages := func() []string {
		var kipr kdexv1alpha1.KDexInternalPackageReferences
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, &kipr); err != nil {
			return nil
		}
		out := []string{}
		for _, pr := range kipr.Spec.PackageReferences {
			out = append(out, pr.Name+"@"+pr.Version)
		}
		return out
	}
	// hostPackagesReady is the focal host's PackagesReady condition, or nil.
	hostPackagesReady := func() *metav1.Condition {
		var h kdexv1alpha1.KDexInternalHost
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, &h); err != nil {
			return nil
		}
		return meta.FindStatusCondition(h.Status.Conditions, ConditionTypePackagesReady)
	}
	// markKIPRBuilding stands in for the KIPR reconciler, which does not run
	// in this suite. Ready=False is the "Building" outcome, which lets the
	// host reconcile continue past the packages image: there is no registry
	// here to pull an importmap from.
	markKIPRBuilding := func() {
		Eventually(func(g Gomega) {
			var kipr kdexv1alpha1.KDexInternalPackageReferences
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: focalHost, Namespace: namespace}, &kipr)).To(Succeed())
			meta.SetStatusCondition(&kipr.Status.Conditions, metav1.Condition{
				Type: string(kdexv1alpha1.ConditionTypeReady), Status: metav1.ConditionFalse, Reason: "Building",
			})
			g.Expect(k8sClient.Status().Update(ctx, &kipr)).To(Succeed())
		}, "10s").Should(Succeed())
	}

	It("lets a rewrite parent and its own child both reach Ready after a reference was not ready", func() {
		seed()
		newApp("rd-admin", "0.3.1")

		By("creating the child (blocked on a not-ready app) and the group page rewriting to it")
		Expect(k8sClient.Create(ctx, appPage("rd-users", "/rd-group/users", "rd-admin", "rd-group"))).To(Succeed())
		Expect(k8sClient.Create(ctx, groupPage("rd-group", "rd-users"))).To(Succeed())

		By("both persisting a non-Ready status")
		Eventually(readyStatus("rd-users"), "10s").Should(Equal(metav1.ConditionUnknown))
		Eventually(readyStatus("rd-group"), "10s").Should(Equal(metav1.ConditionUnknown))

		By("making the app Ready: the child must no longer wait on its rewrite parent")
		setAppReady(ctx, namespace, "rd-admin", metav1.ConditionTrue)
		Eventually(readyStatus("rd-users"), "15s").Should(Equal(metav1.ConditionTrue))
		Eventually(readyStatus("rd-group"), "15s").Should(Equal(metav1.ConditionTrue))
		Eventually(kiprPackages, "15s").Should(ContainElement("@x/rd-admin@0.3.1"))

		By("the host not flagging its package set while every page is Ready")
		markKIPRBuilding()
		Eventually(func(g Gomega) {
			c := hostPackagesReady()
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Reason).To(Equal("Building"))
		}, "15s").Should(Succeed())

		By("replaying the incident: the app blips not-ready, then ships 0.3.2")
		setAppReady(ctx, namespace, "rd-admin", metav1.ConditionFalse)
		Eventually(readyStatus("rd-users"), "10s").Should(Equal(metav1.ConditionUnknown))
		Eventually(readyStatus("rd-group"), "10s").Should(Equal(metav1.ConditionUnknown))

		Eventually(func(g Gomega) {
			var app kdexv1alpha1.KDexApp
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "rd-admin", Namespace: namespace}, &app)).To(Succeed())
			app.Spec.PackageReference.Version = "0.3.2"
			g.Expect(k8sClient.Update(ctx, &app)).To(Succeed())
		}, "5s").Should(Succeed())

		By("the host saying its package set may be stale while the pages are blocked")
		// The blocked pages keep serving their last good render from the
		// page store, so the KIPR still carries 0.3.1. The host must not
		// claim its package set is current.
		Eventually(func(g Gomega) {
			c := hostPackagesReady()
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Status).To(Equal(metav1.ConditionFalse))
			g.Expect(c.Reason).To(Equal(string(pagesNotReadyReason)))
			g.Expect(c.Message).To(ContainSubstring("package set may be stale: pages [rd-group, rd-users] not Ready"))
		}, "15s").Should(Succeed())
		Expect(kiprPackages()).To(ContainElement("@x/rd-admin@0.3.1"))

		setAppReady(ctx, namespace, "rd-admin", metav1.ConditionTrue)

		Eventually(readyStatus("rd-users"), "15s").Should(Equal(metav1.ConditionTrue))
		Eventually(readyStatus("rd-group"), "15s").Should(Equal(metav1.ConditionTrue))
		Eventually(kiprPackages, "15s").Should(ContainElement("@x/rd-admin@0.3.2"))
		Expect(kiprPackages()).NotTo(ContainElement("@x/rd-admin@0.3.1"))

		By("the stale-package condition clearing once the pages are Ready")
		Eventually(func(g Gomega) {
			c := hostPackagesReady()
			g.Expect(c).NotTo(BeNil())
			g.Expect(c.Reason).To(Equal("Building"))
		}, "15s").Should(Succeed())
	})

	It("tells a page blocked on a not-ready reference why, on the page itself", func() {
		seed()
		newApp("rd-slow", "1.0.0")
		Expect(k8sClient.Create(ctx, appPage("rd-waiting", "/rd-waiting", "rd-slow", ""))).To(Succeed())

		Eventually(func(g Gomega) {
			var p kdexv1alpha1.KDexPage
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "rd-waiting", Namespace: namespace}, &p)).To(Succeed())
			degraded := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded))
			g.Expect(degraded).NotTo(BeNil())
			g.Expect(degraded.Status).To(Equal(metav1.ConditionTrue))
			g.Expect(degraded.Reason).To(Equal(string(referenceNotReadyReason)))
			g.Expect(degraded.Message).To(Equal("referenced KDexApp rd-slow is not ready"))
			ready := meta.FindStatusCondition(p.Status.Conditions, string(kdexv1alpha1.ConditionTypeReady))
			g.Expect(ready).NotTo(BeNil())
			g.Expect(ready.Status).To(Equal(metav1.ConditionUnknown))
		}, 10*time.Second).Should(Succeed())

		setAppReady(ctx, namespace, "rd-slow", metav1.ConditionTrue)
		Eventually(readyStatus("rd-waiting"), "15s").Should(Equal(metav1.ConditionTrue))
	})
})

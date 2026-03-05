package controller

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Pairs struct {
	resource client.Object
	list     client.ObjectList
}

func addOrUpdateInternalHost(
	ctx context.Context,
	k8sClient client.Client,
	internalHost kdexv1alpha1.KDexInternalHost,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexInternalHostList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			Namespace:     internalHost.Namespace,
			FieldSelector: fields.OneTermEqualSelector("metadata.name", internalHost.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = internalHost.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &internalHost)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func addOrUpdateClusterPageArchetype(
	ctx context.Context,
	k8sClient client.Client,
	pageArchetype kdexv1alpha1.KDexClusterPageArchetype,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexClusterPageArchetypeList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", pageArchetype.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = pageArchetype.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &pageArchetype)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func addOrUpdatePageArchetype(
	ctx context.Context,
	k8sClient client.Client,
	pageArchetype kdexv1alpha1.KDexPageArchetype,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexPageArchetypeList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			Namespace:     pageArchetype.Namespace,
			FieldSelector: fields.OneTermEqualSelector("metadata.name", pageArchetype.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = pageArchetype.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &pageArchetype)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func addOrUpdatePageHeader(
	ctx context.Context,
	k8sClient client.Client,
	pageHeader kdexv1alpha1.KDexPageHeader,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexPageHeaderList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			Namespace:     pageHeader.Namespace,
			FieldSelector: fields.OneTermEqualSelector("metadata.name", pageHeader.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = pageHeader.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &pageHeader)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func addOrUpdatePageFooter(
	ctx context.Context,
	k8sClient client.Client,
	pageFooter kdexv1alpha1.KDexPageFooter,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexPageFooterList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			Namespace:     pageFooter.Namespace,
			FieldSelector: fields.OneTermEqualSelector("metadata.name", pageFooter.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = pageFooter.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &pageFooter)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func addOrUpdatePageNavigation(
	ctx context.Context,
	k8sClient client.Client,
	pageNavigation kdexv1alpha1.KDexPageNavigation,
) {
	Eventually(func(g Gomega) error {
		list := &kdexv1alpha1.KDexPageNavigationList{}
		err := k8sClient.List(ctx, list, &client.ListOptions{
			Namespace:     pageNavigation.Namespace,
			FieldSelector: fields.OneTermEqualSelector("metadata.name", pageNavigation.Name),
		})
		g.Expect(err).NotTo(HaveOccurred())
		if len(list.Items) > 0 {
			existing := list.Items[0]
			existing.Spec = pageNavigation.Spec
			g.Expect(k8sClient.Update(ctx, &existing)).To(Succeed())
		} else {
			g.Expect(k8sClient.Create(ctx, &pageNavigation)).To(Succeed())
		}
		return nil
	}).Should(Succeed())
}

func assertResourceReady(ctx context.Context, k8sClient client.Client, name string, namespace string, checkResource client.Object, ready bool) {
	typeNamespacedName := types.NamespacedName{
		Name: name,
	}

	if namespace != "" {
		typeNamespacedName.Namespace = namespace
	}

	check := func(g Gomega) {
		err := k8sClient.Get(ctx, typeNamespacedName, checkResource)
		g.Expect(err).NotTo(HaveOccurred())
		it := reflect.ValueOf(checkResource).Elem()

		statusField := it.FieldByName("Status")

		g.Expect(statusField.IsZero()).To(BeFalse())
		conditionsField := statusField.FieldByName("Conditions")

		g.Expect(conditionsField.IsZero()).To(BeFalse())
		conditions, ok := conditionsField.Interface().([]metav1.Condition)

		g.Expect(ok).To(BeTrue())

		g.Expect(
			meta.IsStatusConditionTrue(
				conditions, string(kdexv1alpha1.ConditionTypeReady),
			),
		).To(BeEquivalentTo(ready))
	}

	Eventually(check, "5s").Should(Succeed())
}

func cleanupResources(namespace string) {
	By("Cleanup all the test resource instances")

	for _, pair := range []Pairs{
		{&kdexv1alpha1.KDexApp{}, &kdexv1alpha1.KDexAppList{}},
		{&kdexv1alpha1.KDexClusterApp{}, &kdexv1alpha1.KDexClusterAppList{}},
		{&kdexv1alpha1.KDexClusterFaaSAdaptor{}, &kdexv1alpha1.KDexClusterFaaSAdaptorList{}},
		{&kdexv1alpha1.KDexClusterPageArchetype{}, &kdexv1alpha1.KDexClusterPageArchetypeList{}},
		{&kdexv1alpha1.KDexClusterPageFooter{}, &kdexv1alpha1.KDexClusterPageFooterList{}},
		{&kdexv1alpha1.KDexClusterPageHeader{}, &kdexv1alpha1.KDexClusterPageHeaderList{}},
		{&kdexv1alpha1.KDexClusterPageNavigation{}, &kdexv1alpha1.KDexClusterPageNavigationList{}},
		{&kdexv1alpha1.KDexClusterScriptLibrary{}, &kdexv1alpha1.KDexClusterScriptLibraryList{}},
		{&kdexv1alpha1.KDexClusterTheme{}, &kdexv1alpha1.KDexClusterThemeList{}},
		{&kdexv1alpha1.KDexClusterUtilityPage{}, &kdexv1alpha1.KDexClusterUtilityPageList{}},
		{&kdexv1alpha1.KDexFaaSAdaptor{}, &kdexv1alpha1.KDexFaaSAdaptorList{}},
		{&kdexv1alpha1.KDexFunction{}, &kdexv1alpha1.KDexFunctionList{}},
		{&kdexv1alpha1.KDexInternalHost{}, &kdexv1alpha1.KDexInternalHostList{}},
		{&kdexv1alpha1.KDexInternalPackageReferences{}, &kdexv1alpha1.KDexInternalPackageReferencesList{}},
		{&kdexv1alpha1.KDexInternalTranslation{}, &kdexv1alpha1.KDexInternalTranslationList{}},
		{&kdexv1alpha1.KDexInternalUtilityPage{}, &kdexv1alpha1.KDexInternalUtilityPageList{}},
		{&kdexv1alpha1.KDexPageArchetype{}, &kdexv1alpha1.KDexPageArchetypeList{}},
		{&kdexv1alpha1.KDexPage{}, &kdexv1alpha1.KDexPageList{}},
		{&kdexv1alpha1.KDexPageFooter{}, &kdexv1alpha1.KDexPageFooterList{}},
		{&kdexv1alpha1.KDexPageHeader{}, &kdexv1alpha1.KDexPageHeaderList{}},
		{&kdexv1alpha1.KDexPageNavigation{}, &kdexv1alpha1.KDexPageNavigationList{}},
		{&kdexv1alpha1.KDexScriptLibrary{}, &kdexv1alpha1.KDexScriptLibraryList{}},
		{&kdexv1alpha1.KDexTheme{}, &kdexv1alpha1.KDexThemeList{}},
		{&kdexv1alpha1.KDexTranslation{}, &kdexv1alpha1.KDexTranslationList{}},
		{&kdexv1alpha1.KDexUtilityPage{}, &kdexv1alpha1.KDexUtilityPageList{}},
		{&corev1.Secret{}, &corev1.SecretList{}},
		{&corev1.ServiceAccount{}, &corev1.ServiceAccountList{}},
	} {
		err := k8sClient.DeleteAllOf(ctx, pair.resource, client.InNamespace(namespace))
		Expect(err).NotTo(HaveOccurred())

		Eventually(func(g Gomega) error {
			list := pair.list
			err := k8sClient.List(ctx, list, client.InNamespace(namespace))
			g.Expect(err).NotTo(HaveOccurred())
			items, err := meta.ExtractList(list)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(items).To(HaveLen(0))
			return nil
		}).To(Succeed())
	}
}

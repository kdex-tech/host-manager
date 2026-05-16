package controller

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/kdex-tech/host-manager/internal/page"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func ResolveContents(
	ctx context.Context,
	c client.Client,
	referrer client.Object,
	referrerConditions *[]metav1.Condition,
	contentEntries []kdexv1alpha1.ContentEntry,
	requeueDelay time.Duration,
) (map[string]page.ResolvedContentEntry, bool, ctrl.Result, error) {
	contents := make(map[string]page.ResolvedContentEntry)

	for _, contentEntry := range contentEntries {
		appRef := contentEntry.AppRef
		if appRef == nil {
			contents[contentEntry.Slot] = page.ResolvedContentEntry{
				Content: page.PackedContent{
					Content: contentEntry.RawHTML,
					Slot:    contentEntry.Slot,
				},
			}

			continue
		}

		app, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, c, referrer, referrerConditions, appRef, requeueDelay)
		if shouldReturn {
			return nil, shouldReturn, r1, err
		}

		var appSpec *kdexv1alpha1.KDexAppSpec

		switch v := app.(type) {
		case *kdexv1alpha1.KDexApp:
			appSpec = &v.Spec
		case *kdexv1alpha1.KDexClusterApp:
			appSpec = &v.Spec
		}

		contents[contentEntry.Slot] = page.ResolvedContentEntry{
			App:    appSpec,
			AppObj: app,
			Content: page.PackedContent{
				AppName:           app.GetName(),
				AppGeneration:     fmt.Sprintf("%d", app.GetGeneration()),
				Attributes:        contentEntry.Attributes,
				Content:           contentEntry.RawHTML,
				CustomElementName: contentEntry.CustomElementName,
				Slot:              contentEntry.Slot,
			},
		}
	}

	return contents, false, ctrl.Result{}, nil
}

func ResolveHost(
	ctx context.Context,
	c client.Client,
	object client.Object,
	objectConditions *[]metav1.Condition,
	hostRef *corev1.LocalObjectReference,
	requeueDelay time.Duration,
	checkReady bool,
) (*kdexv1alpha1.KDexInternalHost, bool, ctrl.Result, error) {
	if hostRef == nil {
		return nil, false, ctrl.Result{}, nil
	}

	var host kdexv1alpha1.KDexInternalHost
	hostName := types.NamespacedName{
		Name:      hostRef.Name,
		Namespace: object.GetNamespace(),
	}
	if err := c.Get(ctx, hostName, &host); err != nil {
		if errors.IsNotFound(err) {
			kdexv1alpha1.SetConditions(
				objectConditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			return nil, true, ctrl.Result{RequeueAfter: requeueDelay}, nil
		}

		return nil, true, ctrl.Result{}, err
	}

	if checkReady {
		if isReady, r1, err := isReady(&host, &host.Status.Conditions, requeueDelay); !isReady {
			return nil, true, r1, err
		}
	}

	return &host, false, ctrl.Result{}, nil
}

func ResolvePageNavigations(
	ctx context.Context,
	c client.Client,
	object client.Object,
	objectConditions *[]metav1.Condition,
	navigationRefs map[string]*kdexv1alpha1.KDexObjectReference,
	requeueDelay time.Duration,
) (map[string]page.ResolvedNavigation, bool, ctrl.Result, error) {
	navigations := make(map[string]page.ResolvedNavigation)

	for navigationName, navigationRef := range navigationRefs {
		navigation, shouldReturn, response, err := ResolveKDexObjectReference(
			ctx, c, object, objectConditions, navigationRef, requeueDelay)

		if shouldReturn {
			return nil, true, response, err
		}

		if navigation != nil {
			var navigationSpec *kdexv1alpha1.KDexPageNavigationSpec

			switch v := navigation.(type) {
			case *kdexv1alpha1.KDexPageNavigation:
				navigationSpec = &v.Spec
			case *kdexv1alpha1.KDexClusterPageNavigation:
				navigationSpec = &v.Spec
			}

			navigations[navigationName] = page.ResolvedNavigation{
				Generation: navigation.GetGeneration(),
				Name:       navigation.GetName(),
				Spec:       navigationSpec,
			}
		}
	}

	return navigations, false, ctrl.Result{}, nil
}

func ResolvePage(
	ctx context.Context,
	c client.Client,
	object client.Object,
	objectConditions *[]metav1.Condition,
	pageRef *corev1.LocalObjectReference,
	requeueDelay time.Duration,
) (*kdexv1alpha1.KDexPage, bool, ctrl.Result, error) {
	if pageRef == nil {
		return nil, false, ctrl.Result{}, nil
	}

	var kdexPage kdexv1alpha1.KDexPage
	pageName := types.NamespacedName{
		Name:      pageRef.Name,
		Namespace: object.GetNamespace(),
	}
	if err := c.Get(ctx, pageName, &kdexPage); err != nil {
		if errors.IsNotFound(err) {
			kdexv1alpha1.SetConditions(
				objectConditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			return nil, true, ctrl.Result{RequeueAfter: requeueDelay}, nil
		}

		return nil, true, ctrl.Result{}, err
	}

	if isReady, r1, err := isReady(&kdexPage, &kdexPage.Status.Conditions, requeueDelay); !isReady {
		return nil, true, r1, err
	}

	return &kdexPage, false, ctrl.Result{}, nil
}

func ResolveKDexObjectReference(
	ctx context.Context,
	c client.Client,
	referrer client.Object,
	referrerConditions *[]metav1.Condition,
	objectRef *kdexv1alpha1.KDexObjectReference,
	requeueDelay time.Duration,
) (client.Object, bool, ctrl.Result, error) {
	if objectRef == nil {
		return nil, false, ctrl.Result{}, nil
	}

	t := reflect.TypeOf(referrer)

	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	referrerKind := t.Name()
	isReferrerClustered := strings.Contains(referrerKind, "Cluster")

	if isReferrerClustered && !strings.Contains(objectRef.Kind, "Cluster") {
		return nil, true, ctrl.Result{}, fmt.Errorf(
			"referrer %s is cluster scoped so %s must also be cluster scoped", referrerKind, objectRef.Kind)
	}

	gvk := schema.GroupVersionKind{Group: "kdex.dev", Version: "v1alpha1", Kind: objectRef.Kind}
	obj, err := c.Scheme().New(gvk)
	if err != nil {
		return nil, true, ctrl.Result{}, fmt.Errorf("unknown kind %s", objectRef.Kind)
	}

	key := client.ObjectKey{Name: objectRef.Name}

	if !isReferrerClustered && !strings.Contains(objectRef.Kind, "Cluster") {
		key.Namespace = referrer.GetNamespace()
		if objectRef.Namespace != "" {
			key.Namespace = objectRef.Namespace
		}
	}

	if err := c.Get(ctx, key, obj.(client.Object)); err != nil {
		kdexv1alpha1.SetConditions(
			referrerConditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			err.Error(),
		)

		return nil, true, ctrl.Result{}, err
	}

	it := reflect.ValueOf(obj).Elem()
	statusField := it.FieldByName("Status")
	conditionsField := statusField.FieldByName("Conditions")
	conditions, ok := conditionsField.Interface().([]metav1.Condition)

	if !ok {
		return obj.(client.Object), true, ctrl.Result{}, fmt.Errorf("no condition field on status %v", obj)
	}

	if isReady, r1, err := isReady(obj.(client.Object), &conditions, requeueDelay); !isReady {
		return obj.(client.Object), true, r1, err
	}

	return obj.(client.Object), false, ctrl.Result{}, nil
}

func ResolveOrDefaultFaaSAdaptor(ctx context.Context, c client.Client, referrer client.Object, referrerConditions *[]metav1.Condition, internalHost *kdexv1alpha1.KDexInternalHost, requeueDelay time.Duration) (client.Object, bool, ctrl.Result, error) {
	faasAdaptorObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, c, referrer, referrerConditions, internalHost.Spec.FaaSAdaptorRef, requeueDelay)
	if shouldReturn {
		return nil, shouldReturn, r1, err
	}

	if faasAdaptorObj == nil {
		var clusterFaaSAdaptorList kdexv1alpha1.KDexClusterFaaSAdaptorList
		if err = c.List(ctx, &clusterFaaSAdaptorList, client.MatchingLabels{"kdex.dev/default": "true"}); err != nil {
			kdexv1alpha1.SetConditions(
				referrerConditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileSuccess,
				err.Error(),
			)
			return nil, true, ctrl.Result{}, err
		}

		if len(clusterFaaSAdaptorList.Items) != 0 {
			slices.SortFunc(clusterFaaSAdaptorList.Items, func(a, b kdexv1alpha1.KDexClusterFaaSAdaptor) int {
				return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
			})

			faasAdaptorObj = &clusterFaaSAdaptorList.Items[0]
		}
	}

	return faasAdaptorObj, false, ctrl.Result{}, nil
}

func ResolveOrDefaultPageArchetype(ctx context.Context, c client.Client, referrer client.Object, referrerConditions *[]metav1.Condition, pageArchetypeRef *kdexv1alpha1.KDexObjectReference, requeueDelay time.Duration) (client.Object, bool, ctrl.Result, error) {
	pageArchetypeObj, shouldReturn, r1, err := ResolveKDexObjectReference(ctx, c, referrer, referrerConditions, pageArchetypeRef, requeueDelay)
	if shouldReturn {
		return nil, shouldReturn, r1, err
	}

	if pageArchetypeObj == nil {
		var clusterPageArchetypeList kdexv1alpha1.KDexClusterPageArchetypeList
		if err = c.List(ctx, &clusterPageArchetypeList, client.MatchingLabels{"kdex.dev/default": "true"}); err != nil {
			kdexv1alpha1.SetConditions(
				referrerConditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileSuccess,
				err.Error(),
			)
			return nil, true, ctrl.Result{}, err
		}

		if len(clusterPageArchetypeList.Items) != 0 {
			slices.SortFunc(clusterPageArchetypeList.Items, func(a, b kdexv1alpha1.KDexClusterPageArchetype) int {
				return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
			})

			pageArchetypeObj = &clusterPageArchetypeList.Items[0]
		}
	}

	return pageArchetypeObj, false, ctrl.Result{}, nil
}

func ResolveSecret(
	ctx context.Context,
	c client.Client,
	object client.Object,
	objectConditions *[]metav1.Condition,
	secretRef *corev1.LocalObjectReference,
	requeueDelay time.Duration,
) (*corev1.Secret, bool, ctrl.Result, error) {
	if secretRef == nil {
		return nil, false, ctrl.Result{}, nil
	}

	var secret corev1.Secret
	secretName := types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: object.GetNamespace(),
	}
	if err := c.Get(ctx, secretName, &secret); err != nil {
		if errors.IsNotFound(err) {
			kdexv1alpha1.SetConditions(
				objectConditions,
				kdexv1alpha1.ConditionStatuses{
					Degraded:    metav1.ConditionTrue,
					Progressing: metav1.ConditionFalse,
					Ready:       metav1.ConditionFalse,
				},
				kdexv1alpha1.ConditionReasonReconcileError,
				err.Error(),
			)

			return nil, true, ctrl.Result{RequeueAfter: requeueDelay}, nil
		}
	}

	return &secret, false, ctrl.Result{}, nil
}

func ResolveSecrets(ctx context.Context, c client.Client, objectStatus *kdexv1alpha1.KDexObjectStatus, namespace string, selector *metav1.LabelSelector) (kdexv1alpha1.Secrets, error) {
	if selector == nil {
		return kdexv1alpha1.Secrets{}, nil
	}

	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("invalid secretSelector: %w", err)
	}

	var list corev1.SecretList
	if err := c.List(ctx, &list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, err
	}

	// Sort by name for deterministic ordering — List order is not guaranteed
	// and downstream Filter/Find helpers re-sort by creationTimestamp.
	slices.SortFunc(list.Items, func(a, b corev1.Secret) int {
		return strings.Compare(a.Name, b.Name)
	})

	secrets := make(kdexv1alpha1.Secrets, 0, len(list.Items))
	for _, secret := range list.Items {
		secrets = append(secrets, secret)
		objectStatus.Attributes[secret.Name+".secret.generation"] = fmt.Sprintf("%d", secret.GetGeneration())
	}
	return secrets, nil
}

func isReady(
	referred client.Object,
	referredConditions *[]metav1.Condition,
	requeueDelay time.Duration,
) (bool, ctrl.Result, error) {
	t := reflect.TypeOf(referred)
	if t == nil {
		return false, ctrl.Result{}, fmt.Errorf("referred is nil")
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	if !meta.IsStatusConditionTrue(*referredConditions, string(kdexv1alpha1.ConditionTypeReady)) {
		kdexv1alpha1.SetConditions(
			referredConditions,
			kdexv1alpha1.ConditionStatuses{
				Degraded:    metav1.ConditionTrue,
				Progressing: metav1.ConditionFalse,
				Ready:       metav1.ConditionFalse,
			},
			kdexv1alpha1.ConditionReasonReconcileError,
			fmt.Sprintf("referenced %s %s is not ready", t.Name(), referred.GetName()),
		)

		return false, ctrl.Result{RequeueAfter: requeueDelay}, nil
	}

	return true, ctrl.Result{}, nil
}

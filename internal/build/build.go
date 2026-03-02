package build

import (
	"context"
	"fmt"

	"github.com/kdex-tech/host-manager/internal"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type Builder struct {
	client.Client
	ImageRegistry  string
	Scheme         *runtime.Scheme
	ServiceAccount string
	Source         kdexv1alpha1.Source
}

func (b *Builder) GetOrCreateKPackImage(
	ctx context.Context,
	function *kdexv1alpha1.KDexFunction,
) (controllerutil.OperationResult, *unstructured.Unstructured, error) {

	kImageName := fmt.Sprintf("%s-%s", function.Spec.HostRef.Name, function.Name)

	kImage := &unstructured.Unstructured{}
	kImage.SetGroupVersionKind(internal.KPackImageGVK)
	kImage.SetNamespace(function.Namespace)
	kImage.SetName(kImageName)

	op, err := ctrl.CreateOrPatch(ctx, b.Client, kImage, func() error {
		spec := map[string]any{
			"builder": map[string]any{
				"name": b.Source.Builder.BuilderRef.Name,
				"kind": b.Source.Builder.BuilderRef.Kind,
			},
			"imageTaggingStrategy": "BuildNumber",
			"serviceAccountName":   b.ServiceAccount,
			"source": map[string]any{
				"git": map[string]any{
					"url":      b.Source.Repository,
					"revision": b.Source.Revision,
				},
				"subPath": b.Source.Path,
			},
			"tag": fmt.Sprintf("%s/%s/%s:latest", b.ImageRegistry, function.Spec.HostRef.Name, function.Name),
			"additionalTags": []any{
				fmt.Sprintf("%s/%s/%s:%d", b.ImageRegistry, function.Spec.HostRef.Name, function.Name, function.GetGeneration()),
			},
		}

		if err := unstructured.SetNestedMap(kImage.Object, spec, "spec"); err != nil {
			return err
		}

		if err := unstructured.SetNestedSlice(kImage.Object, convert(b.Source.Builder.Env), "spec", "build", "env"); err != nil {
			return err
		}

		kImage.SetLabels(map[string]string{
			"app":           "builder",
			"function":      function.Name,
			"kdex.dev/host": function.Spec.HostRef.Name,
		})

		return ctrl.SetControllerReference(function, kImage, b.Scheme)
	})

	if err != nil {
		return op, kImage, fmt.Errorf("failed to create image builder: %w", err)
	}

	return op, kImage, nil
}

func convert(envVar []v1.EnvVar) []any {
	result := make([]any, 0, len(envVar))
	for _, env := range envVar {
		result = append(result, map[string]any{
			"name":  env.Name,
			"value": env.Value,
		})
	}
	return result
}

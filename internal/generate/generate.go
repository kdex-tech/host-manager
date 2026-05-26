package generate

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oasdiff/yaml"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kdex-tech/host-manager/internal"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Generator struct {
	client.Client
	CodegenResources corev1.ResourceRequirements
	Config           kdexv1alpha1.Generator
	GitSecret        corev1.LocalObjectReference
	ImagePullSecrets []corev1.LocalObjectReference
	OpenAPIBuilder   *ko.Builder
	Scheme           *runtime.Scheme
	ServerUrl        string
	ServiceAccount   string
}

func (g *Generator) GetOrCreateGenerateJob(ctx context.Context, function *kdexv1alpha1.KDexFunction) (*batchv1.Job, error) {
	// Create Job name
	jobName := fmt.Sprintf("%s-codegen-%d", function.Name, function.Generation)

	job := &batchv1.Job{}
	err := g.Get(ctx, client.ObjectKey{Namespace: function.Namespace, Name: jobName}, job)
	if err == nil {
		return job, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	spec := g.OpenAPIBuilder.BuildOneOff(g.ServerUrl, function)
	specBytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, err
	}

	env := []corev1.EnvVar{
		{
			Name:  "FUNCTION_HOST",
			Value: function.Spec.HostRef.Name,
		},
		{
			Name:  "FUNCTION_GENERATION",
			Value: fmt.Sprintf("%d", function.Generation),
		},
		{
			Name:  "FUNCTION_NAME",
			Value: function.Name,
		},
		{
			Name:  "FUNCTION_ENTRYPOINT",
			Value: g.Config.Entrypoint,
		},
		{
			Name:  "FUNCTION_NAMESPACE",
			Value: function.Namespace,
		},
		{
			Name:  "FUNCTION_BASEPATH",
			Value: function.Spec.API.BasePath,
		},
		{
			Name:  "FUNCTION_SPEC",
			Value: marshall(function),
		},
		{
			Name:  "FUNCTION_API_SPEC",
			Value: string(specBytes),
		},
		{
			Name:  "COMMITTER_EMAIL",
			Value: g.Config.Git.CommitterEmail,
		},
		{
			Name:  "COMMITTER_NAME",
			Value: g.Config.Git.CommitterName,
		},
		{
			Name:  "COMMIT_SUB_DIRECTORY",
			Value: g.Config.Git.FunctionSubDirectory,
		},
		{
			Name: "GIT_HOST",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "host",
					LocalObjectReference: g.GitSecret,
				},
			},
		},
		{
			Name: "GIT_ORG",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "org",
					LocalObjectReference: g.GitSecret,
				},
			},
		},
		{
			Name: "GIT_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "password",
					LocalObjectReference: g.GitSecret,
				},
			},
		},
		{
			Name: "GIT_REPO",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "repo",
					LocalObjectReference: g.GitSecret,
				},
			},
		},
		{
			Name: "GIT_USERNAME",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key:                  "username",
					LocalObjectReference: g.GitSecret,
				},
			},
		},
		{
			Name:  "WORKDIR",
			Value: internal.WORKDIR,
		},
	}

	// When spec.origin.source.path is set, propagate it so git_checkout
	// (kdex-cli-tools >= 0.3.13) writes into the developer's chosen
	// layout rather than the canonical COMMIT_SUB_DIRECTORY/HOST/NAME
	// convention. Preserves hand-authored cmd/custom.go + custom go.mod
	// when source has been declared by the developer; the canonical
	// convention is still used in pure codegen mode (origin.source nil).
	if function.Spec.Origin.Source != nil && function.Spec.Origin.Source.Path != "" {
		env = append(env, corev1.EnvVar{
			Name:  "SOURCE_PATH",
			Value: function.Spec.Origin.Source.Path,
		})
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      internal.SHARED_VOLUME,
			MountPath: internal.WORKDIR,
		},
	}

	job = &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: function.Namespace,
			Labels: map[string]string{
				"app":                 "codegen",
				"function":            function.Name,
				"kdex.dev/generation": fmt.Sprintf("%d", function.Generation),
			},
			Annotations: map[string]string{
				"kdex.dev/generation": fmt.Sprintf("%d", function.Generation),
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: new(int32(3)),
			Completions:  new(int32(1)),
			Parallelism:  new(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kdex.dev/generation": fmt.Sprintf("%d", function.Generation),
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(true),
					SecurityContext:              internal.PSSRestrictedPodSecurityContext(),
					Containers: []corev1.Container{
						{
							Name: "results",

							Command:         []string{"patch_source_status"},
							Env:             env,
							Image:           g.Config.Git.Image,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
					},
					ImagePullSecrets: g.ImagePullSecrets,
					InitContainers: []corev1.Container{
						{
							Name: "git-checkout",

							Command:         []string{"git_checkout"},
							Env:             env,
							Image:           g.Config.Git.Image,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
						{
							Name: "generate-code",

							Args:            g.Config.Args,
							Command:         g.Config.Command,
							Env:             env,
							Image:           g.Config.Image,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
							// CodegenResources overrides the namespace LimitRange default so
							// `go mod tidy` survives heavy-dep function trees
							// (cloudsqlconn + grpc + opentelemetry + pgx); defaults come
							// from NexusConfiguration.Codegen.Resources (2Gi req / 4Gi
							// limit), mirroring the kpack builder. Without this the
							// LimitRange default OOM-kills the step — observed on
							// user-service-admin codegen-10 (exit 137).
							Resources: g.CodegenResources,
						},
						{
							Name: "git-push",

							Command:         []string{"git_push"},
							Env:             env,
							Image:           g.Config.Git.Image,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
					},
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: g.ServiceAccount,
					Volumes: []corev1.Volume{
						{
							Name: internal.SHARED_VOLUME,
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}

	if err = ctrl.SetControllerReference(function, job, g.Scheme); err != nil {
		return nil, fmt.Errorf("failed to create code generation job: %w", err)
	}

	if err = g.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to create code generation job: %w", err)
	}

	return job, nil
}

func marshall(function *kdexv1alpha1.KDexFunction) string {
	copy := function.DeepCopy()

	if copy.Status.Generator != nil && copy.Spec.Origin.Generator == nil {
		copy.Spec.Origin.Generator = copy.Status.Generator
	}
	if copy.Status.Source != nil && copy.Spec.Origin.Source == nil {
		copy.Spec.Origin.Source = copy.Status.Source
	}
	if copy.Status.Executable != nil && copy.Spec.Origin.Executable == nil {
		copy.Spec.Origin.Executable = copy.Status.Executable
	}

	copy.Status = kdexv1alpha1.KDexFunctionStatus{}
	copy.ManagedFields = nil
	copy.ResourceVersion = "0"
	copy.UID = "0"
	copy.CreationTimestamp = metav1.Time{}
	copy.DeletionTimestamp = nil
	copy.DeletionGracePeriodSeconds = nil
	copy.OwnerReferences = nil
	copy.Finalizers = nil
	copy.GenerateName = ""
	copy.Generation = 0
	yamlBytes, _ := yaml.Marshal(&copy)
	return string(yamlBytes)
}

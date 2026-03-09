package packref

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type PackRef struct {
	client.Client
	ConfigMap         *corev1.ConfigMap
	InternalHost      *kdexv1alpha1.KDexInternalHost
	ImageRegistry     string
	ImagePushSecret   *corev1.Secret
	ImagePullSecrets  []corev1.LocalObjectReference
	Log               logr.Logger
	NPMSecret         corev1.Secret
	Packages          *configuration.Packages
	Scheme            *runtime.Scheme
	ServiceAccountRef corev1.LocalObjectReference
}

func (p *PackRef) GetOrCreatePackRefJob(ctx context.Context, ipr *kdexv1alpha1.KDexInternalPackageReferences) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("%s-packages-%d", ipr.Name, ipr.Generation)

	job := &batchv1.Job{}
	err := p.Get(ctx, client.ObjectKey{Namespace: ipr.Namespace, Name: jobName}, job)
	if err == nil {
		return job, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	volumes := []corev1.Volume{
		{
			Name: internal.SHARED_VOLUME,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
		{
			Name: "build-scripts",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: p.ConfigMap.Name,
					},
				},
			},
		},
		{
			Name: "npmrc",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: p.NPMSecret.Name,
				},
			},
		},
	}

	if p.ImagePushSecret != nil {
		volumes = append(volumes, corev1.Volume{
			Name: "image-push-secret",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: p.ImagePushSecret.Name,
				},
			},
		})
	}

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      internal.SHARED_VOLUME,
			MountPath: internal.WORKDIR,
		},
		{
			Name:      "build-scripts",
			MountPath: "/scripts",
			ReadOnly:  true,
		},
		{
			Name:      "npmrc",
			MountPath: internal.WORKDIR + "/.npmrc",
			SubPath:   ".npmrc",
			ReadOnly:  true,
		},
	}

	if p.ImagePushSecret != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "image-push-secret",
			MountPath: internal.WORKDIR + "/config.json",
			SubPath:   ".dockerconfigjson",
			ReadOnly:  true,
		})
	}

	imageURL := fmt.Sprintf("%s/%s/packages:%d", p.ImageRegistry, ipr.Name, p.InternalHost.Generation)

	env := []corev1.EnvVar{
		{
			Name:  "IMAGE_REGISTRY",
			Value: p.ImageRegistry,
		},
		{
			Name:  "IMAGE_URL",
			Value: imageURL,
		},
		{
			Name:  "MODULE_PATH",
			Value: internal.MODULE_PATH,
		},
		{
			Name:  "PACKAGING_DIR",
			Value: internal.WORKDIR + "/node_modules",
		},
		{
			Name:  "WORKDIR",
			Value: internal.WORKDIR,
		},
	}

	if p.ImagePushSecret != nil {
		env = append(env, corev1.EnvVar{
			Name:  "IMAGE_PUSH_SECRET_PATH",
			Value: internal.WORKDIR + "/config.json",
		})
	}

	job = &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: ipr.Namespace,
			Labels: map[string]string{
				"app":                 "packages",
				"packages":            ipr.Name,
				"kdex.dev/generation": fmt.Sprintf("%d", ipr.Generation),
			},
			Annotations: map[string]string{
				"kdex.dev/generation": fmt.Sprintf("%d", ipr.Generation),
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: new(int32(3)),
			Completions:  new(int32(1)),
			Parallelism:  new(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kdex.dev/generation": fmt.Sprintf("%d", ipr.Generation),
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(true),
					Containers: []corev1.Container{
						{
							Name: "packager",

							Command:         []string{"package_image"},
							Env:             env,
							Image:           p.Packages.PackagerImage,
							ImagePullPolicy: p.Packages.PackagerImagePullPolicy,
							VolumeMounts:    volumeMounts,
						},
					},
					ImagePullSecrets: p.ImagePullSecrets,
					InitContainers: []corev1.Container{
						{
							Name: "npm-build",

							Command:         []string{"get_modules"},
							Env:             env,
							Image:           "k3d-registry:5000/kdex-tech/node-tools:latest",
							ImagePullPolicy: corev1.PullAlways,
							VolumeMounts:    volumeMounts,
						},
						{
							Name: "importmap-generator",

							Command:         []string{"importmap_generator"},
							Env:             env,
							Image:           "k3d-registry:5000/kdex-tech/node-tools:latest",
							ImagePullPolicy: corev1.PullAlways,
							VolumeMounts:    volumeMounts,
						},
					},
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: p.ServiceAccountRef.Name,
					Volumes:            volumes,
				},
			},
		},
	}

	if err := ctrl.SetControllerReference(ipr, job, p.Scheme); err != nil {
		return nil, fmt.Errorf("failed to create packages job: %w", err)
	}

	if err = p.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to create packages job: %w", err)
	}

	return job, nil
}

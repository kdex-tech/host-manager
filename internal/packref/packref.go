package packref

import (
	"context"
	"fmt"
	"strings"

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
	ConfigMap        *corev1.ConfigMap
	InternalHost     *kdexv1alpha1.KDexInternalHost
	ImageRegistry    string
	ImagePushSecret  *corev1.Secret
	ImagePullSecrets []corev1.LocalObjectReference
	Log              logr.Logger
	NPMSecret        corev1.Secret
	Packages         *configuration.Packages
	Scheme           *runtime.Scheme
	ServiceAccount   string
}

// imageBuiltForCurrentGeneration reports whether status already records a
// packages image (and importmap) whose tag matches the IPR's current
// generation. The recorded image is written by the controller as
// "<registry>/<name>/packages:<generation>@<digest>" on a successful build, so
// a matching ":<generation>@" prefix means this exact generation has already
// produced an image — no rebuild is required. See kdex-tech/host-manager#111.
func (p *PackRef) imageBuiltForCurrentGeneration(ipr *kdexv1alpha1.KDexInternalPackageReferences) bool {
	if ipr.Status.Attributes == nil {
		return false
	}
	image := ipr.Status.Attributes["image"]
	if image == "" || ipr.Status.Attributes["importmap"] == "" {
		return false
	}
	wantTag := fmt.Sprintf("/%s/packages:%d@", ipr.Name, ipr.Generation)
	return strings.Contains(image, wantTag)
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

	// Idempotency guard: if the packages image for the CURRENT generation is
	// already recorded in status, the build is content-complete — a missing Job
	// object (GC'd after success, reaped on a controller restart, or no TTL but
	// externally deleted) must NOT trigger a full rebuild. Re-running npm
	// install + image build + push is pure waste and (per #110's
	// non-reproducible digests) needlessly rolls the packages Deployment. A
	// real generation bump changes the recorded tag, so this only suppresses
	// rebuilds of an unchanged generation. See kdex-tech/host-manager#111.
	if p.imageBuiltForCurrentGeneration(ipr) {
		return nil, nil
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

	// A per-host PersistentVolumeClaim mounted at /cache persists the
	// package-manager download cache (npm + bun) across packaging Jobs, so
	// installs are reusable ("warm"). Empty CacheClaim leaves the ephemeral
	// EmptyDir (cold installs) — behavior identical to before this field.
	if p.Packages.CacheClaim != "" {
		volumes = append(volumes, corev1.Volume{
			Name: internal.CACHE_VOLUME,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: p.Packages.CacheClaim,
				},
			},
		})
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

	if p.Packages.CacheClaim != "" {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      internal.CACHE_VOLUME,
			MountPath: internal.CACHE_DIR,
		})
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
		{
			// Force HOME into the writable EmptyDir mount so npm,
			// kaniko, oras, and anything else that resolves a default
			// state directory from $HOME (npm: $HOME/.npm, kaniko:
			// $HOME/.docker, etc.) writes inside the shared volume
			// instead of attempting /.npm or /.docker on the container's
			// root-owned read-write rootfs - those mkdirs fail with
			// EACCES under runAsUser=65532 even without
			// readOnlyRootFilesystem, since the image's `/` is owned by
			// root and lacks world-write.
			Name:  "HOME",
			Value: internal.WORKDIR,
		},
	}

	// INSTALLER / RUNTIME select the packaging pipeline's dependency installer
	// and JS runtime (node-tools >= 0.3.0, kdex-tech/node-tools#3). Emitted
	// only when configured, so an unset config leaves the image defaults
	// (npm + node) — byte-identical to prior packaging behavior.
	if p.Packages.Installer != "" {
		env = append(env, corev1.EnvVar{
			Name:  "INSTALLER",
			Value: p.Packages.Installer,
		})
	}
	if p.Packages.Runtime != "" {
		env = append(env, corev1.EnvVar{
			Name:  "RUNTIME",
			Value: p.Packages.Runtime,
		})
	}

	// Redirect the package-manager download caches onto the /cache PVC so they
	// persist across Jobs. Both installers honor these; without them the cache
	// falls back to $HOME (the ephemeral WORKDIR EmptyDir).
	if p.Packages.CacheClaim != "" {
		env = append(env,
			corev1.EnvVar{
				Name:  "NPM_CONFIG_CACHE",
				Value: internal.CACHE_DIR + "/npm",
			},
			corev1.EnvVar{
				Name:  "BUN_INSTALL_CACHE_DIR",
				Value: internal.CACHE_DIR + "/bun",
			},
		)
	}

	if p.ImagePushSecret != nil {
		env = append(env, corev1.EnvVar{
			Name:  "IMAGE_PUSH_SECRET_PATH",
			Value: internal.WORKDIR + "/config.json",
		})
		// oras (and any docker/containerd client) resolves registry
		// auth from $DOCKER_CONFIG/config.json (then $HOME/.docker/
		// config.json). The image-push-secret volume mounts the
		// dockerconfigjson at <WORKDIR>/config.json, so point
		// DOCKER_CONFIG at WORKDIR and oras finds it. Without this the
		// packager container's oras push hits the registry without
		// auth and the AR replies "denied: Unauthenticated request" -
		// the rsi-<env>-docker Secret may be fresh and valid, but oras
		// never consults it because the file path doesn't match its
		// default search order. Only emitted when an ImagePushSecret
		// is present so non-push setups don't trip the env.
		env = append(env, corev1.EnvVar{
			Name:  "DOCKER_CONFIG",
			Value: internal.WORKDIR,
		})
	}

	// A PVC mounts root-owned; fsGroup makes /cache group-writable by the
	// runtime user (65532) so the installer can populate the cache. Only set
	// when a cache PVC is attached, so non-cache Jobs are unchanged.
	podSecurityContext := internal.PSSRestrictedPodSecurityContext()
	if p.Packages.CacheClaim != "" {
		podSecurityContext.FSGroup = new(int64(65532))
		// OnRootMismatch skips a full recursive chown of the (growing) cache
		// on every mount — it only relabels when the root dir's ownership is
		// wrong, keeping mount time flat as the cache fills.
		podSecurityContext.FSGroupChangePolicy = new(corev1.FSGroupChangeOnRootMismatch)
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
			// Without ActiveDeadlineSeconds a hung packref pod (npm
			// install on a slow registry, oras push to a deadlocked
			// registry) runs forever — BackoffLimit only counts pod
			// failures. 30m covers a heavy npm install + oras push;
			// well below "operator intervenes." See
			// kdex-tech/host-manager#63.
			ActiveDeadlineSeconds: new(int64(30 * 60)),
			BackoffLimit:          new(int32(3)),
			Completions:           new(int32(1)),
			Parallelism:           new(int32(1)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kdex.dev/generation": fmt.Sprintf("%d", ipr.Generation),
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(true),
					SecurityContext:              podSecurityContext,
					Containers: []corev1.Container{
						{
							Name: "packager",

							Command:         []string{"package_image"},
							Env:             env,
							Image:           p.Packages.PackagerImage,
							ImagePullPolicy: p.Packages.PackagerImagePullPolicy,
							Resources:       p.Packages.Resources,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
					},
					ImagePullSecrets: p.ImagePullSecrets,
					InitContainers: []corev1.Container{
						{
							Name: "npm-build",

							Command:         []string{"get_modules"},
							Env:             env,
							Image:           p.Packages.ToolsImage,
							ImagePullPolicy: p.Packages.ToolsImagePullPolicy,
							Resources:       p.Packages.Resources,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
						{
							Name: "importmap-generator",

							Command:         []string{"importmap_generator"},
							Env:             env,
							Image:           p.Packages.ToolsImage,
							ImagePullPolicy: p.Packages.ToolsImagePullPolicy,
							Resources:       p.Packages.Resources,
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							VolumeMounts:    volumeMounts,
						},
					},
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: p.ServiceAccount,
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

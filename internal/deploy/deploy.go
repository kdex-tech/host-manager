package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kdex-tech/host-manager/internal"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// resolveTolerations applies the REPLACE semantics documented in
// kdex-crds#7: the per-function spec override (if non-empty) replaces
// the FaaSAdaptor.Deployer default; an empty result means "emit no
// FUNCTION_TOLERATIONS env var and let knative-deployer leave the
// Knative Service podspec unchanged."
func resolveTolerations(
	function *kdexv1alpha1.KDexFunction,
	faas kdexv1alpha1.KDexFaaSAdaptorSpec,
) []corev1.Toleration {
	if len(function.Spec.Tolerations) > 0 {
		return function.Spec.Tolerations
	}
	return faas.Deployer.Tolerations
}

// resolveNodeSelector is the NodeSelector counterpart of
// resolveTolerations, with the same REPLACE semantics.
func resolveNodeSelector(
	function *kdexv1alpha1.KDexFunction,
	faas kdexv1alpha1.KDexFaaSAdaptorSpec,
) map[string]string {
	if len(function.Spec.NodeSelector) > 0 {
		return function.Spec.NodeSelector
	}
	return faas.Deployer.NodeSelector
}

type Deployer struct {
	Client           client.Client
	FaaSAdaptor      kdexv1alpha1.KDexFaaSAdaptorSpec
	Host             kdexv1alpha1.KDexInternalHost
	ImagePullSecrets []corev1.LocalObjectReference
	Scheme           *runtime.Scheme
	ServiceAccount   string
}

// Runtime defines the interface for interacting with a FaaS provider.
type Runtime interface {
	// Deploy returns a Job that, when executed, will deploy or update the function.
	// The Job is expected to update the KDexFunction status upon completion.
	Deploy(ctx context.Context, function *kdexv1alpha1.KDexFunction) (*batchv1.Job, error)

	// Observe returns a workload that, when executed, calls the provider API to check status.
	// For external providers, this is likely a CronJob.
	// For K8s-native providers (like Knative), this might return nil (if handled by standard Watch),
	// or a no-op Job for consistency.
	Observe(ctx context.Context, function *kdexv1alpha1.KDexFunction) (client.Object, error)
}

// The FaaS adaptor is responsible for deploying the function.
// Since there are virtually unlimited number of ways to deploy a function,
// we use a job as a bridge between the Nexus controller and the FaaS adaptor.
// The workload provided by the FaaS adaptor knows how to deploy the function.
// Whether the functions are deployed on KNative, AWS Lambda, Google Cloud Functions,
// Azure Functions, or something else is irrelevant to the Nexus controller.
// The job is responsible for deploying the function and reporting the status
// of the deployment back to the Nexus controller. The job must return success or
// failure along with reasons, and upon success, at least the URL of the function so that the
// Focal Controller can mount it into the host's service mesh and dispatch requests to it.
func (d *Deployer) Deploy(ctx context.Context, function *kdexv1alpha1.KDexFunction) (*batchv1.Job, error) {
	if function.Status.Executable == nil {
		return nil, fmt.Errorf("function %s/%s has no executable", function.Namespace, function.Name)
	}

	// Create Job identity hash based on the image and the adaptor version
	image := function.Status.Executable.Image
	adaptorGen := function.Status.Attributes["faasAdaptor.generation"]
	h := sha256.New()
	h.Write([]byte(image))
	h.Write([]byte(adaptorGen))
	idHash := fmt.Sprintf("%x", h.Sum(nil))[:8]

	jobName := fmt.Sprintf("%s-deployer-%d-%s", function.Name, function.Generation, idHash)

	job := &batchv1.Job{}
	err := d.Client.Get(ctx, client.ObjectKey{Namespace: function.Namespace, Name: jobName}, job)
	if err == nil {
		return job, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	issuer := fmt.Sprintf("%s://%s", d.Host.Spec.Routing.Scheme, d.Host.Spec.Routing.Domains[0])

	// Function audience: the cluster-local URL the runtime pod will be
	// reachable at. The Knative Service we're about to create uses the
	// function's name as the Service name and lives in the function's
	// namespace, so the URL is deterministic. We can NOT use
	// function.Status.URL here — that field is only populated after the
	// deployer Job finishes (kdexfunction_controller.go:969), so on the
	// first deploy AUDIENCE would resolve to "" and any function with
	// JWT validation crashes on startup with "AUDIENCE environment
	// variable is required for security".
	audience := fmt.Sprintf("http://%s.%s.svc.cluster.local", function.Name, function.Namespace)

	env := []corev1.EnvVar{}

	// Function environment variables
	if len(function.Spec.Env) != 0 {
		// {
		// 	Name:  "ANONYMOUS_ENTITLEMENTS",
		// 	Value: "", // TODO: make this configurable, set by Function
		// },
		// {
		// 	Name:  "DEBUG",
		// 	Value: "false", // TODO: make this configurable, set by Function
		// },
		// {
		// 	Name:  "DEFAULT_SECURITY_SCHEME",
		// 	Value: "bearer", // TODO: make this configurable, set by Function
		// },
		env = append(env, function.Spec.Env...)
	}

	// Common environment variables
	env = append(env, []corev1.EnvVar{
		{
			Name:  "AUDIENCE",
			Value: audience,
		},
		{
			Name:  "FUNCTION_BASEPATH",
			Value: function.Spec.API.BasePath,
		},
		{
			Name:  "FUNCTION_GENERATION",
			Value: fmt.Sprintf("%d", function.Generation),
		},
		{
			Name:  "FUNCTION_HOST",
			Value: function.Spec.HostRef.Name,
		},
		{
			Name:  "FUNCTION_IMAGE",
			Value: image,
		},
		{
			Name:  "FUNCTION_NAME",
			Value: function.Name,
		},
		{
			Name:  "FUNCTION_NAMESPACE",
			Value: function.Namespace,
		},
		{
			Name:  "ISSUER",
			Value: issuer,
		},
		{
			Name:  "JWKS_URL",
			Value: issuer + "/.well-known/jwks.json",
		},
		{
			Name:  "PKS_URL",
			Value: issuer + "/.well-known/pks.json",
		},
	}...)

	// FUNCTION_SERVICE_ACCOUNT_NAME is set only when the CR opts in.
	// knative-deployer applies it to the generated Knative Service's
	// spec.template.spec.serviceAccountName, letting the runtime pod use
	// a non-default KSA (e.g. for Workload Identity bindings).
	if function.Spec.ServiceAccountName != "" {
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_SERVICE_ACCOUNT_NAME",
			Value: function.Spec.ServiceAccountName,
		})
	}

	// FUNCTION_TOLERATIONS / FUNCTION_NODE_SELECTOR forward runtime-pod
	// scheduling onto the deployer Job. knative-deployer (v0.1.11+)
	// JSON-decodes them and sets the Knative Service's
	// spec.template.spec.{tolerations,nodeSelector} so function pods
	// can land on a tainted node pool (e.g. arm64 spot). REPLACE
	// resolution: per-function override (KDexFunctionSpec.{...}) wins
	// over the FaaSAdaptor.Deployer default; empty wins are no-ops
	// (the env var is omitted, deployer keeps the prior podspec).
	if tols := resolveTolerations(function, d.FaaSAdaptor); len(tols) > 0 {
		body, err := json.Marshal(tols)
		if err != nil {
			return nil, fmt.Errorf("marshal function tolerations: %w", err)
		}
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_TOLERATIONS",
			Value: string(body),
		})
	}
	if ns := resolveNodeSelector(function, d.FaaSAdaptor); len(ns) > 0 {
		body, err := json.Marshal(ns)
		if err != nil {
			return nil, fmt.Errorf("marshal function nodeSelector: %w", err)
		}
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_NODE_SELECTOR",
			Value: string(body),
		})
	}

	var forwardedEnvVars strings.Builder
	sep := ""
	for _, e := range env {
		fmt.Fprintf(&forwardedEnvVars, "%s%s", sep, e.Name)
		sep = ","
	}

	env = append(env, corev1.EnvVar{
		Name:  "FORWARDED_ENV_VARS",
		Value: forwardedEnvVars.String(),
	})

	// FaaS adaptor environment variables
	env = append(env, d.FaaSAdaptor.Deployer.Env...)

	// Scaling environment variables
	if function.Status.Executable.Scaling != nil {
		env = append(env, []corev1.EnvVar{
			{
				Name:  "SCALING_ACTIVATION_SCALE",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.ActivationScale),
			},
			{
				Name:  "SCALING_INITIAL_SCALE",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.InitialScale),
			},
			{
				Name:  "SCALING_MAX_SCALE",
				Value: fmt.Sprintf("%d", function.Status.Executable.Scaling.MaxScale),
			},
			{
				Name:  "SCALING_METRIC",
				Value: *function.Status.Executable.Scaling.Metric,
			},
			{
				Name:  "SCALING_MIN_SCALE",
				Value: fmt.Sprintf("%d", function.Status.Executable.Scaling.MinScale),
			},
			{
				Name:  "SCALING_PANIC_THRESHOLD_PERCENTAGE",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.PanicThresholdPercentage),
			},
			{
				Name:  "SCALING_PANIC_WINDOW_PERCENTAGE",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.PanicWindowPercentage),
			},
			{
				Name:  "SCALING_SCALE_DOWN_DELAY",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.ScaleDownDelay),
			},
			{
				Name:  "SCALING_SCALE_TO_ZERO_POD_RETENTION_PERIOD",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.ScaleToZeroPodRetentionPeriod),
			},
			{
				Name:  "SCALING_STABLE_WINDOW",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.StableWindow),
			},
			{
				Name:  "SCALING_TARGET",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.Target),
			},
			{
				Name:  "SCALING_TARGET_UTILIZATION_PERCENTAGE",
				Value: fmt.Sprintf("%d", *function.Status.Executable.Scaling.TargetUtilizationPercentage),
			},
		}...)
	}

	job = &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: function.Namespace,
			Labels: map[string]string{
				"app":                 "deployer",
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
							Args:    d.FaaSAdaptor.Deployer.Args,
							Command: d.FaaSAdaptor.Deployer.Command,
							Env:     env,
							Image:   d.FaaSAdaptor.Deployer.Image,

							// TODO: implement the AWS Lambda deployer image
							// TODO: implement the Google Cloud Functions deployer image
							// TODO: implement the Azure Functions deployer image

							Name:            "deployer",
							SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
						},
					},
					ImagePullSecrets:   d.ImagePullSecrets,
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: d.ServiceAccount,
				},
			},
		},
	}

	if err = ctrl.SetControllerReference(function, job, d.Scheme); err != nil {
		return nil, fmt.Errorf("failed to create deployment job: %w", err)
	}

	if err = d.Client.Create(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to create deployment job: %w", err)
	}

	return job, nil
}

func (d *Deployer) Observe(ctx context.Context, function *kdexv1alpha1.KDexFunction) (client.Object, error) {
	if d.FaaSAdaptor.Observer == nil {
		return nil, nil // No observer configured
	}

	// Create CronJob name
	cronJobName := fmt.Sprintf("%s-observer", function.Name)

	cronJob := &batchv1.CronJob{}
	err := d.Client.Get(ctx, client.ObjectKey{Namespace: function.Namespace, Name: cronJobName}, cronJob)
	if err == nil {
		if d.FaaSAdaptor.Observer.Schedule != cronJob.Spec.Schedule {
			cronJob.Spec.Schedule = d.FaaSAdaptor.Observer.Schedule
			err = d.Client.Update(ctx, cronJob)
			if err != nil {
				return nil, fmt.Errorf("failed to update observation cronjob: %w", err)
			}
		}

		return cronJob, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	// Reuse deployment environment variables where appropriate
	env := make([]corev1.EnvVar, 0, 6+len(d.FaaSAdaptor.Observer.Env))
	env = append(env, []corev1.EnvVar{
		{
			Name:  "FUNCTION_BASEPATH",
			Value: function.Spec.API.BasePath,
		},
		{
			Name:  "FUNCTION_GENERATION",
			Value: fmt.Sprintf("%d", function.Generation),
		},
		{
			Name:  "FUNCTION_HOST",
			Value: function.Spec.HostRef.Name,
		},
		{
			Name:  "FUNCTION_NAME",
			Value: function.Name,
		},
		{
			Name:  "FUNCTION_NAMESPACE",
			Value: function.Namespace,
		},
	}...)

	// Forward the kpack-Build auto-recovery policy knobs to the
	// observer's runtime (see kdex-knative-deployer cmd/retry.go).
	// Optional on the CRD; observer falls back to compiled-in defaults
	// (3 retries, 20m cooldown) when these env vars are unset.
	if d.FaaSAdaptor.Observer.MaxBuildRetries != nil {
		env = append(env, corev1.EnvVar{
			Name:  "MAX_BUILD_RETRIES",
			Value: fmt.Sprintf("%d", *d.FaaSAdaptor.Observer.MaxBuildRetries),
		})
	}
	if d.FaaSAdaptor.Observer.RetryCooldown != nil {
		env = append(env, corev1.EnvVar{
			Name:  "RETRY_COOLDOWN",
			Value: d.FaaSAdaptor.Observer.RetryCooldown.Duration.String(),
		})
	}

	env = append(env, d.FaaSAdaptor.Observer.Env...)

	cronJob = &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cronJobName,
			Namespace: function.Namespace,
			Labels: map[string]string{
				"app":      "observer",
				"function": function.Name,
			},
		},
		Spec: batchv1.CronJobSpec{
			ConcurrencyPolicy: batchv1.ForbidConcurrent,
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Completions: new(int32(1)),
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							AutomountServiceAccountToken: new(true),
							SecurityContext:              internal.PSSRestrictedPodSecurityContext(),
							Containers: []corev1.Container{
								{
									Args:            d.FaaSAdaptor.Observer.Args,
									Command:         d.FaaSAdaptor.Observer.Command,
									Env:             env,
									Image:           d.FaaSAdaptor.Observer.Image,
									Name:            "observer",
									SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
								},
							},
							ImagePullSecrets:   d.ImagePullSecrets,
							RestartPolicy:      corev1.RestartPolicyOnFailure,
							ServiceAccountName: d.ServiceAccount,
						},
					},
					TTLSecondsAfterFinished: new(int32(0)),
				},
			},
			Schedule:                   d.FaaSAdaptor.Observer.Schedule,
			SuccessfulJobsHistoryLimit: new(int32(1)),
		},
	}

	// Default service account if not set in observer spec
	if cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName == "" {
		cronJob.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName = d.ServiceAccount
	}

	if err = ctrl.SetControllerReference(function, cronJob, d.Scheme); err != nil {
		return nil, fmt.Errorf("failed to create observation cronjob: %w", err)
	}

	if err = d.Client.Create(ctx, cronJob); err != nil {
		return nil, fmt.Errorf("failed to create observation cronjob: %w", err)
	}

	return cronJob, nil
}

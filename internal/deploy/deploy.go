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

	// `issuer` is the externally-routable URL of the host, used as the
	// `iss` claim in minted JWTs — function pods compare it against
	// `token.iss` during validation, so it MUST match what the host's
	// signer uses at mint time. Stays public because the JWT carries
	// this value as-is.
	issuer := fmt.Sprintf("%s://%s", d.Host.Spec.Routing.Scheme, d.Host.Spec.Routing.Domains[0])

	// `internalHost` is the host's in-cluster Service URL — used for
	// JWKS_URL and PKS_URL so the function pod fetches keys without
	// leaving the cluster. The cnas-operator names the host's
	// host-manager Service after the KDexHost.metadata.name in the
	// host's namespace; webserver-bind-address defaults to :8090 (see
	// host-manager/cmd/main.go). Going via the external URL works on
	// permissive networks but (a) burns a public LB round-trip and
	// (b) requires explicit egress NetworkPolicy allowance in
	// strict-default-deny namespaces, which the function pod doesn't
	// have by default.
	internalHost := fmt.Sprintf("http://%s.%s.svc.cluster.local:8090", d.Host.Name, d.Host.Namespace)

	// Function audience: equals the function's Knative cluster-local
	// URL. The reverse proxy (host/proxy.go:47-54) creates a per-
	// function Signer with audience=fn.Status.URL and uses it to mint
	// the downscoped Function Access Token (FAT) it forwards to the
	// function in the Authorization header. So the function MUST
	// validate JWTs against its own URL — not the host's issuer URL
	// (which is what the broader host-side validator uses for the
	// upstream session cookie, not the per-function FAT).
	//
	// We can NOT use function.Status.URL here directly — that field
	// is only populated after the deployer Job finishes
	// (kdexfunction_controller.go:969), so on the first deploy
	// AUDIENCE would resolve to "" and any function with JWT
	// validation crashes with "AUDIENCE environment variable is
	// required for security". The Knative Service we're about to
	// create uses the function's name as the Service name and lives
	// in the function's namespace, so the URL is deterministic:
	audience := fmt.Sprintf("http://%s.%s.svc.cluster.local", function.Name, function.Namespace)

	env := []corev1.EnvVar{}

	// Function-author env from KDexFunction.spec.env is NOT spliced into
	// the deployer Job's env block here - doing so would have the kubelet
	// dereference any valueFrom.secretKeyRef into a plain env string at
	// deployer-pod start, and the downstream knative-deployer would then
	// emit those resolved values as plaintext .spec.containers[0].env[].value
	// on the Knative Service, exposing secrets to anyone with `get revision`
	// RBAC. Instead, the whole []corev1.EnvVar is JSON-marshaled into
	// FUNCTION_USER_ENV below and passed through opaquely; knative-deployer
	// v0.1.21+ unmarshals it back into the Knative Service template,
	// preserving valueFrom.secretKeyRef so the runtime pod's kubelet does
	// the secret resolution (the right boundary).

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
			Value: internalHost + "/.well-known/jwks.json",
		},
		{
			Name:  "PKS_URL",
			Value: internalHost + "/.well-known/pks.json",
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

	// FUNCTION_USER_ENV carries function.Spec.Env opaquely to
	// knative-deployer (which JSON-unmarshals it back into the Knative
	// Service template). See the comment block where this used to splice
	// directly into env above: forwarding via env+os.Getenv lost the
	// valueFrom.secretKeyRef shape because the kubelet resolved it before
	// the deployer's Go code saw it. Marshaling the []corev1.EnvVar
	// through a JSON blob preserves the full struct (value, valueFrom.*,
	// optional, etc.) so secret resolution happens at the runtime pod's
	// kubelet, not on the Revision YAML. Empty Spec.Env emits "null" which
	// the deployer treats as no-op; omit the env var entirely to keep
	// behavior identical to pre-fix for functions without Spec.Env.
	if len(function.Spec.Env) > 0 {
		userEnvJSON, err := json.Marshal(function.Spec.Env)
		if err != nil {
			return nil, fmt.Errorf("marshal function user env: %w", err)
		}
		env = append(env, corev1.EnvVar{
			Name:  "FUNCTION_USER_ENV",
			Value: string(userEnvJSON),
		})
	}

	// FaaS adaptor environment variables
	env = append(env, d.FaaSAdaptor.Deployer.Env...)

	// Scaling environment variables
	// SCALING_* env block — each field is appended individually so a nil
	// pointer on any single field (including Target, the only ScalingConfig
	// field without a CRD default) doesn't take down the whole reconcile.
	// Durations use Duration.String() so the consumer reads "30s", not the
	// internal struct rep. See kdex-tech/host-manager#45.
	if s := function.Status.Executable.Scaling; s != nil {
		if s.ActivationScale != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_ACTIVATION_SCALE", Value: fmt.Sprintf("%d", *s.ActivationScale)})
		}
		if s.InitialScale != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_INITIAL_SCALE", Value: fmt.Sprintf("%d", *s.InitialScale)})
		}
		if s.MaxScale != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_MAX_SCALE", Value: fmt.Sprintf("%d", *s.MaxScale)})
		}
		if s.Metric != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_METRIC", Value: *s.Metric})
		}
		if s.MinScale != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_MIN_SCALE", Value: fmt.Sprintf("%d", *s.MinScale)})
		}
		if s.PanicThresholdPercentage != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_PANIC_THRESHOLD_PERCENTAGE", Value: fmt.Sprintf("%d", *s.PanicThresholdPercentage)})
		}
		if s.PanicWindowPercentage != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_PANIC_WINDOW_PERCENTAGE", Value: fmt.Sprintf("%d", *s.PanicWindowPercentage)})
		}
		if s.ScaleDownDelay != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_SCALE_DOWN_DELAY", Value: s.ScaleDownDelay.Duration.String()})
		}
		if s.ScaleToZeroPodRetentionPeriod != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_SCALE_TO_ZERO_POD_RETENTION_PERIOD", Value: s.ScaleToZeroPodRetentionPeriod.Duration.String()})
		}
		if s.StableWindow != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_STABLE_WINDOW", Value: s.StableWindow.Duration.String()})
		}
		if s.Target != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_TARGET", Value: fmt.Sprintf("%d", *s.Target)})
		}
		if s.TargetUtilizationPercentage != nil {
			env = append(env, corev1.EnvVar{Name: "SCALING_TARGET_UTILIZATION_PERCENTAGE", Value: fmt.Sprintf("%d", *s.TargetUtilizationPercentage)})
		}
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

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
	"k8s.io/apimachinery/pkg/api/equality"
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

// functionFileAndExposureEnv builds the deployer-Job env vars that forward
// file-config projection (FUNCTION_VOLUMES / FUNCTION_VOLUME_MOUNTS, #10) and
// the internal-exposure marker (FUNCTION_INTERNAL, #6) to knative-deployer.
// Extracted from Deploy to keep its cyclomatic complexity in check; each var
// is omitted when its source field is empty/false so existing CRs are
// unaffected.
func functionFileAndExposureEnv(function *kdexv1alpha1.KDexFunction) ([]corev1.EnvVar, error) {
	var env []corev1.EnvVar
	if len(function.Spec.Volumes) > 0 {
		body, err := json.Marshal(function.Spec.Volumes)
		if err != nil {
			return nil, fmt.Errorf("marshal function volumes: %w", err)
		}
		env = append(env, corev1.EnvVar{Name: "FUNCTION_VOLUMES", Value: string(body)})
	}
	if len(function.Spec.VolumeMounts) > 0 {
		body, err := json.Marshal(function.Spec.VolumeMounts)
		if err != nil {
			return nil, fmt.Errorf("marshal function volumeMounts: %w", err)
		}
		env = append(env, corev1.EnvVar{Name: "FUNCTION_VOLUME_MOUNTS", Value: string(body)})
	}
	if function.Spec.Internal {
		env = append(env, corev1.EnvVar{Name: "FUNCTION_INTERNAL", Value: "true"})
	}
	return env, nil
}

type Deployer struct {
	Client           client.Client
	FaaSAdaptor      kdexv1alpha1.KDexFaaSAdaptorSpec
	Host             kdexv1alpha1.KDexInternalHost
	ImagePullSecrets []corev1.LocalObjectReference
	Scheme           *runtime.Scheme
	ServiceAccount   string
	// TokenPrefix is the host's resolved white-label PASETO API token prefix
	// (per-host spec or NexusConfiguration default). Injected as
	// PASETO_TOKEN_PREFIX so the function's verifier can restore the
	// "v4.public." header. Empty => bare tokens (no prefixing). It MUST be the
	// same value the host's TokenManager mints with.
	TokenPrefix string
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
			// White-label API token prefix. When non-empty the host mints
			// PASETO API tokens with the "v4.public." header replaced by this
			// prefix; the function's verifier restores the header before
			// parsing. Empty => bare tokens. MUST match the host's
			// TokenManager prefix (both resolved via resolveAPITokenPrefix).
			Name:  "PASETO_TOKEN_PREFIX",
			Value: d.TokenPrefix,
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

	// File-config projection (#10) + internal-exposure marker (#6) are
	// appended AFTER the FORWARDED_ENV_VARS builder (like the SCALING_*
	// block) so the deployer reads them via its own os.Getenv to build the
	// podspec/Service WITHOUT injecting the (potentially large) JSON as
	// literal env vars on the function container.
	fileExposureEnv, err := functionFileAndExposureEnv(function)
	if err != nil {
		return nil, err
	}
	env = append(env, fileExposureEnv...)

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
	if s := function.Spec.Scaling; s != nil {
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
			// Without ActiveDeadlineSeconds a hung deployer pod (Knative
			// API blocked, probe stuck) runs forever — BackoffLimit only
			// counts pod failures, so a never-failing pod is never
			// retried and never expires, and the KDexFunction stays
			// Progressing=True indefinitely. 30m comfortably covers a
			// Knative cold start with deps; well below "operator
			// intervenes." See kdex-tech/host-manager#63.
			ActiveDeadlineSeconds: new(int64(30 * 60)),
			BackoffLimit:          new(int32(3)),
			Completions:           new(int32(1)),
			Parallelism:           new(int32(1)),
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

// ObservedByLabel marks a KDexFunction as a member of a host's observer set.
// The per-host observer CronJob lists by it, so the observed set stays exactly
// the adaptor-deployed functions -- service-backed functions never had an
// observer and still don't. Must match the constant in knative-deployer's
// cmd/main.go. See kdex-tech/host-manager#156.
const ObservedByLabel = "kdex.dev/observed-by"

// HostObserverName is the per-host observer CronJob's name.
func HostObserverName(host string) string {
	return fmt.Sprintf("%s-observer", host)
}

// observerEnv builds the observer container's env vars from the
// FaaSAdaptor's Observer spec. Split out of Observe so the desired state
// can be recomputed on every reconcile, not just on create (#143).
//
// One CronJob now covers every function on the host, so this carries no
// per-function values -- the observer resolves its set from FUNCTION_HOST +
// the observed-by label and reads each function's basePath off its CR (#156).
func (d *Deployer) observerEnv() []corev1.EnvVar {
	env := make([]corev1.EnvVar, 0, 4+len(d.FaaSAdaptor.Observer.Env))
	env = append(env, []corev1.EnvVar{
		{
			Name:  "FUNCTION_HOST",
			Value: d.Host.Name,
		},
		{
			Name:  "FUNCTION_NAMESPACE",
			Value: d.Host.Namespace,
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

	return env
}

// observerCronJobSpec builds the desired CronJobSpec for a function's observer.
// Every field an operator can influence via FaaSAdaptor.Observer is set here, so
// that Observe can converge an existing CronJob onto it rather than freezing it
// at whatever the adaptor happened to say when the function was created (#143).
func (d *Deployer) observerCronJobSpec() batchv1.CronJobSpec {
	serviceAccount := d.ServiceAccount

	return batchv1.CronJobSpec{
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
								Env:             d.observerEnv(),
								Image:           d.FaaSAdaptor.Observer.Image,
								Name:            "observer",
								SecurityContext: internal.PSSRestrictedContainerSecurityContext(),
							},
						},
						ImagePullSecrets: d.ImagePullSecrets,
						// Steer observer Job pods to the operator-intended
						// node pool. Cluster-default-only: read from the
						// FaaSAdaptor's Observer. Empty values are no-ops, so
						// observers keep their prior scheduler-picks-anything
						// behavior unless an operator sets them.
						NodeSelector:       d.FaaSAdaptor.Observer.NodeSelector,
						RestartPolicy:      corev1.RestartPolicyOnFailure,
						ServiceAccountName: serviceAccount,
						Tolerations:        d.FaaSAdaptor.Observer.Tolerations,
					},
				},
				TTLSecondsAfterFinished: new(int32(0)),
			},
		},
		Schedule:                   d.FaaSAdaptor.Observer.Schedule,
		SuccessfulJobsHistoryLimit: new(int32(1)),
	}
}

// Observe converges the host's observer CronJob onto the current
// FaaSAdaptor.Observer spec and enrolls the function in its observed set.
//
// Two defects are addressed here.
//
// #143: this used to reconcile only Spec.Schedule on an existing CronJob and
// apply the full pod template only on the create path, so an adaptor edit
// (image, tolerations, nodeSelector, env, securityContext) never reached
// functions that already had an observer. The desired spec is now rebuilt every
// pass and written whenever it differs, so any triggered reconcile -- including
// the periodic resync -- heals a stale observer.
//
// #156: observers used to be one CronJob per function, all sharing the adaptor's
// single schedule, so every observer in a namespace fired in the same second and
// object count grew with the fleet. There is now one CronJob per host; the
// function is marked with ObservedByLabel and the observer resolves its set from
// that label. Any legacy per-function CronJob found is retired.
func (d *Deployer) Observe(ctx context.Context, function *kdexv1alpha1.KDexFunction) (client.Object, error) {
	if d.FaaSAdaptor.Observer == nil {
		return nil, nil // No observer configured
	}

	if err := d.markObserved(ctx, function); err != nil {
		return nil, err
	}

	cronJob, err := d.reconcileHostObserver(ctx)
	if err != nil {
		return nil, err
	}

	if err := d.retireLegacyObserver(ctx, function); err != nil {
		return nil, err
	}

	return cronJob, nil
}

// markObserved stamps ObservedByLabel on the function so the per-host observer
// picks it up. Patched rather than Updated so it can't clobber a concurrent
// write to the function by its own reconciler.
func (d *Deployer) markObserved(ctx context.Context, function *kdexv1alpha1.KDexFunction) error {
	if function.Labels[ObservedByLabel] == d.Host.Name {
		return nil
	}

	patch := client.MergeFrom(function.DeepCopy())
	if function.Labels == nil {
		function.Labels = map[string]string{}
	}
	function.Labels[ObservedByLabel] = d.Host.Name

	if err := d.Client.Patch(ctx, function, patch); err != nil {
		return fmt.Errorf("failed to label function for observation: %w", err)
	}
	return nil
}

// reconcileHostObserver creates or converges the single CronJob that observes
// every function on this host. Owned by the KDexInternalHost, so it is garbage
// collected with the host rather than with whichever function happened to
// create it.
func (d *Deployer) reconcileHostObserver(ctx context.Context) (client.Object, error) {
	cronJobName := HostObserverName(d.Host.Name)

	desiredSpec := d.observerCronJobSpec()
	desiredLabels := map[string]string{
		"app":  "observer",
		"host": d.Host.Name,
	}

	cronJob := &batchv1.CronJob{}
	err := d.Client.Get(ctx, client.ObjectKey{Namespace: d.Host.Namespace, Name: cronJobName}, cronJob)
	if err == nil {
		// Converge the whole spec, not just the schedule. Compare before
		// writing so a byte-stable observer doesn't generate an Update on
		// every reconcile (and, via the CronJob watch, re-trigger us) --
		// the same self-amplification #102 fixed for status writes.
		if equality.Semantic.DeepEqual(cronJob.Spec, desiredSpec) &&
			labelsMatch(cronJob.Labels, desiredLabels) {
			return cronJob, nil
		}

		cronJob.Spec = desiredSpec
		if cronJob.Labels == nil {
			cronJob.Labels = map[string]string{}
		}
		for k, v := range desiredLabels {
			cronJob.Labels[k] = v
		}

		if err = d.Client.Update(ctx, cronJob); err != nil {
			return nil, fmt.Errorf("failed to update observation cronjob: %w", err)
		}

		return cronJob, nil
	}
	if !errors.IsNotFound(err) {
		return nil, err
	}

	cronJob = &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cronJobName,
			Namespace: d.Host.Namespace,
			Labels:    desiredLabels,
		},
		Spec: desiredSpec,
	}

	host := d.Host
	if err = ctrl.SetControllerReference(&host, cronJob, d.Scheme); err != nil {
		return nil, fmt.Errorf("failed to create observation cronjob: %w", err)
	}

	if err = d.Client.Create(ctx, cronJob); err != nil {
		if errors.IsAlreadyExists(err) {
			// Another function on this host won the race; converge next pass.
			return cronJob, nil
		}
		return nil, fmt.Errorf("failed to create observation cronjob: %w", err)
	}

	return cronJob, nil
}

// retireLegacyObserver deletes the pre-#156 per-function CronJob. It is owned by
// the KDexFunction, so ownership GC will never remove it while the function
// lives -- without this, the old and new observers both run.
func (d *Deployer) retireLegacyObserver(ctx context.Context, function *kdexv1alpha1.KDexFunction) error {
	legacyName := fmt.Sprintf("%s-observer", function.Name)
	if legacyName == HostObserverName(d.Host.Name) {
		// A function named identically to its host: the "legacy" name IS the
		// per-host name. Never delete the CronJob we just converged.
		return nil
	}

	legacy := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      legacyName,
			Namespace: function.Namespace,
		},
	}
	if err := d.Client.Delete(ctx, legacy); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to retire legacy observer cronjob: %w", err)
	}
	return nil
}

// labelsMatch reports whether every desired label is present on have with the
// same value. Labels set by other controllers or by an operator are ignored, so
// convergence doesn't fight them.
func labelsMatch(have, desired map[string]string) bool {
	for k, v := range desired {
		if have[k] != v {
			return false
		}
	}
	return true
}

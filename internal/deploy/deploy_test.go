package deploy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// TestDeploy_PreservesSecretKeyRef_NotInlinedIntoJobEnv pins the security
// fix for the original bug: function.Spec.Env entries with
// valueFrom.secretKeyRef were spliced directly into the deployer Job's
// env block. The kubelet then resolved them when starting the deployer
// pod, the deployer's downstream knative-deployer saw plain os.Getenv
// strings, and the resulting Knative Service stored secret values as
// plaintext .spec.containers[0].env[].value (visible to anyone with
// `get revision` RBAC, much broader than `get secret`).
//
// The fix routes user env opaquely through FUNCTION_USER_ENV (JSON
// blob). This test asserts both halves of that contract:
//
//   - The secretKeyRef entry does NOT appear as a sibling env on the Job
//     (kubelet would dereference it there).
//   - FUNCTION_USER_ENV IS present and JSON-decodes back to the original
//     spec.Env list with valueFrom.secretKeyRef shape intact.
//   - FORWARDED_ENV_VARS does NOT list the user-env names (those flow
//     via the JSON blob, not the legacy os.Getenv round-trip).
func TestDeploy_PreservesSecretKeyRef_NotInlinedIntoJobEnv(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kdexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "user-service-admin",
			Namespace:  "dev",
			Generation: 3,
			UID:        "fn-uid",
		},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "rsi-dev"},
			API:     kdexv1alpha1.API{BasePath: "/v1/admin"},
			Env: []corev1.EnvVar{
				{
					Name: "RESEND_API_KEY",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "knowdrive-resend-credentials"},
							Key:                  "api_key",
						},
					},
				},
				{Name: "HOST_DOMAIN", Value: "dev.knowdrive.ai"},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			KDexObjectStatus: kdexv1alpha1.KDexObjectStatus{
				Attributes: map[string]string{"faasAdaptor.generation": "1"},
			},
			Executable: &kdexv1alpha1.Executable{
				Image: "registry.example/admin@sha256:abcd",
			},
		},
	}

	host := kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{Name: "rsi-dev", Namespace: "dev"},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: kdexv1alpha1.KDexHostSpec{
				Routing: kdexv1alpha1.Routing{
					Scheme:  "https",
					Domains: []string{"dev.knowdrive.ai"},
				},
			},
		},
	}

	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		FaaSAdaptor: kdexv1alpha1.KDexFaaSAdaptorSpec{
			Deployer: kdexv1alpha1.Deployer{
				Image: "ghcr.io/kdex-tech/knative-deployer:test",
			},
		},
		Host:           host,
		Scheme:         scheme,
		ServiceAccount: "deployer-sa",
	}

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	jobEnv := job.Spec.Template.Spec.Containers[0].Env

	// 1. The secretKeyRef entry must NOT appear directly on the Job's env
	//    (the kubelet would resolve it at deployer-pod start otherwise).
	for _, e := range jobEnv {
		if e.Name == "RESEND_API_KEY" && e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
			t.Errorf("RESEND_API_KEY secretKeyRef LEAKED into deployer Job env: %+v", e)
		}
		// HOST_DOMAIN is a plain value (no secret); we also forward it via
		// FUNCTION_USER_ENV, not as a sibling env. Same rule.
		if e.Name == "HOST_DOMAIN" {
			t.Errorf("HOST_DOMAIN unexpectedly present as sibling env: %+v (should be in FUNCTION_USER_ENV only)", e)
		}
	}

	// 2. FUNCTION_USER_ENV must be present, with the full Spec.Env JSON.
	var userEnvVar *corev1.EnvVar
	for i := range jobEnv {
		if jobEnv[i].Name == "FUNCTION_USER_ENV" {
			userEnvVar = &jobEnv[i]
			break
		}
	}
	if userEnvVar == nil {
		t.Fatal("FUNCTION_USER_ENV missing from deployer Job env")
	}
	var roundtripped []corev1.EnvVar
	if err := json.Unmarshal([]byte(userEnvVar.Value), &roundtripped); err != nil {
		t.Fatalf("FUNCTION_USER_ENV is not valid JSON: %v", err)
	}
	if len(roundtripped) != 2 {
		t.Fatalf("FUNCTION_USER_ENV decoded to %d entries; want 2", len(roundtripped))
	}
	if roundtripped[0].Name != "RESEND_API_KEY" ||
		roundtripped[0].ValueFrom == nil ||
		roundtripped[0].ValueFrom.SecretKeyRef == nil ||
		roundtripped[0].ValueFrom.SecretKeyRef.Name != "knowdrive-resend-credentials" ||
		roundtripped[0].ValueFrom.SecretKeyRef.Key != "api_key" {
		t.Errorf("RESEND_API_KEY shape lost in roundtrip: %+v", roundtripped[0])
	}
	if roundtripped[1].Name != "HOST_DOMAIN" || roundtripped[1].Value != "dev.knowdrive.ai" {
		t.Errorf("HOST_DOMAIN shape lost in roundtrip: %+v", roundtripped[1])
	}

	// 3. FORWARDED_ENV_VARS must NOT list the user-env names (they flow
	//    via the JSON blob, not via the legacy os.Getenv round-trip).
	var forwarded string
	for _, e := range jobEnv {
		if e.Name == "FORWARDED_ENV_VARS" {
			forwarded = e.Value
		}
	}
	if forwarded == "" {
		t.Fatal("FORWARDED_ENV_VARS missing from deployer Job env")
	}
	for _, badName := range []string{"RESEND_API_KEY", "HOST_DOMAIN"} {
		// Use a simple contains-as-token check (the value is a comma-
		// separated list of names).
		for _, name := range splitCSV(forwarded) {
			if name == badName {
				t.Errorf("FORWARDED_ENV_VARS unexpectedly lists %q: %q", badName, forwarded)
			}
		}
	}
}

// TestDeploy_EmptySpecEnv_OmitsFunctionUserEnv keeps the new path
// backward-compatible: functions that don't declare a spec.env block
// should not emit FUNCTION_USER_ENV at all (avoids an empty "null" JSON
// in the Job env, and lets the downstream deployer skip its unmarshal
// branch entirely).
func TestDeploy_EmptySpecEnv_OmitsFunctionUserEnv(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = kdexv1alpha1.AddToScheme(scheme)

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "dev", Generation: 1, UID: "u"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/x"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			Executable: &kdexv1alpha1.Executable{Image: "img"},
		},
	}
	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Host: kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev"},
			Spec: kdexv1alpha1.KDexInternalHostSpec{
				KDexHostSpec: kdexv1alpha1.KDexHostSpec{
					Routing: kdexv1alpha1.Routing{Scheme: "https", Domains: []string{"x"}},
				},
			},
		},
		Scheme: scheme,
	}
	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	for _, e := range job.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "FUNCTION_USER_ENV" {
			t.Errorf("FUNCTION_USER_ENV should be omitted when Spec.Env is empty; got %q", e.Value)
		}
	}
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

func indexEnvByName(envs []corev1.EnvVar) map[string]string {
	m := map[string]string{}
	for _, e := range envs {
		m[e.Name] = e.Value
	}
	return m
}

// scalingTestDeployer builds a Deployer + KDexFunction suitable for asserting
// the SCALING_* env block. Caller customizes the returned function's
// Status.Executable.Scaling.
func scalingTestSetup(t *testing.T) (*Deployer, *kdexv1alpha1.KDexFunction) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kdexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn", Namespace: "dev", Generation: 1, UID: "u"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/x"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			Executable: &kdexv1alpha1.Executable{Image: "img"},
		},
	}
	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		Host: kdexv1alpha1.KDexInternalHost{
			ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "dev"},
			Spec: kdexv1alpha1.KDexInternalHostSpec{
				KDexHostSpec: kdexv1alpha1.KDexHostSpec{
					Routing: kdexv1alpha1.Routing{Scheme: "https", Domains: []string{"x"}},
				},
			},
		},
		Scheme: scheme,
	}
	return d, fn
}

// TestDeploy_ForwardsVolumesMountsInternal pins kdex-tech/kdex-crds#10 + #6:
// Spec.Volumes / Spec.VolumeMounts are JSON-forwarded onto the deployer Job as
// FUNCTION_VOLUMES / FUNCTION_VOLUME_MOUNTS (knative-deployer decodes them onto
// the Knative Service podspec/container), and Spec.Internal=true forwards
// FUNCTION_INTERNAL=true (deployer labels the Service cluster-local).
func TestDeploy_ForwardsVolumesMountsInternal(t *testing.T) {
	d, fn := scalingTestSetup(t)
	fn.Spec.Volumes = []corev1.Volume{{
		Name:         "cfg",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "app-cfg"}},
	}}
	fn.Spec.VolumeMounts = []corev1.VolumeMount{{Name: "cfg", MountPath: "/etc/app"}}
	fn.Spec.Internal = true

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	envs := indexEnvByName(job.Spec.Template.Spec.Containers[0].Env)

	if v, ok := envs["FUNCTION_VOLUMES"]; !ok {
		t.Error("FUNCTION_VOLUMES missing")
	} else {
		var vols []corev1.Volume
		if err := json.Unmarshal([]byte(v), &vols); err != nil || len(vols) != 1 || vols[0].Name != "cfg" {
			t.Errorf("FUNCTION_VOLUMES = %q; want JSON [{name:cfg ...}] (err=%v)", v, err)
		}
	}
	if v, ok := envs["FUNCTION_VOLUME_MOUNTS"]; !ok {
		t.Error("FUNCTION_VOLUME_MOUNTS missing")
	} else {
		var mounts []corev1.VolumeMount
		if err := json.Unmarshal([]byte(v), &mounts); err != nil || len(mounts) != 1 || mounts[0].MountPath != "/etc/app" {
			t.Errorf("FUNCTION_VOLUME_MOUNTS = %q; want JSON [{mountPath:/etc/app ...}] (err=%v)", v, err)
		}
	}
	if v, ok := envs["FUNCTION_INTERNAL"]; !ok || v != "true" {
		t.Errorf("FUNCTION_INTERNAL = %q (present=%v); want \"true\"", v, ok)
	}

	// The three vars must NOT be listed in FORWARDED_ENV_VARS — otherwise the
	// deployer would re-inject them (incl. the large volumes JSON) as literal
	// env vars on the function container. They are consumed by the deployer's
	// own LoadEnv to build the podspec/Service, not forwarded to the function.
	fwd := envs["FORWARDED_ENV_VARS"]
	for _, name := range []string{"FUNCTION_VOLUMES", "FUNCTION_VOLUME_MOUNTS", "FUNCTION_INTERNAL"} {
		for listed := range strings.SplitSeq(fwd, ",") {
			if listed == name {
				t.Errorf("%s must not appear in FORWARDED_ENV_VARS (would pollute the function container env); got %q", name, fwd)
			}
		}
	}
}

// TestDeploy_NoVolumesOrInternal_OmitsEnv keeps the additive path a no-op:
// a function without volumes and Internal=false must not emit any of the three
// env vars (preserves pre-#10/#6 behavior for existing CRs).
func TestDeploy_NoVolumesOrInternal_OmitsEnv(t *testing.T) {
	d, fn := scalingTestSetup(t)

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	envs := indexEnvByName(job.Spec.Template.Spec.Containers[0].Env)
	for _, k := range []string{"FUNCTION_VOLUMES", "FUNCTION_VOLUME_MOUNTS", "FUNCTION_INTERNAL"} {
		if v, present := envs[k]; present {
			t.Errorf("%s present with value %q but should be omitted when unset", k, v)
		}
	}
}

// TestDeploy_NilScalingFields_DoNotPanic_AndAreOmitted pins kdex-tech/host-manager#45:
// the SCALING_* env block dereferenced Scaling.* pointers unconditionally and
// panicked on any nil field. Target is the trigger today (the only field
// without a CRD default), but every pointer in the block was a latent trap.
// Post-fix: nil fields are silently omitted from the env block and Deploy
// returns a Job normally.
func TestDeploy_NilScalingFields_DoNotPanic_AndAreOmitted(t *testing.T) {
	d, fn := scalingTestSetup(t)
	one := int32(1)
	// Scaling block set, but every field nil except MinScale — mirrors the
	// real-world CR that triggered the crash (scaling: { minScale: 1 }).
	fn.Status.Executable.Scaling = &kdexv1alpha1.ScalingConfig{
		MinScale: &one,
	}

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	envs := indexEnvByName(job.Spec.Template.Spec.Containers[0].Env)

	// MinScale is set — present, derefed correctly.
	if v, ok := envs["SCALING_MIN_SCALE"]; !ok || v != "1" {
		t.Errorf("SCALING_MIN_SCALE = %q (present=%v); want %q", v, ok, "1")
	}

	// All other fields are nil — must be omitted entirely (not panicked,
	// not emitted with a garbage pointer-address value).
	for _, k := range []string{
		"SCALING_ACTIVATION_SCALE",
		"SCALING_INITIAL_SCALE",
		"SCALING_MAX_SCALE",
		"SCALING_METRIC",
		"SCALING_PANIC_THRESHOLD_PERCENTAGE",
		"SCALING_PANIC_WINDOW_PERCENTAGE",
		"SCALING_SCALE_DOWN_DELAY",
		"SCALING_SCALE_TO_ZERO_POD_RETENTION_PERIOD",
		"SCALING_STABLE_WINDOW",
		"SCALING_TARGET",
		"SCALING_TARGET_UTILIZATION_PERCENTAGE",
	} {
		if v, present := envs[k]; present {
			t.Errorf("%s present with value %q but the field was nil on Scaling — should be omitted", k, v)
		}
	}
}

// TestDeploy_ScalingFieldFormatting pins the *VALUE* shape of each SCALING_*
// env. Two latent format bugs in the pre-fix code:
//   - MaxScale / MinScale are *int32 in kdex-crds but the original deploy.go
//     formatted them WITHOUT a deref (fmt.Sprintf("%d", *int32)), so the env
//     value was the pointer address as a giant integer rather than the field
//     value.
//   - ScaleDownDelay / ScaleToZeroPodRetentionPeriod / StableWindow are
//     *metav1.Duration. fmt.Sprintf("%d", durationStruct) prints
//     "%!d(v1.Duration={…})" garbage rather than the duration string.
//
// Post-fix: int32 fields format as the integer value; Duration fields
// format as their canonical Go string ("30s", "0s", etc.).
func TestDeploy_ScalingFieldFormatting(t *testing.T) {
	d, fn := scalingTestSetup(t)
	one := int32(1)
	five := int32(5)
	hundred := int32(100)
	conc := "concurrency"
	thirty := metav1.Duration{Duration: 30 * time.Second}
	sixty := metav1.Duration{Duration: 60 * time.Second}
	zero := metav1.Duration{Duration: 0}

	fn.Status.Executable.Scaling = &kdexv1alpha1.ScalingConfig{
		MinScale:                      &one,
		MaxScale:                      &five,
		Target:                        &hundred,
		Metric:                        &conc,
		StableWindow:                  &sixty,
		ScaleDownDelay:                &thirty,
		ScaleToZeroPodRetentionPeriod: &zero,
	}

	job, err := d.Deploy(context.Background(), fn)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	envs := indexEnvByName(job.Spec.Template.Spec.Containers[0].Env)

	want := map[string]string{
		"SCALING_MIN_SCALE":                          "1",
		"SCALING_MAX_SCALE":                          "5",
		"SCALING_TARGET":                             "100",
		"SCALING_METRIC":                             "concurrency",
		"SCALING_STABLE_WINDOW":                      "1m0s", // 60s canonical form
		"SCALING_SCALE_DOWN_DELAY":                   "30s",
		"SCALING_SCALE_TO_ZERO_POD_RETENTION_PERIOD": "0s",
	}
	for k, w := range want {
		if got := envs[k]; got != w {
			t.Errorf("%s = %q; want %q", k, got, w)
		}
	}
}

// newObserverTestScheme builds the scheme the observer tests share.
func newObserverTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := batchv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kdexv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func newObserverFunction() *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-service",
			Namespace: "dev",
			UID:       "fn-uid",
		},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "rsi-dev"},
			API:     kdexv1alpha1.API{BasePath: "/v1/users"},
		},
	}
}

// TestObserve_SteersObserverPodsViaNodeSelectorAndTolerations is the wire-up
// for kdex-tech/host-manager#121 (consuming kdex-crds#13): the observer
// CronJob's PodSpec must carry the FaaSAdaptor.Observer NodeSelector +
// Tolerations so operators can pin observer Job pods to a specific node pool.
func TestObserve_SteersObserverPodsViaNodeSelectorAndTolerations(t *testing.T) {
	scheme := newObserverTestScheme(t)

	tolerations := []corev1.Toleration{
		{Key: "component", Operator: corev1.TolerationOpEqual, Value: "workload", Effect: corev1.TaintEffectNoSchedule},
	}
	nodeSelector := map[string]string{"kubernetes.io/arch": "arm64"}

	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		FaaSAdaptor: kdexv1alpha1.KDexFaaSAdaptorSpec{
			Observer: &kdexv1alpha1.Observer{
				Image:        "ghcr.io/kdex-tech/knative-deployer:test",
				Schedule:     "*/5 * * * *",
				NodeSelector: nodeSelector,
				Tolerations:  tolerations,
			},
		},
		Scheme:         scheme,
		ServiceAccount: "observer-sa",
	}

	obj, err := d.Observe(context.Background(), newObserverFunction())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	cronJob, ok := obj.(*batchv1.CronJob)
	if !ok {
		t.Fatalf("Observe returned %T; want *batchv1.CronJob", obj)
	}

	podSpec := cronJob.Spec.JobTemplate.Spec.Template.Spec
	if podSpec.NodeSelector["kubernetes.io/arch"] != "arm64" {
		t.Errorf("observer NodeSelector not propagated: %+v", podSpec.NodeSelector)
	}
	if len(podSpec.Tolerations) != 1 ||
		podSpec.Tolerations[0].Key != "component" ||
		podSpec.Tolerations[0].Value != "workload" ||
		podSpec.Tolerations[0].Effect != corev1.TaintEffectNoSchedule {
		t.Errorf("observer Tolerations not propagated: %+v", podSpec.Tolerations)
	}
}

// TestObserve_OmitsPlacementWhenUnset keeps the change backward-compatible:
// an Observer with no NodeSelector/Tolerations yields a PodSpec with neither
// set, preserving the prior "scheduler picks anything" behavior.
func TestObserve_OmitsPlacementWhenUnset(t *testing.T) {
	scheme := newObserverTestScheme(t)

	d := &Deployer{
		Client: fake.NewClientBuilder().WithScheme(scheme).Build(),
		FaaSAdaptor: kdexv1alpha1.KDexFaaSAdaptorSpec{
			Observer: &kdexv1alpha1.Observer{
				Image:    "ghcr.io/kdex-tech/knative-deployer:test",
				Schedule: "*/5 * * * *",
			},
		},
		Scheme:         scheme,
		ServiceAccount: "observer-sa",
	}

	obj, err := d.Observe(context.Background(), newObserverFunction())
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	cronJob := obj.(*batchv1.CronJob)

	podSpec := cronJob.Spec.JobTemplate.Spec.Template.Spec
	if podSpec.NodeSelector != nil {
		t.Errorf("expected nil NodeSelector when unset, got %+v", podSpec.NodeSelector)
	}
	if podSpec.Tolerations != nil {
		t.Errorf("expected nil Tolerations when unset, got %+v", podSpec.Tolerations)
	}
}

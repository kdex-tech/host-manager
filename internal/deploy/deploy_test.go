package deploy

import (
	"context"
	"encoding/json"
	"testing"

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

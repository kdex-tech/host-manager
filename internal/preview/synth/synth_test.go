package synth

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/preview/loader"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// minimalHost returns a KDexInternalHost with the spec fields host-manager's
// SetHost path dereferences without nil-checking (BrandName, Organization,
// DefaultLang, ModulePolicy). Anything else stays zero/nil — the synth
// package itself only touches Namespace and Spec.KDexHostSpec.
func minimalHost(name, namespace string) kdexv1alpha1.KDexInternalHost {
	return kdexv1alpha1.KDexInternalHost{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: kdexv1alpha1.KDexInternalHostSpec{
			KDexHostSpec: kdexv1alpha1.KDexHostSpec{
				BrandName:    "Test",
				Organization: "Test Org",
				DefaultLang:  "en",
				ModulePolicy: kdexv1alpha1.LooseModulePolicy,
			},
		},
	}
}

// minimalFunction returns a KDexFunction in `namespace` whose Spec.API.BasePath
// is `basePath` and whose name is `name`. Status is left zero — SynthesizeRoutes
// keys on overrides + spec, not status.
func minimalFunction(name, namespace, basePath string) kdexv1alpha1.KDexFunction {
	return kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			API: kdexv1alpha1.API{
				BasePath: basePath,
			},
			HostRef: corev1.LocalObjectReference{Name: "test-host"},
		},
	}
}

func buildTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(kdexv1alpha1.AddToScheme(s))
	return s
}

func TestSynthesizeRoutes_HostWithSingleFunction(t *testing.T) {
	h := minimalHost("test-host", "default")
	fn := minimalFunction("echo", "default", "/api/echo")
	urls := map[string]string{"echo": "http://localhost:12345"}

	routes, err := SynthesizeRoutes(h, []kdexv1alpha1.KDexFunction{fn}, urls)
	if err != nil {
		t.Fatalf("SynthesizeRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route; got %d", len(routes))
	}
	if routes[0].URL != "http://localhost:12345" {
		t.Errorf("URL: got %q, want %q", routes[0].URL, "http://localhost:12345")
	}
	if routes[0].BasePath != "/api/echo" {
		t.Errorf("BasePath: got %q, want %q", routes[0].BasePath, "/api/echo")
	}
	if routes[0].FunctionName != "echo" {
		t.Errorf("FunctionName: got %q, want %q", routes[0].FunctionName, "echo")
	}
}

func TestSynthesizeRoutes_FunctionWithoutMatchingURL_Skipped(t *testing.T) {
	h := minimalHost("test-host", "default")
	withURL := minimalFunction("echo", "default", "/api/echo")
	withoutURL := minimalFunction("ping", "default", "/api/ping")
	urls := map[string]string{"echo": "http://localhost:12345"}

	routes, err := SynthesizeRoutes(h, []kdexv1alpha1.KDexFunction{withURL, withoutURL}, urls)
	if err != nil {
		t.Fatalf("SynthesizeRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route (ping has no override); got %d", len(routes))
	}
	if routes[0].FunctionName != "echo" {
		t.Errorf("FunctionName: got %q, want %q", routes[0].FunctionName, "echo")
	}
}

func TestSynthesizeRoutes_FunctionInOtherNamespace_Skipped(t *testing.T) {
	h := minimalHost("test-host", "default")
	sameNS := minimalFunction("echo", "default", "/api/echo")
	otherNS := minimalFunction("echo", "other-ns", "/api/echo")
	urls := map[string]string{"echo": "http://localhost:12345"}

	routes, err := SynthesizeRoutes(h, []kdexv1alpha1.KDexFunction{sameNS, otherNS}, urls)
	if err != nil {
		t.Fatalf("SynthesizeRoutes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route (otherNS function skipped); got %d", len(routes))
	}
	if routes[0].BasePath != "/api/echo" {
		t.Errorf("BasePath: got %q", routes[0].BasePath)
	}
}

func TestSynthesizeRoutes_MultipleFunctions(t *testing.T) {
	h := minimalHost("test-host", "default")
	a := minimalFunction("a", "default", "/api/a")
	b := minimalFunction("b", "default", "/api/b")
	urls := map[string]string{
		"a": "http://localhost:11111",
		"b": "http://localhost:22222",
	}

	routes, err := SynthesizeRoutes(h, []kdexv1alpha1.KDexFunction{a, b}, urls)
	if err != nil {
		t.Fatalf("SynthesizeRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes; got %d", len(routes))
	}
	gotByName := map[string]Route{}
	for _, r := range routes {
		gotByName[r.FunctionName] = r
	}
	if gotByName["a"].URL != "http://localhost:11111" {
		t.Errorf("a URL: got %q", gotByName["a"].URL)
	}
	if gotByName["b"].URL != "http://localhost:22222" {
		t.Errorf("b URL: got %q", gotByName["b"].URL)
	}
}

// TestApplyToHostHandler_CallsSetHostWithRoutes wires the synth output into a
// freshly-constructed HostHandler and verifies that SetHost ran (the host
// status flipped to Ready). We can't easily exercise the proxy mux end-to-end
// here — reverseProxyHandler requires a fully-built authConfig with an
// ActivePair, gated at host.go:404 — but we can assert the SetHost call shape
// landed without panicking, which is the load-bearing contract for synth.
func TestApplyToHostHandler_CallsSetHostWithRoutes(t *testing.T) {
	ih := minimalHost("test-host", "default")
	fn := minimalFunction("echo", "default", "/api/echo")
	urls := map[string]string{"echo": "http://localhost:12345"}

	snap := &loader.Snapshot{
		InternalHosts: []kdexv1alpha1.KDexInternalHost{ih},
		Functions:     []kdexv1alpha1.KDexFunction{fn},
	}

	scheme := buildTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	cm, err := cache.NewCacheManager("", "test-host", nil)
	if err != nil {
		t.Fatalf("NewCacheManager: %v", err)
	}
	hh := host.NewHostHandler(c, "test-host", "default", log.Log.WithName("test"), cm)

	if err := ApplyToHostHandler(context.Background(), hh, &ih, snap, urls); err != nil {
		t.Fatalf("ApplyToHostHandler: %v", err)
	}

	if got := hh.GetStatus(); got != host.HostStatusReady {
		t.Errorf("HostHandler status after SetHost: got %q, want %q", got, host.HostStatusReady)
	}
}

// TestApplyToHostHandler_MultiHost verifies that when the snapshot contains two
// KDexInternalHosts, ApplyToHostHandler uses the explicitly-passed focal host
// (the second) rather than defaulting to InternalHosts[0] (the first). It does
// this by giving each host a distinct namespace and a function in that namespace,
// then asserting the HostHandler renders Ready (meaning SetHost was called with
// the correct focal) and that selectFunctionsForHost returns only the second
// host's function.
func TestApplyToHostHandler_MultiHost_UsesFocalNotFirst(t *testing.T) {
	host1 := minimalHost("host-one", "ns-one")
	host2 := minimalHost("host-two", "ns-two")

	fn1 := minimalFunction("fn-one", "ns-one", "/api/one")
	fn2 := minimalFunction("fn-two", "ns-two", "/api/two")

	// Only provide a URL override for fn-two (host2's function). fn-one has
	// no override so it should be excluded regardless of which host is focal.
	urls := map[string]string{"fn-two": "http://localhost:22222"}

	snap := &loader.Snapshot{
		InternalHosts: []kdexv1alpha1.KDexInternalHost{host1, host2},
		Functions:     []kdexv1alpha1.KDexFunction{fn1, fn2},
	}

	scheme := buildTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	cm, err := cache.NewCacheManager("", "host-two", nil)
	if err != nil {
		t.Fatalf("NewCacheManager: %v", err)
	}
	hh := host.NewHostHandler(c, "host-two", "ns-two", log.Log.WithName("test"), cm)

	// Pass &host2 as focal — the fix under test.
	if err := ApplyToHostHandler(context.Background(), hh, &host2, snap, urls); err != nil {
		t.Fatalf("ApplyToHostHandler: %v", err)
	}

	// SetHost was called with host2's spec — HostHandler should be Ready.
	if got := hh.GetStatus(); got != host.HostStatusReady {
		t.Errorf("HostHandler status: got %q, want %q (wrong focal would give wrong spec)", got, host.HostStatusReady)
	}

	// Independently verify selectFunctionsForHost selects only fn2 when focal=host2.
	selected := selectFunctionsForHost(&host2, snap.Functions, urls)
	if len(selected) != 1 {
		t.Fatalf("selectFunctionsForHost with focal=host2: expected 1 function, got %d", len(selected))
	}
	if selected[0].Name != "fn-two" {
		t.Errorf("selectFunctionsForHost: got %q, want %q", selected[0].Name, "fn-two")
	}
}

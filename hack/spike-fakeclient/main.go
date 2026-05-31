// Package main is the Task-0.1 fake-client spike for the unified `kdex`
// CLI preview tool. It is throwaway — it exists to answer:
//
//  1. Can host-manager's reconcilers run behind sigs.k8s.io/controller-
//     runtime/pkg/client/fake.Client (no apiserver, no manager event loop)?
//  2. Does the resulting populated cache feed internal/web/server such
//     that an HTTP GET returns a 200 with rendered HTML?
//
// See ./README.md for the findings + the PROCEED/ESCALATE recommendation.
//
// Run with `go run ./hack/spike-fakeclient`; success = "status=200" + a
// recognizable HTML fragment printed to stdout.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/controller"
	hostpkg "github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/web/server"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const (
	focalHost = "spike"
	namespace = "default"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "spike failed:", err)
		os.Exit(1)
	}
}

func run() error {
	logger := zap.New(zap.UseDevMode(true))
	ctrl.SetLogger(logger)
	ctx := context.Background()

	// ---- 1. scheme + fixtures -------------------------------------------

	scheme := k8sruntime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(kdexv1alpha1.AddToScheme(scheme))
	utilruntime.Must(configuration.AddToScheme(scheme))

	internalHost, theme, pg, err := loadFixtures(scheme)
	if err != nil {
		return fmt.Errorf("load fixtures: %w", err)
	}

	// Default cluster page archetype — without one, KDexPageReconciler.Reconcile
	// nil-derefs on archetypeObj.GetGeneration() (kdexpage_controller.go:140).
	// In real clusters the operator stack ships one; the spike must too.
	archetype := defaultClusterPageArchetype()

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(
			&kdexv1alpha1.KDexInternalHost{},
			&kdexv1alpha1.KDexPage{},
			&kdexv1alpha1.KDexInternalTranslation{},
			&kdexv1alpha1.KDexInternalUtilityPage{},
		).
		WithObjects(internalHost, theme, pg, archetype).
		Build()

	// ---- 2. wire HostHandler + reconcilers ------------------------------

	cacheManager, _ := cache.NewCacheManager("", focalHost, nil)
	hostHandler := hostpkg.NewHostHandler(c, focalHost, namespace, logger.WithName("host"), cacheManager)

	conf := configuration.LoadConfiguration("/does-not-exist", scheme) // built-in default
	requeueDelay := 1 * time.Second

	// ---- 3. Try the page reconciler directly ----------------------------
	//
	// We invoke r.Reconcile in a manual loop instead of building a controller-
	// runtime Manager: Manager.Start requires a real *rest.Config (it dials
	// the apiserver for leader election + watch streams), which is the
	// entire point we're trying to avoid. Direct Reconcile invocation is
	// the blessed fallback per the task scaffold.
	pageReconciler := &controller.KDexPageReconciler{
		Client:              c,
		Configuration:       conf,
		ControllerNamespace: namespace,
		FocalHost:           focalHost,
		HostHandler:         hostHandler,
		RequeueDelay:        requeueDelay,
		Scheme:              scheme,
	}

	// Two passes: the reconciler adds a finalizer on the first pass and
	// returns Requeue=true, then runs the actual reconcile on the second.
	pageReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: "spike-home", Namespace: namespace}}
	if res, err := pageReconciler.Reconcile(ctx, pageReq); err != nil {
		fmt.Printf("page-reconcile pass-1 (finalizer): res=%+v err=%v (informational)\n", res, err)
	} else {
		fmt.Printf("page-reconcile pass-1 (finalizer): res=%+v ok\n", res)
	}
	if res, err := pageReconciler.Reconcile(ctx, pageReq); err != nil {
		fmt.Printf("page-reconcile pass-2: res=%+v err=%v (informational — see README)\n", res, err)
	} else {
		fmt.Printf("page-reconcile pass-2: res=%+v ok\n", res)
	}

	fmt.Printf("HostHandler.Pages count after page-reconcile: %d\n", hostHandler.Pages.Count())

	// ---- 4. Skip the full KDexInternalHost reconcile --------------------
	//
	// We deliberately do NOT invoke KDexInternalHostReconciler.Reconcile().
	// That method (~570 LOC, ends at kdexinternalhost_controller.go:665)
	// requires, in order:
	//   - Resolved secrets (line 151)
	//   - Created Deployments to reach DeploymentAvailable=True (line 570-595)
	//     before SetHost is ever called. Nothing in fake.Client reconciles
	//     Deployment.Status — they stay forever-not-ready and the host
	//     reconciler loops on RequeueAfter without populating the cache.
	//   - Auth key generation + PASETO/JWT material wiring
	//   - HTTPRoute / Ingress / Service creation
	// All of that is irrelevant to the preview-tool use case (render pages
	// in-memory for a developer). The spike instead synthesizes the
	// minimum SetHost call below to prove that, given a populated
	// HostHandler, the web/server path returns a 200.
	hostHandler.SetHost(
		ctx,
		&internalHost.Spec.KDexHostSpec,
		statusReady(),
		nil,               // packageReferences
		theme.Spec.Assets, // themeAssets — directly threaded from theme.yaml
		nil,               // scripts
		"",                // importmap
		nil,               // paths (initialPaths from controller)
		nil,               // functions
		nil,               // authExchanger — nil-tolerant per host.go ServeHTTP
		nil,               // authConfig — same
		"http",            // scheme
		nil,               // sniffer
		time.Now(),
	)

	// ---- 5. Stand up the server and probe it ----------------------------

	srv := server.New(":0", hostHandler) // address irrelevant — httptest replaces it
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	resp, body, err := getString(ts.URL + "/")
	if err != nil {
		return fmt.Errorf("GET /: %w", err)
	}

	fmt.Printf("status=%d content-type=%q bytes=%d\n", resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
	if len(body) > 600 {
		fmt.Printf("body[:600]=%s...\n", body[:600])
	} else {
		fmt.Printf("body=%s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		// A non-200 here is the spike's useful negative signal: the server
		// is wired but the page route wasn't installed because the page
		// reconciler couldn't fully run. Surface it; don't pretend success.
		return fmt.Errorf("non-200 status: %d (see README §findings for diagnosis)", resp.StatusCode)
	}

	return nil
}

// loadFixtures parses the three YAML files in testdata/ into typed CRD objects.
func loadFixtures(scheme *k8sruntime.Scheme) (*kdexv1alpha1.KDexInternalHost, *kdexv1alpha1.KDexTheme, *kdexv1alpha1.KDexPage, error) {
	dir := testdataDir()
	codecFactory := serializer.NewCodecFactory(scheme)
	decoder := codecFactory.UniversalDeserializer()

	decode := func(path string, into client.Object) error {
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if _, _, err := decoder.Decode(raw, nil, into); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		return nil
	}

	var internalHost kdexv1alpha1.KDexInternalHost
	if err := decode(filepath.Join(dir, "host.yaml"), &internalHost); err != nil {
		return nil, nil, nil, err
	}
	var theme kdexv1alpha1.KDexTheme
	if err := decode(filepath.Join(dir, "theme.yaml"), &theme); err != nil {
		return nil, nil, nil, err
	}
	var pg kdexv1alpha1.KDexPage
	if err := decode(filepath.Join(dir, "page.yaml"), &pg); err != nil {
		return nil, nil, nil, err
	}
	return &internalHost, &theme, &pg, nil
}

// testdataDir resolves the path to ./testdata relative to this source file
// so the spike runs identically whether invoked from the repo root or via
// `go run ./hack/spike-fakeclient`.
func testdataDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "testdata")
}

// defaultClusterPageArchetype synthesizes the minimal cluster-scope
// archetype that ResolveOrDefaultPageArchetype falls back to when a
// KDexPage doesn't specify spec.pageArchetypeRef
// (kdexpage_controller.go:135 → resolver_common.go:317).
func defaultClusterPageArchetype() *kdexv1alpha1.KDexClusterPageArchetype {
	return &kdexv1alpha1.KDexClusterPageArchetype{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "spike-default-archetype",
			Labels: map[string]string{"kdex.dev/default": "true"},
		},
		Spec: kdexv1alpha1.KDexPageArchetypeSpec{
			// Delimiters '[[' / ']]' per render/render.go contract.
			// Single 'main' slot mirrors the page fixture.
			Content: `<!doctype html><html><head><title>[[.Title]]</title>[[.Meta]][[.Theme]][[.HeadScript]]</head><body>[[.Content.main]]</body></html>`,
		},
	}
}

// statusReady returns a Ready=true KDexObjectStatus so HostHandler.GetStatus
// returns HostStatusReady; otherwise ServeHTTP short-circuits to a
// not-ready page for non-system paths (host.go:585).
func statusReady() *kdexv1alpha1.KDexObjectStatus {
	return &kdexv1alpha1.KDexObjectStatus{
		Conditions: []metav1.Condition{
			{
				Type:   string(kdexv1alpha1.ConditionTypeReady),
				Status: metav1.ConditionTrue,
			},
		},
	}
}

// getString performs a plain GET and returns response + body string.
func getString(url string) (*http.Response, string, error) {
	resp, err := http.Get(url) //nolint:gosec // throwaway spike, URL is httptest
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, "", err
	}
	return resp, string(body), nil
}

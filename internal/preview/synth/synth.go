// Package synth synthesizes routing state for HostHandler from CR data +
// function URL overrides, sidestepping the reconcilers that depend on Knative
// status (KDexInternalHostReconciler, KDexFunctionReconciler). Those
// reconcilers can't compose under sigs.k8s.io/controller-runtime/pkg/client/
// fake — they require Deployment.Status/Knative Revision rollout signals the
// fake client never produces. Per the Phase 0 spike (hack/spike-fakeclient),
// the preview tool instead synthesizes their output: it builds the list of
// KDexFunction CRs that SetHost would receive in production, with each
// function's Status.URL patched to the ephemeral URL from the supervised
// child process or the URL-form override, then calls HostHandler.SetHost
// directly.
//
// See ../../../docs/superpowers/plans/2026-06-04-kdex-cli-phase-2-preview-mvp.md §Task 2.6
// for the function-proxy plumbing context.
package synth

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"

	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/preview/loader"
)

// Route is a single proxy route synthesized from a KDexFunction CR + override URL.
//
// FunctionName is the CR's metadata.name; BasePath is Spec.API.BasePath; URL
// is the override target (typically http://127.0.0.1:<ephemeral-port> from the
// supervised child or a static URL-form override).
type Route struct {
	FunctionName string
	BasePath     string
	URL          string
}

// SynthesizeRoutes builds the proxy route list for a host from its
// KDexFunction CRs and the resolved override URLs. Filters:
//
//   - Functions whose Namespace differs from the host's Namespace are skipped
//     (cross-namespace function CRs aren't a thing in the preview model — the
//     loader uses the host's namespace as the "in-cluster" boundary).
//   - Functions with no matching URL in urls are omitted from the output. The
//     caller decides how to surface that (e.g. missing-fn placeholder is the
//     proxy resolver's job, not synth's).
func SynthesizeRoutes(h kdexv1alpha1.KDexInternalHost, fns []kdexv1alpha1.KDexFunction, urls map[string]string) ([]Route, error) {
	selected := selectFunctionsForHost(&h, fns, urls)
	routes := make([]Route, 0, len(selected))
	for _, fn := range selected {
		url := urls[fn.Name]
		routes = append(routes, Route{
			FunctionName: fn.Name,
			BasePath:     fn.Spec.API.BasePath,
			URL:          url,
		})
	}
	return routes, nil
}

// ApplyToHostHandler calls hh.SetHost with the host spec and a synthesized
// function CR list. Each function in the snapshot whose Namespace matches the
// focal host AND has an entry in urls gets a clone whose Status.URL is set to
// the override URL and Status.State is forced to Ready — those are the two
// fields reverseProxyHandler (proxy.go:88) and the registration gate
// (host.go:406) read when wiring the function mux.
//
// focal must be non-nil (the caller — server.Run — guarantees this via
// pickHost). The snapshot's InternalHosts slice is not consulted; focal is
// used directly, which ensures multi-host snapshots with --host selecting a
// non-first host are rendered correctly.
//
// Known gap (Task 2.6 scope): host-manager's reverseProxyHandler also
// short-circuits when hh.authConfig.ActivePair is nil (host.go:404). The
// preview tool's composition root (Task 2.7) is responsible for either
// supplying a synthetic auth config or accepting that the function mux paths
// won't activate. SetHost itself accepts a nil authConfig — that's not a panic
// — so this function is safe to call from a pre-auth context.
//
// SetHost parameters not derivable from the snapshot are passed as their
// zero/nil defaults; ThemeAssets is pulled from the first KDexTheme in the
// snapshot whose name matches host.Spec.ThemeRef (best-effort — the preview
// is render-focused, not auth-focused).
func ApplyToHostHandler(ctx context.Context, hh *host.HostHandler, focal *kdexv1alpha1.KDexInternalHost, snap *loader.Snapshot, urls map[string]string) error {
	// Patch each function CR with the override URL + Ready state so the
	// downstream proxy registration path treats it as a deployed Knative
	// service. Operate on a copy so we don't mutate the loader.Snapshot
	// (which other callers may iterate after us).
	selected := selectFunctionsForHost(focal, snap.Functions, urls)
	synthFns := make([]kdexv1alpha1.KDexFunction, 0, len(selected))
	for _, fn := range selected {
		clone := fn.DeepCopy()
		clone.Status.URL = urls[fn.Name]
		clone.Status.State = kdexv1alpha1.KDexFunctionStateReady
		synthFns = append(synthFns, *clone)
	}

	themeAssets := themeAssetsFor(focal, snap)

	// Match the spike's argument shape (hack/spike-fakeclient/main.go:146-161).
	// nil authExchanger/authConfig are tolerated by ServeHTTP; scheme="http"
	// matches the dev preview's loopback origin.
	hh.SetHost(
		ctx,
		&focal.Spec.KDexHostSpec,
		statusReady(),
		nil,         // packageReferences — Task 2.6 doesn't resolve npm registry references
		themeAssets, // themeAssets — pulled from snapshot's theme if present
		nil,         // scripts
		"",          // importmap — Task 2.6 doesn't synthesize the importmap
		nil,         // paths (initialPaths from controller)
		synthFns,    // functions — the load-bearing synth output
		nil,         // authExchanger
		nil,         // authConfig
		"http",      // scheme
		nil,         // sniffer
		time.Now(),
	)
	return nil
}

// selectFunctionsForHost returns pointers to functions in fns whose namespace
// matches focal's namespace AND have a URL override in urls. The returned
// pointers point into fns — callers must DeepCopy before mutating.
func selectFunctionsForHost(focal *kdexv1alpha1.KDexInternalHost, fns []kdexv1alpha1.KDexFunction, urls map[string]string) []*kdexv1alpha1.KDexFunction {
	var out []*kdexv1alpha1.KDexFunction
	for i := range fns {
		fn := &fns[i]
		if fn.Namespace != focal.Namespace {
			continue
		}
		if _, ok := urls[fn.Name]; !ok {
			continue
		}
		out = append(out, fn)
	}
	return out
}

// themeAssetsFor returns the asset list from the snapshot's KDexTheme that
// matches the host's themeRef, or nil if no match. The match is by name +
// namespace (themes are namespaced CRs; clusterTheme support would be additive).
func themeAssetsFor(ih *kdexv1alpha1.KDexInternalHost, snap *loader.Snapshot) []kdexv1alpha1.Asset {
	if ih.Spec.ThemeRef == nil || ih.Spec.ThemeRef.Name == "" {
		return nil
	}
	wantName := ih.Spec.ThemeRef.Name
	wantNS := ih.Namespace
	for i := range snap.Themes {
		t := &snap.Themes[i]
		if t.Name == wantName && (t.Namespace == "" || t.Namespace == wantNS) {
			return t.Spec.Assets
		}
	}
	return nil
}

// statusReady returns a Ready=true KDexObjectStatus, matching the spike's
// statusReady() helper. Without it HostHandler.GetStatus returns
// HostStatusInitializing and ServeHTTP short-circuits for non-system paths
// (host.go:585).
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

// ErrNoInternalHost is retained for compatibility but is no longer returned by
// ApplyToHostHandler (which now accepts focal directly). Kept so any external
// callers using errors.Is(err, synth.ErrNoInternalHost) don't break.
var ErrNoInternalHost = synthError("snapshot has no KDexInternalHost — cannot synthesize SetHost call")

type synthError string

func (e synthError) Error() string { return string(e) }

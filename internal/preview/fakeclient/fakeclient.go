// Package fakeclient seeds a sigs.k8s.io/controller-runtime/pkg/client/fake
// client from a loader.Snapshot and runs the subset of host-manager's
// reconcilers that compose cleanly behind it (KDexPage,
// KDexInternalTranslation, KDexInternalUtilityPage). The
// KDexInternalHostReconciler and KDexFunctionReconciler are intentionally
// skipped — they depend on apiserver behaviors (Deployment.Status
// availability, secret resolution, Knative Revision rollout) that
// fake.Client cannot synthesize. Their effects on HostHandler state are
// applied in Task 2.6 (synth) via a direct HostHandler.SetHost call
// projected from CR data.
//
// Constructor signatures + reconciler-field shapes were validated by the
// Phase 0 spike at hack/spike-fakeclient/.
package fakeclient

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/configuration"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/controller"
	"github.com/kdex-tech/host-manager/internal/host"
	"github.com/kdex-tech/host-manager/internal/preview/loader"
)

// defaultRequeueDelay matches the production controller wiring so that
// reconcilers don't take a special-case path for a 0 delay. Preview never
// actually sleeps on it — we call Reconcile directly and move on.
const defaultRequeueDelay = 1 * time.Second

// defaultNamespace is the Kubernetes namespace used when a CR carries no
// explicit namespace (e.g. snapshot fixtures loaded from plain YAML).
const defaultNamespace = "default"

// FakeClient bundles the fake client + the populated state that subsequent
// preview-tool tasks (synth, server) consume.
type FakeClient struct {
	Client       client.Client
	CacheManager cache.CacheManager
	HostHandler  *host.HostHandler
	Scheme       *runtime.Scheme
}

// SetupOptions configures Setup's host selection behavior.
type SetupOptions struct {
	// FocalHostName, if non-empty, overrides the default first-InternalHost
	// pick. Use when the caller has already selected a specific host (e.g.
	// via `--host` flag) so that the fakeclient and the server's outer proxy
	// mux agree on which host is focal.
	FocalHostName string
}

// Setup builds the fake client, runs the page/translation/utility reconcilers
// to populate the HostHandler from snap's CR data, and returns the assembled
// FakeClient. The KDexInternalHost and KDexFunction reconcilers are not
// driven; their state is synthesized in Task 2.6 from CR data + overrides.
//
// Per the spike findings, callers must NOT expect a populated HostHandler.host
// after Setup — only the Pages / Translations / UtilityPages maps mutated by
// the simpler reconcilers. SetHost is the synth-stage responsibility.
func Setup(ctx context.Context, snap *loader.Snapshot) (*FakeClient, error) {
	return SetupWithOptions(ctx, snap, SetupOptions{})
}

// SetupWithOptions is like Setup but accepts explicit options. Use when the
// caller has already selected a focal host (e.g. via pickHost / --host flag)
// so the fakeclient's reconciler filtering agrees with the server's outer mux.
func SetupWithOptions(ctx context.Context, snap *loader.Snapshot, opts SetupOptions) (*FakeClient, error) {
	scheme := buildScheme()
	focalHost, namespace, err := deriveFocalHostAndNamespace(snap, opts.FocalHostName)
	if err != nil {
		return nil, fmt.Errorf("derive focal host: %w", err)
	}

	objs := snapshotToObjects(snap)
	if def := ensureDefaultArchetype(snap); def != nil {
		objs = append(objs, def)
	}

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(
			&kdexv1alpha1.KDexInternalHost{},
			&kdexv1alpha1.KDexPage{},
			&kdexv1alpha1.KDexInternalTranslation{},
			&kdexv1alpha1.KDexInternalUtilityPage{},
		).
		WithObjects(objs...).
		Build()

	cacheManager, err := cache.NewCacheManager("", focalHost, nil)
	if err != nil {
		return nil, fmt.Errorf("cache.NewCacheManager: %w", err)
	}

	logger := log.Log.WithName("preview-fakeclient")
	hostHandler := host.NewHostHandler(c, focalHost, namespace, logger.WithName("host"), cacheManager)

	// LoadConfiguration with a missing path returns the embedded YAML
	// defaults. Per the spike, configuration.AddToScheme(scheme) must have
	// happened first (done in buildScheme).
	conf := configuration.LoadConfiguration("/does-not-exist", scheme)

	if err := reconcilePages(ctx, c, scheme, conf, focalHost, namespace, hostHandler, snap); err != nil {
		return nil, fmt.Errorf("reconcile pages: %w", err)
	}
	if err := reconcileTranslations(ctx, c, scheme, focalHost, namespace, hostHandler, snap); err != nil {
		return nil, fmt.Errorf("reconcile translations: %w", err)
	}
	if err := reconcileUtilityPages(ctx, c, scheme, conf, focalHost, namespace, hostHandler, snap); err != nil {
		return nil, fmt.Errorf("reconcile utility pages: %w", err)
	}

	return &FakeClient{
		Client:       c,
		CacheManager: cacheManager,
		HostHandler:  hostHandler,
		Scheme:       scheme,
	}, nil
}

// buildScheme registers the three schemes the reconcilers + LoadConfiguration
// reach into: core k8s, kdex CRDs, and the embedded NexusConfiguration kind.
func buildScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(kdexv1alpha1.AddToScheme(s))
	utilruntime.Must(configuration.AddToScheme(s))
	return s
}

// deriveFocalHostAndNamespace picks a (focal-host name, controller-namespace)
// pair from the snapshot. The reconcilers gate on both: req.Namespace must
// equal ControllerNamespace, and KDexPage.Spec.HostRef.Name must equal
// FocalHost, or the reconcile is a no-op.
//
// If explicitName is non-empty, the InternalHost with that name is selected
// (error if not found). Otherwise the preference order is:
//   - first InternalHost (preview's intended driver)
//   - first Page's hostRef + namespace (covers minimal fixtures with just
//     theme + page)
//
// Returns an error when the snapshot contains neither, so Setup surfaces a
// clear diagnostic instead of silently producing an empty HostHandler.
func deriveFocalHostAndNamespace(snap *loader.Snapshot, explicitName string) (focalHost, namespace string, err error) {
	if explicitName != "" {
		for i := range snap.InternalHosts {
			if snap.InternalHosts[i].Name == explicitName {
				ih := &snap.InternalHosts[i]
				ns := ih.Namespace
				if ns == "" {
					ns = defaultNamespace
				}
				return ih.Name, ns, nil
			}
		}
		return "", "", fmt.Errorf("no KDexInternalHost named %q in snapshot", explicitName)
	}
	if len(snap.InternalHosts) > 0 {
		ih := &snap.InternalHosts[0]
		ns := ih.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return ih.Name, ns, nil
	}
	if len(snap.Pages) > 0 {
		pg := &snap.Pages[0]
		ns := pg.Namespace
		if ns == "" {
			ns = defaultNamespace
		}
		return pg.Spec.HostRef.Name, ns, nil
	}
	return "", "", fmt.Errorf("snapshot has no KDexInternalHost and no KDexPage to derive focal host from")
}

// stampReadyCondition sets status.conditions = [{type: Ready, status: True}] on
// the given page-composition object. This is the preview fakeclient's stand-in
// for the per-kind reconcilers that run in a real cluster and stamp the Ready
// condition after validating the CR. Without it,
// controller/resolver_common.go:ResolveKDexObjectReference bails (shouldReturn=true)
// and pages that reference any of these kinds never land in HostHandler.Pages —
// meaning RebuildMux registers no page handlers and GET / returns 404.
//
// These 10 kinds are NOT in WithStatusSubresource(...), so the fake client
// serves the status field directly from the seeded object rather than
// requiring a separate Status().Update call.
//
// Mutates the object in place. Safe because Snapshot objects are consumed once
// by Setup and discarded.
func stampReadyCondition(obj client.Object) {
	ready := metav1.Condition{
		Type:               string(kdexv1alpha1.ConditionTypeReady),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Time{},
		Reason:             "PreviewSynthesized",
		Message:            "synthesized by kdex preview fakeclient",
	}
	switch o := obj.(type) {
	case *kdexv1alpha1.KDexPageArchetype:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexClusterPageArchetype:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexPageHeader:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexClusterPageHeader:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexPageFooter:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexClusterPageFooter:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexPageNavigation:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexClusterPageNavigation:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexScriptLibrary:
		o.Status.Conditions = []metav1.Condition{ready}
	case *kdexv1alpha1.KDexClusterScriptLibrary:
		o.Status.Conditions = []metav1.Condition{ready}
	}
}

// snapshotToObjects builds the seed objects list. Apps + Functions are NOT
// included; their proxy targets are synthesized in Task 2.6.
//
// stampReadyCondition is called on each page-composition object (the 10 chrome
// kinds) before appending. In a real cluster, each kind's own reconciler stamps
// Ready=True after validating the CR; here the fakeclient does it at seed time
// so that KDexPageReconciler.ResolveKDexObjectReference does not bail early.
func snapshotToObjects(snap *loader.Snapshot) []client.Object {
	out := make([]client.Object, 0,
		len(snap.Themes)+
			len(snap.Pages)+
			len(snap.InternalHosts)+
			len(snap.InternalTranslations)+
			len(snap.InternalUtilityPages)+
			len(snap.ClusterPageArchetypes)+
			len(snap.PageArchetypes)+
			len(snap.PageHeaders)+
			len(snap.PageFooters)+
			len(snap.PageNavigations)+
			len(snap.ScriptLibraries)+
			len(snap.ClusterPageHeaders)+
			len(snap.ClusterPageFooters)+
			len(snap.ClusterPageNavigations)+
			len(snap.ClusterScriptLibraries),
	)
	for i := range snap.Themes {
		out = append(out, &snap.Themes[i])
	}
	for i := range snap.Pages {
		out = append(out, &snap.Pages[i])
	}
	for i := range snap.InternalHosts {
		out = append(out, &snap.InternalHosts[i])
	}
	for i := range snap.InternalTranslations {
		out = append(out, &snap.InternalTranslations[i])
	}
	for i := range snap.InternalUtilityPages {
		out = append(out, &snap.InternalUtilityPages[i])
	}
	for i := range snap.ClusterPageArchetypes {
		stampReadyCondition(&snap.ClusterPageArchetypes[i])
		out = append(out, &snap.ClusterPageArchetypes[i])
	}
	for i := range snap.PageArchetypes {
		stampReadyCondition(&snap.PageArchetypes[i])
		out = append(out, &snap.PageArchetypes[i])
	}
	for i := range snap.PageHeaders {
		stampReadyCondition(&snap.PageHeaders[i])
		out = append(out, &snap.PageHeaders[i])
	}
	for i := range snap.PageFooters {
		stampReadyCondition(&snap.PageFooters[i])
		out = append(out, &snap.PageFooters[i])
	}
	for i := range snap.PageNavigations {
		stampReadyCondition(&snap.PageNavigations[i])
		out = append(out, &snap.PageNavigations[i])
	}
	for i := range snap.ScriptLibraries {
		stampReadyCondition(&snap.ScriptLibraries[i])
		out = append(out, &snap.ScriptLibraries[i])
	}
	for i := range snap.ClusterPageHeaders {
		stampReadyCondition(&snap.ClusterPageHeaders[i])
		out = append(out, &snap.ClusterPageHeaders[i])
	}
	for i := range snap.ClusterPageFooters {
		stampReadyCondition(&snap.ClusterPageFooters[i])
		out = append(out, &snap.ClusterPageFooters[i])
	}
	for i := range snap.ClusterPageNavigations {
		stampReadyCondition(&snap.ClusterPageNavigations[i])
		out = append(out, &snap.ClusterPageNavigations[i])
	}
	for i := range snap.ClusterScriptLibraries {
		stampReadyCondition(&snap.ClusterScriptLibraries[i])
		out = append(out, &snap.ClusterScriptLibraries[i])
	}
	return out
}

// ensureDefaultArchetype injects a minimal default KDexClusterPageArchetype
// labeled kdex.dev/default=true if the snapshot doesn't already contain one.
// Without this, KDexPageReconciler.Reconcile nil-derefs in
// ResolveOrDefaultPageArchetype → archetypeObj.GetGeneration() per the spike
// finding (kdexpage_controller.go:140). The literal is copied from
// hack/spike-fakeclient/main.go.
func ensureDefaultArchetype(snap *loader.Snapshot) client.Object {
	for i := range snap.ClusterPageArchetypes {
		if snap.ClusterPageArchetypes[i].Labels["kdex.dev/default"] == "true" {
			return nil
		}
	}
	def := &kdexv1alpha1.KDexClusterPageArchetype{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "preview-default-archetype",
			Labels: map[string]string{"kdex.dev/default": "true"},
		},
		Spec: kdexv1alpha1.KDexPageArchetypeSpec{
			// Delimiters '[[' / ']]' per render/render.go contract. Single
			// 'main' slot mirrors the loader fixtures.
			Content: `<!doctype html><html><head><title>[[.Title]]</title>[[.Meta]][[.Theme]][[.HeadScript]]</head><body>[[.Content.main]]</body></html>`,
		},
	}
	stampReadyCondition(def)
	return def
}

// reconcilePages runs KDexPageReconciler.Reconcile twice per page (per the
// spike's two-pass pattern: first pass adds the finalizer + requeues, second
// pass does the real work). Errors are recorded and returned to the caller —
// preview surfaces them but does not abort, since a partial render is still
// useful for diagnosing CR mistakes.
func reconcilePages(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	conf configuration.NexusConfiguration,
	focalHost, namespace string,
	hh *host.HostHandler,
	snap *loader.Snapshot,
) error {
	r := &controller.KDexPageReconciler{
		Client:              c,
		Configuration:       conf,
		ControllerNamespace: namespace,
		FocalHost:           focalHost,
		HostHandler:         hh,
		RequeueDelay:        defaultRequeueDelay,
		Scheme:              scheme,
	}
	for i := range snap.Pages {
		pg := &snap.Pages[i]
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: pg.Name, Namespace: pg.Namespace}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("page %s/%s pass-1: %w", pg.Namespace, pg.Name, err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("page %s/%s pass-2: %w", pg.Namespace, pg.Name, err)
		}
	}
	return nil
}

// reconcileTranslations runs KDexInternalTranslationReconciler.Reconcile twice
// per translation (same finalizer two-pass pattern).
func reconcileTranslations(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	focalHost, namespace string,
	hh *host.HostHandler,
	snap *loader.Snapshot,
) error {
	r := &controller.KDexInternalTranslationReconciler{
		Client:              c,
		ControllerNamespace: namespace,
		FocalHost:           focalHost,
		HostHandler:         hh,
		RequeueDelay:        defaultRequeueDelay,
		Scheme:              scheme,
	}
	for i := range snap.InternalTranslations {
		tr := &snap.InternalTranslations[i]
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: tr.Name, Namespace: tr.Namespace}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("translation %s/%s pass-1: %w", tr.Namespace, tr.Name, err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("translation %s/%s pass-2: %w", tr.Namespace, tr.Name, err)
		}
	}
	return nil
}

// reconcileUtilityPages runs KDexInternalUtilityPageReconciler.Reconcile twice
// per utility page (same finalizer two-pass pattern).
func reconcileUtilityPages(
	ctx context.Context,
	c client.Client,
	scheme *runtime.Scheme,
	conf configuration.NexusConfiguration,
	focalHost, namespace string,
	hh *host.HostHandler,
	snap *loader.Snapshot,
) error {
	r := &controller.KDexInternalUtilityPageReconciler{
		Client:              c,
		Configuration:       conf,
		ControllerNamespace: namespace,
		FocalHost:           focalHost,
		HostHandler:         hh,
		RequeueDelay:        defaultRequeueDelay,
		Scheme:              scheme,
	}
	for i := range snap.InternalUtilityPages {
		up := &snap.InternalUtilityPages[i]
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: up.Name, Namespace: up.Namespace}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("utility-page %s/%s pass-1: %w", up.Namespace, up.Name, err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			return fmt.Errorf("utility-page %s/%s pass-2: %w", up.Namespace, up.Name, err)
		}
	}
	return nil
}

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

// Setup builds the fake client, runs the page/translation/utility reconcilers
// to populate the HostHandler from snap's CR data, and returns the assembled
// FakeClient. The KDexInternalHost and KDexFunction reconcilers are not
// driven; their state is synthesized in Task 2.6 from CR data + overrides.
//
// Per the spike findings, callers must NOT expect a populated HostHandler.host
// after Setup — only the Pages / Translations / UtilityPages maps mutated by
// the simpler reconcilers. SetHost is the synth-stage responsibility.
func Setup(ctx context.Context, snap *loader.Snapshot) (*FakeClient, error) {
	scheme := buildScheme()
	focalHost, namespace, err := deriveFocalHostAndNamespace(snap)
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
// FocalHost, or the reconcile is a no-op. Preference order:
//   - first InternalHost (preview's intended driver)
//   - first Page's hostRef + namespace (covers minimal fixtures with just
//     theme + page)
//
// Returns an error when the snapshot contains neither, so Setup surfaces a
// clear diagnostic instead of silently producing an empty HostHandler.
func deriveFocalHostAndNamespace(snap *loader.Snapshot) (focalHost, namespace string, err error) {
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

// snapshotToObjects builds the seed objects list. Apps + Functions are NOT
// included; their proxy targets are synthesized in Task 2.6.
func snapshotToObjects(snap *loader.Snapshot) []client.Object {
	out := make([]client.Object, 0, len(snap.Themes)+len(snap.Pages)+len(snap.InternalHosts)+len(snap.InternalTranslations)+len(snap.InternalUtilityPages)+len(snap.ClusterPageArchetypes))
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
		out = append(out, &snap.ClusterPageArchetypes[i])
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
	return &kdexv1alpha1.KDexClusterPageArchetype{
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

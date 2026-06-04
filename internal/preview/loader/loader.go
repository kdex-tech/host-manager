// Package loader reads KDex CRs from a directory of YAML files and returns
// a typed Snapshot. Multi-doc YAML is supported. Subdirectories are walked
// recursively. Files not matching *.yaml or *.yml are ignored.
//
// User-facing CRs (KDexHost, KDexTranslation, KDexUtilityPage) are projected
// to their post-reconcile Internal* equivalents at load time via the
// internal/preview/projector package — preview consumes the same form as
// host-manager's in-cluster reconcilers. KDexPageArchetype and
// KDexClusterPageArchetype are independent kinds (no projection); both are
// loaded into the Snapshot for the fake client to seed.
//
// Page-composition kinds (KDexPageHeader, KDexPageFooter, KDexPageNavigation,
// KDexScriptLibrary plus their cluster-scoped siblings) have no projection —
// host-manager's page reconciler reads them directly from the API server, and
// the fake client serves them at reconcile time.
//
// Kinds orthogonal to page rendering (KDexRole, KDexRoleBinding) are silently
// ignored. Kustomize support is deferred to Phase 4.
package loader

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/kdex-tech/host-manager/internal/preview/projector"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Snapshot is the typed view of the CR state on disk at the time Load was called.
type Snapshot struct {
	InternalHosts         []kdexv1alpha1.KDexInternalHost
	Themes                []kdexv1alpha1.KDexTheme
	Pages                 []kdexv1alpha1.KDexPage
	Apps                  []kdexv1alpha1.KDexApp
	Functions             []kdexv1alpha1.KDexFunction
	InternalTranslations  []kdexv1alpha1.KDexInternalTranslation
	InternalUtilityPages  []kdexv1alpha1.KDexInternalUtilityPage
	ClusterPageArchetypes []kdexv1alpha1.KDexClusterPageArchetype

	// Page-composition kinds (C.6): consumed directly by host-manager's page
	// reconciler; no projection step required.
	PageArchetypes         []kdexv1alpha1.KDexPageArchetype
	PageHeaders            []kdexv1alpha1.KDexPageHeader
	PageFooters            []kdexv1alpha1.KDexPageFooter
	PageNavigations        []kdexv1alpha1.KDexPageNavigation
	ScriptLibraries        []kdexv1alpha1.KDexScriptLibrary
	ClusterPageHeaders     []kdexv1alpha1.KDexClusterPageHeader
	ClusterPageFooters     []kdexv1alpha1.KDexClusterPageFooter
	ClusterPageNavigations []kdexv1alpha1.KDexClusterPageNavigation
	ClusterScriptLibraries []kdexv1alpha1.KDexClusterScriptLibrary
}

// rawBuckets accumulates all decoded CRs before materialization. The two-phase
// design lets Task C.5 inject projectUserFacing(buckets) between decode and
// materialize so that KDexHost → KDexInternalHost projection has all
// KDexUtilityPage + KDexTranslation objects in scope when it runs.
type rawBuckets struct {
	// Post-reconcile kinds (passed through unchanged)
	internalHosts         []kdexv1alpha1.KDexInternalHost
	internalTranslations  []kdexv1alpha1.KDexInternalTranslation
	internalUtilityPages  []kdexv1alpha1.KDexInternalUtilityPage
	clusterPageArchetypes []kdexv1alpha1.KDexClusterPageArchetype

	// Direct-consumption kinds
	themes    []kdexv1alpha1.KDexTheme
	pages     []kdexv1alpha1.KDexPage
	apps      []kdexv1alpha1.KDexApp
	functions []kdexv1alpha1.KDexFunction

	// User-facing kinds (projected to Internal*/Cluster* in Task C.5; buffered here for now)
	userHosts          []kdexv1alpha1.KDexHost
	userTranslations   []kdexv1alpha1.KDexTranslation
	userUtilityPages   []kdexv1alpha1.KDexUtilityPage
	userPageArchetypes []kdexv1alpha1.KDexPageArchetype

	// Page-composition kinds (C.6): no projection; loaded directly into Snapshot.
	pageHeaders            []kdexv1alpha1.KDexPageHeader
	pageFooters            []kdexv1alpha1.KDexPageFooter
	pageNavigations        []kdexv1alpha1.KDexPageNavigation
	scriptLibraries        []kdexv1alpha1.KDexScriptLibrary
	clusterPageHeaders     []kdexv1alpha1.KDexClusterPageHeader
	clusterPageFooters     []kdexv1alpha1.KDexClusterPageFooter
	clusterPageNavigations []kdexv1alpha1.KDexClusterPageNavigation
	clusterScriptLibraries []kdexv1alpha1.KDexClusterScriptLibrary
}

// materializeSnapshot projects rawBuckets into the public Snapshot type.
// Task C.5 will call projectUserFacing(buckets) before this to fold
// user-facing CRs into the post-reconcile bucket fields.
func materializeSnapshot(b *rawBuckets) *Snapshot {
	return &Snapshot{
		InternalHosts:          b.internalHosts,
		Themes:                 b.themes,
		Pages:                  b.pages,
		Apps:                   b.apps,
		Functions:              b.functions,
		InternalTranslations:   b.internalTranslations,
		InternalUtilityPages:   b.internalUtilityPages,
		ClusterPageArchetypes:  b.clusterPageArchetypes,
		PageArchetypes:         b.userPageArchetypes,
		PageHeaders:            b.pageHeaders,
		PageFooters:            b.pageFooters,
		PageNavigations:        b.pageNavigations,
		ScriptLibraries:        b.scriptLibraries,
		ClusterPageHeaders:     b.clusterPageHeaders,
		ClusterPageFooters:     b.clusterPageFooters,
		ClusterPageNavigations: b.clusterPageNavigations,
		ClusterScriptLibraries: b.clusterScriptLibraries,
	}
}

// Load walks dir recursively for *.yaml/*.yml files, decodes them into Snapshot,
// and returns the Snapshot. Multi-doc YAML files are split on the standard
// document separator. Unknown kinds are ignored (not an error) — this lets a
// user's CR dir contain non-KDex resources without breaking preview.
func Load(dir string) (*Snapshot, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	buckets := &rawBuckets{}

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return decodeDocs(path, data, buckets)
	})
	if err != nil {
		return nil, err
	}
	if err := projectUserFacing(buckets); err != nil {
		return nil, fmt.Errorf("projection: %w", err)
	}
	return materializeSnapshot(buckets), nil
}

func decodeDocs(path string, data []byte, b *rawBuckets) error {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for docIdx := 0; ; docIdx++ {
		doc, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		doc = bytes.TrimSpace(doc)
		if len(doc) == 0 {
			continue
		}
		if err := decodeOne(path, docIdx, doc, b); err != nil {
			return err
		}
	}
}

// projectUserFacing translates user-facing KDexHost/Translation/UtilityPage
// into the post-reconcile Internal* equivalents and appends them to the
// buckets. Warnings are logged to stderr.
func projectUserFacing(b *rawBuckets) error {
	for _, host := range b.userHosts {
		// Filter translations + utility pages by namespace (only those in the
		// host's namespace can be referenced by it).
		var hostNSTranslations []kdexv1alpha1.KDexTranslation
		for _, tr := range b.userTranslations {
			if tr.Namespace == host.Namespace {
				hostNSTranslations = append(hostNSTranslations, tr)
			}
		}
		var hostNSUtilityPages []kdexv1alpha1.KDexUtilityPage
		for _, up := range b.userUtilityPages {
			if up.Namespace == host.Namespace {
				hostNSUtilityPages = append(hostNSUtilityPages, up)
			}
		}

		ph, err := projector.ProjectHost(host, projector.ProjectInput{
			UtilityPages: hostNSUtilityPages,
			Translations: hostNSTranslations,
		})
		if err != nil {
			return fmt.Errorf("project host %s/%s: %w", host.Namespace, host.Name, err)
		}
		for _, w := range ph.Warnings {
			_, _ = fmt.Fprintln(os.Stderr, "preview: projection warning:", w)
		}
		b.internalHosts = append(b.internalHosts, ph.KDexInternalHost)

		// Project each utility page referenced by this host.
		if host.Spec.UtilityPages != nil {
			projectUPRef(b, host, host.Spec.UtilityPages.LoginRef, hostNSUtilityPages)
			projectUPRef(b, host, host.Spec.UtilityPages.ErrorRef, hostNSUtilityPages)
			projectUPRef(b, host, host.Spec.UtilityPages.AnnouncementRef, hostNSUtilityPages)
		}

		// Project each translation referenced by this host.
		for _, ref := range host.Spec.TranslationRefs {
			for _, tr := range hostNSTranslations {
				if tr.Name == ref.Name {
					b.internalTranslations = append(b.internalTranslations, projector.ProjectTranslation(tr, host))
					break
				}
			}
		}
	}
	return nil
}

func projectUPRef(b *rawBuckets, host kdexv1alpha1.KDexHost, ref *kdexv1alpha1.KDexObjectReference, pages []kdexv1alpha1.KDexUtilityPage) {
	if ref == nil {
		return
	}
	for _, up := range pages {
		if up.Name == ref.Name {
			b.internalUtilityPages = append(b.internalUtilityPages, projector.ProjectUtilityPage(up, host))
			return
		}
	}
}

// peek at apiVersion/kind to decide which typed list to append to.
type meta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func decodeOne(path string, docIdx int, doc []byte, b *rawBuckets) error {
	var m meta
	if err := yaml.Unmarshal(doc, &m); err != nil {
		return fmt.Errorf("%s doc %d: parse meta: %w", path, docIdx, err)
	}
	if m.APIVersion != "kdex.dev/v1alpha1" {
		return nil // ignore non-KDex resources
	}
	if err := decodeCoreKinds(path, docIdx, doc, m.Kind, b); err != nil {
		return err
	}
	return decodePageCompositionKinds(path, docIdx, doc, m.Kind, b)
}

// decodeCoreKinds handles the host/theme/page/app/function and
// translation/utility-page/archetype CR kinds.
func decodeCoreKinds(path string, docIdx int, doc []byte, kind string, b *rawBuckets) error {
	switch kind {
	case "KDexInternalHost":
		var obj kdexv1alpha1.KDexInternalHost
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.internalHosts = append(b.internalHosts, obj)
	case "KDexTheme":
		var obj kdexv1alpha1.KDexTheme
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.themes = append(b.themes, obj)
	case "KDexPage":
		var obj kdexv1alpha1.KDexPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.pages = append(b.pages, obj)
	case "KDexApp":
		var obj kdexv1alpha1.KDexApp
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.apps = append(b.apps, obj)
	case "KDexFunction":
		var obj kdexv1alpha1.KDexFunction
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.functions = append(b.functions, obj)
	case "KDexInternalTranslation":
		var obj kdexv1alpha1.KDexInternalTranslation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.internalTranslations = append(b.internalTranslations, obj)
	case "KDexInternalUtilityPage":
		var obj kdexv1alpha1.KDexInternalUtilityPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.internalUtilityPages = append(b.internalUtilityPages, obj)
	case "KDexClusterPageArchetype":
		var obj kdexv1alpha1.KDexClusterPageArchetype
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.clusterPageArchetypes = append(b.clusterPageArchetypes, obj)
	case "KDexHost":
		var obj kdexv1alpha1.KDexHost
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.userHosts = append(b.userHosts, obj)
	case "KDexTranslation":
		var obj kdexv1alpha1.KDexTranslation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.userTranslations = append(b.userTranslations, obj)
	case "KDexUtilityPage":
		var obj kdexv1alpha1.KDexUtilityPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.userUtilityPages = append(b.userUtilityPages, obj)
	case "KDexPageArchetype":
		var obj kdexv1alpha1.KDexPageArchetype
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.userPageArchetypes = append(b.userPageArchetypes, obj)
	}
	return nil
}

// decodePageCompositionKinds handles the namespace-scoped and cluster-scoped
// page-chrome CR kinds (header/footer/navigation/scriptlibrary). These are
// consumed directly by host-manager's page reconciler; no projection step.
func decodePageCompositionKinds(path string, docIdx int, doc []byte, kind string, b *rawBuckets) error {
	switch kind {
	case "KDexPageHeader":
		var obj kdexv1alpha1.KDexPageHeader
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.pageHeaders = append(b.pageHeaders, obj)
	case "KDexPageFooter":
		var obj kdexv1alpha1.KDexPageFooter
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.pageFooters = append(b.pageFooters, obj)
	case "KDexPageNavigation":
		var obj kdexv1alpha1.KDexPageNavigation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.pageNavigations = append(b.pageNavigations, obj)
	case "KDexScriptLibrary":
		var obj kdexv1alpha1.KDexScriptLibrary
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.scriptLibraries = append(b.scriptLibraries, obj)
	case "KDexClusterPageHeader":
		var obj kdexv1alpha1.KDexClusterPageHeader
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.clusterPageHeaders = append(b.clusterPageHeaders, obj)
	case "KDexClusterPageFooter":
		var obj kdexv1alpha1.KDexClusterPageFooter
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.clusterPageFooters = append(b.clusterPageFooters, obj)
	case "KDexClusterPageNavigation":
		var obj kdexv1alpha1.KDexClusterPageNavigation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.clusterPageNavigations = append(b.clusterPageNavigations, obj)
	case "KDexClusterScriptLibrary":
		var obj kdexv1alpha1.KDexClusterScriptLibrary
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		b.clusterScriptLibraries = append(b.clusterScriptLibraries, obj)
	default:
		// Silently ignore other kdex.dev kinds that are orthogonal to
		// preview's rendering scope (KDexRole, KDexRoleBinding, etc.).
	}
	return nil
}

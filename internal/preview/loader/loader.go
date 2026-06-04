// Package loader reads KDex CRs from a directory of YAML files and returns
// a typed Snapshot. Multi-doc YAML is supported. Subdirectories are walked
// recursively. Files not matching *.yaml or *.yml are ignored.
//
// Kustomize support is deferred to Phase 4 of the preview implementation.
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
}

// materializeSnapshot projects rawBuckets into the public Snapshot type.
// Task C.5 will call projectUserFacing(buckets) before this to fold
// user-facing CRs into the post-reconcile bucket fields.
func materializeSnapshot(b *rawBuckets) *Snapshot {
	return &Snapshot{
		InternalHosts:         b.internalHosts,
		Themes:                b.themes,
		Pages:                 b.pages,
		Apps:                  b.apps,
		Functions:             b.functions,
		InternalTranslations:  b.internalTranslations,
		InternalUtilityPages:  b.internalUtilityPages,
		ClusterPageArchetypes: b.clusterPageArchetypes,
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
	// Task C.5 will inject projectUserFacing(buckets) here before materialization.
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
	switch m.Kind {
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
	case "KDexPageHeader", "KDexPageFooter", "KDexPageNavigation", "KDexScriptLibrary":
		// Page-composition CRs referenced by KDexPage. The loader doesn't
		// wire them yet; surface that explicitly so the user knows their
		// page chrome will be missing rather than just looking broken.
		return fmt.Errorf("%s doc %d: %s is not yet supported by preview (page-composition CRs land in Phase 3)", path, docIdx, m.Kind)
	default:
		// Silently ignore other kdex.dev kinds that are orthogonal to
		// preview's rendering scope (KDexRole, KDexRoleBinding, etc.).
	}
	return nil
}

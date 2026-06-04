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

	snap := &Snapshot{}

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
		return decodeDocs(path, data, snap)
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func decodeDocs(path string, data []byte, snap *Snapshot) error {
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
		if err := decodeOne(path, docIdx, doc, snap); err != nil {
			return err
		}
	}
}

// peek at apiVersion/kind to decide which typed list to append to.
type meta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

func decodeOne(path string, docIdx int, doc []byte, snap *Snapshot) error {
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
		snap.InternalHosts = append(snap.InternalHosts, obj)
	case "KDexTheme":
		var obj kdexv1alpha1.KDexTheme
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Themes = append(snap.Themes, obj)
	case "KDexPage":
		var obj kdexv1alpha1.KDexPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Pages = append(snap.Pages, obj)
	case "KDexApp":
		var obj kdexv1alpha1.KDexApp
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Apps = append(snap.Apps, obj)
	case "KDexFunction":
		var obj kdexv1alpha1.KDexFunction
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.Functions = append(snap.Functions, obj)
	case "KDexInternalTranslation":
		var obj kdexv1alpha1.KDexInternalTranslation
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.InternalTranslations = append(snap.InternalTranslations, obj)
	case "KDexInternalUtilityPage":
		var obj kdexv1alpha1.KDexInternalUtilityPage
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.InternalUtilityPages = append(snap.InternalUtilityPages, obj)
	case "KDexClusterPageArchetype":
		var obj kdexv1alpha1.KDexClusterPageArchetype
		if err := yaml.Unmarshal(doc, &obj); err != nil {
			return fmt.Errorf("%s doc %d: %w", path, docIdx, err)
		}
		snap.ClusterPageArchetypes = append(snap.ClusterPageArchetypes, obj)
	default:
		// Silently ignore other kdex.dev kinds we don't yet handle. Phase 2
		// scope: only the kinds listed above.
	}
	return nil
}

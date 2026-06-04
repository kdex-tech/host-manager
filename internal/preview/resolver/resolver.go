// Package resolver parses CLI/config-file override flags into typed
// structures that downstream packages (loader, supervisor, server) consume.
package resolver

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// FnOverrideKind is "dir" or "url" — determined at parse time.
type FnOverrideKind int

const (
	FnOverrideURL FnOverrideKind = iota
	FnOverrideDir
)

// FnLang is the recognized function-project language. v1 supports Go only;
// FnLangNode is reserved for when `kdex codegen node` lands.
type FnLang int

const (
	FnLangUnknown FnLang = iota
	FnLangGo
	FnLangNode
)

// FnOverride is one entry from a --fn flag or the config file's `functions:` map.
type FnOverride struct {
	Name string
	Kind FnOverrideKind
	URL  string // populated when Kind == FnOverrideURL OR after Supervisor binds a port
	Dir  string // populated when Kind == FnOverrideDir
	Lang FnLang  // populated when Kind == FnOverrideDir
}

// ThemeOverride and AppOverride are simpler: name + URL-or-path. Theme and app
// can both accept either a local filesystem path (served by preview at
// /__preview/{themes,apps}/<name>/) or an http(s) URL passed through.
type ThemeOverride struct {
	Name string
	// Path is set if the value is an existing local directory; otherwise URL.
	Path string
	URL  string
}

type AppOverride struct {
	Name string
	Path string
	URL  string
}

// MissingAppMode controls behavior when a referenced app has no override.
type MissingAppMode int

const (
	MissingAppPlaceholder MissingAppMode = iota
	MissingAppSkip
	MissingAppError
)

// MissingFnMode mirrors MissingAppMode for functions.
type MissingFnMode int

const (
	MissingFnPlaceholder MissingFnMode = iota
	MissingFnSkip
	MissingFnError
)

// ParseFnOverride parses a "name=<dir|URL>" string. Decides at parse time
// whether the value is a directory (resolved relative to PWD if not absolute),
// an http(s) URL, or neither (error).
func ParseFnOverride(spec string) (FnOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return FnOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return FnOverride{}, fmt.Errorf("fn override %q: invalid URL: %w", name, err)
		}
		return FnOverride{Name: name, Kind: FnOverrideURL, URL: value}, nil
	}
	// Treat as filesystem path.
	abs, err := filepath.Abs(value)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: resolve path: %w", name, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: path %q: %w", name, abs, err)
	}
	if !info.IsDir() {
		return FnOverride{}, fmt.Errorf("fn override %q: %q is not a directory", name, abs)
	}
	lang, err := detectLang(abs)
	if err != nil {
		return FnOverride{}, fmt.Errorf("fn override %q: %w", name, err)
	}
	return FnOverride{Name: name, Kind: FnOverrideDir, Dir: abs, Lang: lang}, nil
}

// detectLang looks for language-specific manifest files in dir. Phase 2 only
// recognizes go.mod (Go); package.json with scripts.dev is reserved for the
// codegen-node v2 milestone.
func detectLang(dir string) (FnLang, error) {
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return FnLangGo, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return FnLangUnknown, fmt.Errorf("directory %q has package.json but Node functions are not yet supported (waiting on kdex codegen node)", dir)
	}
	return FnLangUnknown, fmt.Errorf("directory %q is not a recognized KDex function project (no go.mod)", dir)
}

// ParseThemeOverride accepts either a local directory path or an http(s) URL.
// Files referenced by a directory must exist; URLs are not validated beyond
// shape.
func ParseThemeOverride(spec string) (ThemeOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return ThemeOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return ThemeOverride{}, fmt.Errorf("theme override %q: invalid URL: %w", name, err)
		}
		return ThemeOverride{Name: name, URL: value}, nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %w", name, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %w", name, err)
	}
	if !info.IsDir() {
		return ThemeOverride{}, fmt.Errorf("theme override %q: %q is not a directory", name, abs)
	}
	return ThemeOverride{Name: name, Path: abs}, nil
}

// ParseAppOverride mirrors ParseThemeOverride.
func ParseAppOverride(spec string) (AppOverride, error) {
	name, value, err := splitNameValue(spec)
	if err != nil {
		return AppOverride{}, err
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return AppOverride{}, fmt.Errorf("app override %q: invalid URL: %w", name, err)
		}
		return AppOverride{Name: name, URL: value}, nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return AppOverride{}, fmt.Errorf("app override %q: %w", name, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return AppOverride{}, fmt.Errorf("app override %q: %w", name, err)
	}
	if !info.IsDir() {
		return AppOverride{}, fmt.Errorf("app override %q: %q is not a directory", name, abs)
	}
	return AppOverride{Name: name, Path: abs}, nil
}

// ParseMissingAppMode parses one of: "placeholder", "skip", "error".
func ParseMissingAppMode(s string) (MissingAppMode, error) {
	switch strings.ToLower(s) {
	case "placeholder", "":
		return MissingAppPlaceholder, nil
	case "skip":
		return MissingAppSkip, nil
	case "error":
		return MissingAppError, nil
	default:
		return 0, fmt.Errorf("invalid --missing-app mode %q (want placeholder|skip|error)", s)
	}
}

// ParseMissingFnMode parses one of: "placeholder", "skip", "error".
func ParseMissingFnMode(s string) (MissingFnMode, error) {
	switch strings.ToLower(s) {
	case "placeholder", "":
		return MissingFnPlaceholder, nil
	case "skip":
		return MissingFnSkip, nil
	case "error":
		return MissingFnError, nil
	default:
		return 0, fmt.Errorf("invalid --missing-fn mode %q (want placeholder|skip|error)", s)
	}
}

// splitNameValue parses "name=value". Empty name or value is an error.
func splitNameValue(spec string) (string, string, error) {
	idx := strings.Index(spec, "=")
	if idx <= 0 {
		return "", "", fmt.Errorf("override %q: expected NAME=VALUE", spec)
	}
	name := spec[:idx]
	value := spec[idx+1:]
	if value == "" {
		return "", "", fmt.Errorf("override %q: empty value", spec)
	}
	return name, value, nil
}

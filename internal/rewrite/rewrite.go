// Package rewrite holds the pure path logic behind KDexPage rewrite mode
// (kdex-tech/host-manager#217), shared by the page controller's static
// placeholder check and the host's request-time dispatch.
package rewrite

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// ErrUnsafe reports a dispatch path that would contain '//' or a '.'/'..'
// segment after substitution. The CRD's CEL constrains the author's template;
// this guards the request-supplied values substituted into it.
var ErrUnsafe = errors.New("rewrite: substituted path is unsafe")

var (
	placeholderRE = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// wildcardRE matches net/http ServeMux wildcards: {name} and {name...}.
	// {$} has no name and is deliberately not matched.
	wildcardRE = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(?:\.\.\.)?\}`)
)

// Placeholders returns the {name} placeholders in a rewrite path template, in order.
func Placeholders(tmpl string) []string {
	matches := placeholderRE.FindAllStringSubmatch(tmpl, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// UnknownPlaceholders returns the placeholders in tmpl that are not wildcard
// names in patternPath -- they could never be substituted at request time.
func UnknownPlaceholders(tmpl, patternPath string) []string {
	matches := wildcardRE.FindAllStringSubmatch(patternPath, -1)
	known := make([]string, 0, len(matches))
	for _, m := range matches {
		known = append(known, m[1])
	}
	placeholders := Placeholders(tmpl)
	unknown := make([]string, 0, len(placeholders))
	for _, name := range placeholders {
		if !slices.Contains(known, name) {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// Target builds the path a rewrite dispatches to. An empty tmpl returns exact,
// the target's registered form, so the mux never answers with a slash redirect
// that would expose the target URL. Otherwise each {name} is replaced by
// value(name) and the result is joined to basePath with exactly one '/'.
func Target(basePath, exact, tmpl string, value func(string) string) (string, error) {
	if tmpl == "" {
		return exact, nil
	}
	// Strip only the AUTHOR's leading '/', before substitution: a leading '/'
	// produced by a substituted value must survive so safe() sees the '//'.
	suffix := placeholderRE.ReplaceAllStringFunc(strings.TrimPrefix(tmpl, "/"), func(m string) string {
		return value(m[1 : len(m)-1])
	})
	p := strings.TrimSuffix(basePath, "/") + "/" + suffix
	if !safe(p) {
		return "", ErrUnsafe
	}
	return p, nil
}

func safe(p string) bool {
	if strings.Contains(p, "//") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

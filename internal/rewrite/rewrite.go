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

// ErrNotFound reports request values that name no target route: a
// single-segment {name} value holding a '/' (a decoded %2F, which must not
// let one wildcard span segments of the target), or an empty value that
// leaves '//' (a missing segment, not a malformed one). It is a 404, not a
// 400.
var ErrNotFound = errors.New("rewrite: path values name no target route")

// wildcardRE matches net/http ServeMux wildcards, {name} and {name...}. The
// same syntax is accepted in rewrite.path, where {name...} is just {name}:
// authors copy wildcards from patternPath verbatim. {$} has no name and is
// deliberately not matched.
var wildcardRE = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(\.\.\.)?\}`)

// Placeholders returns the bare names of the {name} / {name...} placeholders
// in a rewrite path template, in order.
func Placeholders(tmpl string) []string {
	matches := wildcardRE.FindAllStringSubmatch(tmpl, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// UnknownPlaceholders returns the placeholders in tmpl that are not wildcard
// names in patternPath -- they could never be substituted at request time.
func UnknownPlaceholders(tmpl, patternPath string) []string {
	known := Placeholders(patternPath)
	placeholders := Placeholders(tmpl)
	unknown := make([]string, 0, len(placeholders))
	for _, name := range placeholders {
		if !slices.Contains(known, name) {
			unknown = append(unknown, name)
		}
	}
	return unknown
}

// multiSegment reports whether name is a {name...} wildcard in patternPath:
// only those values may span segments. Whether rewrite.path spells it
// {name} or {name...} is irrelevant; patternPath decides what matched.
func multiSegment(patternPath, name string) bool {
	for _, m := range wildcardRE.FindAllStringSubmatch(patternPath, -1) {
		if m[1] == name {
			return m[2] != ""
		}
	}
	return false
}

// Target builds the path a rewrite dispatches to. An empty tmpl returns exact,
// the target's registered form, so the mux never answers with a slash redirect
// that would expose the target URL. Otherwise each {name} (or {name...}) is
// replaced by value(name) and the result is joined to basePath with exactly
// one '/'. patternPath is the alias page's own pattern: it says which names
// are multi-segment wildcards.
//
// It returns ErrUnsafe (400) when a value would introduce '//' or a '.'/'..'
// segment, and ErrNotFound (404) when a single-segment value holds a '/' or
// when the only '//' comes from an empty value.
func Target(basePath, exact, tmpl, patternPath string, value func(string) string) (string, error) {
	if tmpl == "" {
		return exact, nil
	}
	spans := false
	build := func(fillEmpty bool) string {
		// Strip only the AUTHOR's leading '/', before substitution: a leading
		// '/' produced by a substituted value must survive so safe() sees the
		// '//'.
		suffix := wildcardRE.ReplaceAllStringFunc(strings.TrimPrefix(tmpl, "/"), func(m string) string {
			name := strings.TrimSuffix(m[1:len(m)-1], "...")
			v := value(name)
			if strings.Contains(v, "/") && !multiSegment(patternPath, name) {
				spans = true
			}
			if v == "" && fillEmpty {
				// Any non-empty, slash-free segment: used only to ask
				// whether the empty values are the sole cause of a '//'.
				return "x"
			}
			return v
		})
		return strings.TrimSuffix(basePath, "/") + "/" + suffix
	}
	p := build(false)
	if !safe(p) {
		if safe(build(true)) {
			return "", ErrNotFound
		}
		return "", ErrUnsafe
	}
	if spans {
		return "", ErrNotFound
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

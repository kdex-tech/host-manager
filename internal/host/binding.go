package host

import (
	"fmt"
	"net/url"
	"strings"
)

// pathParamFromMatch extracts a path parameter's value by re-matching the route
// pattern against the concrete URI path.
//
// It exists because r.PathValue does NOT work at the gate: fh.patternMux is
// built with empty handlers and consulted via Handler(r), which returns the
// matched pattern but never populates the request's path values. So the gate
// must re-match the pattern itself.
//
// A trailing Go ServeMux catch-all ({name...}) absorbs one-or-more segments, so
// the concrete URI has AT LEAST as many segments as the fixed prefix; an exact
// length comparison would fail and drop the earlier params. Match the fixed
// prefix positionally instead. The catch-all itself is never a lookup target --
// it is a path remainder, not an identity. (knowdb hit the same case; see
// multi-modal-store issue #347.)
func pathParamFromMatch(pattern, uriPath, paramName string) (string, bool) {
	patternSegs := splitPath(pattern)
	uriSegs := splitPath(uriPath)
	needle := "{" + paramName + "}"

	if n := len(patternSegs); n > 0 {
		last := patternSegs[n-1]
		if strings.HasPrefix(last, "{") && strings.HasSuffix(last, "...}") {
			fixed := patternSegs[:n-1]
			if len(uriSegs) < len(fixed) {
				return "", false
			}
			return matchPrefix(fixed, uriSegs, needle)
		}
	}

	if len(patternSegs) != len(uriSegs) {
		return "", false
	}
	return matchPrefix(patternSegs, uriSegs, needle)
}

func matchPrefix(patternSegs, uriSegs []string, needle string) (string, bool) {
	for i, ps := range patternSegs {
		if ps == needle {
			v := percentDecode(uriSegs[i])
			if v == "" {
				return "", false
			}
			return v, true
		}
	}
	return "", false
}

func splitPath(p string) []string {
	raw := strings.Split(p, "/")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

// percentDecode returns the decoded segment, or the raw segment when it is not
// valid percent-encoding. Never an error: a value that fails to decode is still
// a value, and treating it as absent would be a widen-by-accident.
func percentDecode(s string) string {
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}

// bindingExtensionKey is the operation-level OpenAPI extension declaring where
// a requirement placeholder's value comes from. It sits beside `security` and
// `x-required-entitlement` so an author reads all three together.
const bindingExtensionKey = "x-entitlement-binding"

// bindingSource is one link in a placeholder's precedence chain.
// In is one of: path, query, header.
type bindingSource struct {
	In   string
	Name string
}

// bindingSpec maps a placeholder key to its ordered source chain, mirroring the
// BACKEND's own precedence -- first match wins.
//
// Only sources the AS can read are expressible, and that is the point: an op
// whose backend resolves the identity from a request body or a database row
// must not declare a placeholder at all (the design doc's legality rule),
// because deriving a lower-precedence fallback is not deriving the target.
type bindingSpec map[string][]bindingSource

func parseBindingSpec(ext map[string]any) (bindingSpec, error) {
	raw, ok := ext[bindingExtensionKey]
	if !ok {
		return nil, nil
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object mapping a placeholder key to a source chain", bindingExtensionKey)
	}

	spec := make(bindingSpec, len(obj))
	for key, v := range obj {
		list, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("%s.%s must be an array of sources", bindingExtensionKey, key)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s.%s must declare at least one source", bindingExtensionKey, key)
		}
		chain := make([]bindingSource, 0, len(list))
		for i, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s.%s[%d] must be an object with 'in' and 'name'", bindingExtensionKey, key, i)
			}
			in, _ := m["in"].(string)
			name, _ := m["name"].(string)
			switch in {
			case "path", "query", "header":
			default:
				return nil, fmt.Errorf("%s.%s[%d]: 'in' must be path, query, or header (got %q) -- a source the AS cannot read must not be declared", bindingExtensionKey, key, i, in)
			}
			if name == "" {
				return nil, fmt.Errorf("%s.%s[%d]: 'name' must not be empty", bindingExtensionKey, key, i)
			}
			chain = append(chain, bindingSource{In: in, Name: name})
		}
		spec[key] = chain
	}
	return spec, nil
}

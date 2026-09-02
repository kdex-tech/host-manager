package host

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	entitlements "github.com/kdex-tech/entitlements/go"
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

// Binding source kinds -- the OpenAPI parameter `in` values the AS can read
// from a request. A body/table source is deliberately not expressible here
// (the design doc's legality rule).
const (
	bindingInPath   = "path"
	bindingInQuery  = "query"
	bindingInHeader = "header"
)

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
			case bindingInPath, bindingInQuery, bindingInHeader:
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

// resolveBinding builds the per-request Binding for the placeholder keys a
// requirement set may need.
//
// Per key: the declared chain if the op has one, else a path identity match
// against the route pattern (a {vector_store_id} in `security` matching a
// {vector_store_id} in the path is not a convention -- it is an identity match
// against a pattern present in the CR).
//
// A key that cannot be resolved is ABSENT from the result, never defaulted.
// BindRequirements then returns ErrUnboundPlaceholder and the gate denies. That
// is the contract working: a binder that cannot resolve a value must fail like
// an unbound placeholder rather than widen. Do NOT add a `system` or `*`
// fallback here -- those are knowdb's policy, not the binder's.
func resolveBinding(r *http.Request, pattern string, spec bindingSpec, keys []string) entitlements.Binding {
	if len(keys) == 0 {
		return nil
	}
	b := make(entitlements.Binding, len(keys))
	for _, key := range keys {
		if v, ok := resolveKey(r, pattern, spec, key); ok {
			b[key] = v
		}
	}
	return b
}

// bindFailureIsClientError classifies an ErrUnboundPlaceholder from
// BindRequirements as a caller-fixable client error (true) rather than a
// server-side CR-configuration fault (false).
//
// entitlements.ErrUnboundPlaceholder conflates two conditions the gate must
// answer differently (#195): a placeholder whose declared source is a
// header/query value the caller simply OMITTED is a client error the caller can
// fix by re-sending the request (400) -- not a server fault, and answering 500
// would let an unauthenticated caller drive error-logged 5xx by omitting a
// header. A placeholder with no source the caller can supply -- undeclared and
// not a path segment, or declared only from a path that did not match -- is the
// genuine fault: no request the caller could make would bind it (500).
//
// The unbound key is one of `keys` (placeholderKeys) that resolveBinding left
// absent from `binding`. Pattern-segment placeholders always resolve from the
// matched path, so an absent key is a spec-declared one; it is caller-fixable
// exactly when its chain offers a header or query source. The classification is
// caller-fixable only when EVERY absent key is -- a single unresolvable key
// means the operator must act, so the whole answer is the fault (500). An empty
// absent set (the placeholder had no entry in `keys` at all -- undeclared and
// not in the pattern) is likewise a fault.
func bindFailureIsClientError(spec bindingSpec, binding entitlements.Binding, keys []string) bool {
	absent := 0
	for _, key := range keys {
		if _, ok := binding[key]; ok {
			continue
		}
		absent++
		if !hasCallerSuppliableSource(spec[key]) {
			return false
		}
	}
	return absent > 0
}

// hasCallerSuppliableSource reports whether a placeholder's source chain offers
// a value the caller controls per-request (a header or query parameter). A
// path-only chain, or no chain at all, is not caller-suppliable: the caller
// cannot change the matched route to bind it.
func hasCallerSuppliableSource(chain []bindingSource) bool {
	for _, src := range chain {
		if src.In == bindingInHeader || src.In == bindingInQuery {
			return true
		}
	}
	return false
}

func resolveKey(r *http.Request, pattern string, spec bindingSpec, key string) (string, bool) {
	if chain, ok := spec[key]; ok {
		for _, src := range chain {
			if v, ok := readSource(r, pattern, src); ok {
				return v, true
			}
		}
		return "", false
	}
	// Undeclared: the only legal implicit source is the path, where the pattern
	// itself names the param. A header is NEVER inferred -- host-manager is
	// generic across every function and must not guess the header spelling of a
	// backend it does not control.
	return pathParamFromMatch(pattern, r.URL.Path, key)
}

func readSource(r *http.Request, pattern string, src bindingSource) (string, bool) {
	var v string
	switch src.In {
	case bindingInPath:
		pv, ok := pathParamFromMatch(pattern, r.URL.Path, src.Name)
		if !ok {
			return "", false
		}
		v = pv
	case bindingInQuery:
		v = r.URL.Query().Get(src.Name)
	case bindingInHeader:
		v = r.Header.Get(src.Name)
	default:
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// placeholderKeys returns the placeholder names worth resolving for a route:
// every key the op declares a chain for, plus every {name} segment in the route
// pattern. ParsedRequirements does not expose its placeholder names, so this is
// a superset -- safe and cheap, because BindRequirements ignores binding keys
// that match no placeholder.
func placeholderKeys(spec bindingSpec, pattern string) []string {
	seen := make(map[string]struct{}, len(spec)+2)
	keys := make([]string, 0, len(spec)+2)
	add := func(k string) {
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range spec {
		add(k)
	}
	for _, seg := range splitPath(pattern) {
		if !strings.HasPrefix(seg, "{") || !strings.HasSuffix(seg, "}") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(seg, "{"), "}")
		if strings.HasSuffix(name, "...") {
			continue // a catch-all is a path remainder, not an identity
		}
		add(name)
	}
	return keys
}

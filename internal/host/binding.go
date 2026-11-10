package host

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	entitlements "github.com/kdex-tech/entitlements/go"
)

// pathParamFromMatch extracts a path parameter's value by re-matching the route
// pattern against the concrete URI path.
//
// uriPath must be the ESCAPED path (r.URL.EscapedPath()): each segment is
// percent-decoded here, exactly once. r.URL.Path is already decoded, so
// matching against it decoded %25 a second time -- binding a different
// instance from the one the backend's r.PathValue addresses -- and split a
// segment at an encoded slash, leaving the placeholder unbound (#230).
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

// ambiguousBindingSource reports whether a query parameter or header that the
// binding of keys may read is ambiguous: sent more than once, or sent under
// another name a backend would read as it. Every source in a chain counts, not
// only the one that binds, since a backend reads its own source whichever the
// gate resolved first.
//
// The aliases are the names a permissive backend folds into the bound one.
// PHP drops leading spaces, ends a key at a NUL, reads '.', ' ' and an
// unmatched '[' in it as '_', and store[...] as store;
// ASP.NET matches query keys without regard to case; CGI-style servers read
// '_' in a header name as '-'. Go parses each as a distinct name, so the gate
// would bind one value -- or fall through to the next source in the chain --
// while such a backend acted on another. An alias is refused even when sent
// alone: ?STORE=theirs with X-Store: mine bound "mine" from the header.
func ambiguousBindingSource(r *http.Request, spec bindingSpec, keys []string) bool {
	var query url.Values
	for _, key := range keys {
		for _, src := range spec[key] {
			switch src.In {
			case bindingInQuery:
				if query == nil {
					query = r.URL.Query()
				}
				if ambiguousQueryName(query, src.Name) {
					return true
				}
			case bindingInHeader:
				if ambiguousName(r.Header, http.CanonicalHeaderKey(src.Name), foldHeaderName) {
					return true
				}
			}
		}
	}
	return false
}

// ambiguousName reports whether values hold name more than once, or hold any
// other name that folds to it.
func ambiguousName(values map[string][]string, name string, fold func(string) string) bool {
	if len(values[name]) > 1 {
		return true
	}
	folded := fold(name)
	for other := range values {
		if other != name && fold(other) == folded {
			return true
		}
	}
	return false
}

// ambiguousQueryName reports whether query holds name more than once, or
// holds another key a backend could read as name or overwrite it with. Keys
// are compared as PHP parses them (phpQueryKey), case-folded for ASP.NET:
//   - a plain name's alias is any key with the same base, bracketed or not
//     (store[x] and STORE both reach $_GET['store']);
//   - a bracketed name's alias is the bare base, which replaces the whole
//     array, or a key whose segments agree with it wherever both have one
//     (filter[store]x, filter[store][y], filter[]); a sibling such as
//     filter[status] is not.
func ambiguousQueryName(query url.Values, name string) bool {
	if len(query[name]) > 1 {
		return true
	}
	base, segs := phpQueryKey(name)
	for other := range query {
		if other == name {
			continue
		}
		otherBase, otherSegs := phpQueryKey(other)
		if otherBase != base {
			continue
		}
		if len(segs) == 0 || len(otherSegs) == 0 || segmentsOverlap(segs, otherSegs) {
			return true
		}
	}
	return false
}

// segmentsOverlap reports whether two bracket paths under one base can name
// the same value: equal wherever both have a segment, an empty [] matching
// any.
func segmentsOverlap(a, b []string) bool {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] && a[i] != "" && b[i] != "" {
			return false
		}
	}
	return true
}

// phpQueryKey parses a query key as PHP's php_register_variable_ex does, then
// lowercases it for ASP.NET. PHP drops leading spaces and ends the key at a
// NUL; in the base it reads '.' and ' ' as '_'; it reads [seg] groups as
// array segments, stops at a ']' not followed by '[' and discards the rest,
// and reads an unmatched '[' as '_' in the base.
func phpQueryKey(key string) (string, []string) {
	if nul := strings.IndexByte(key, 0); nul >= 0 {
		key = key[:nul]
	}
	key = strings.TrimLeft(key, " ")
	open := strings.IndexByte(key, '[')
	if open <= 0 || strings.IndexByte(key[open:], ']') < 0 {
		return phpBase(key), nil
	}
	base := phpBase(key[:open])
	var segs []string
	rest := key[open:]
	for len(rest) > 0 && rest[0] == '[' {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			break
		}
		segs = append(segs, strings.ToLower(rest[1:end]))
		rest = rest[end+1:]
	}
	return base, segs
}

// phpBase is a key's base as PHP reads it, case-folded.
func phpBase(base string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', ' ', '[':
			return '_'
		}
		return unicode.ToLower(r)
	}, base)
}

// foldHeaderName is a header name as a CGI-style server reads it.
func foldHeaderName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
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
	return pathParamFromMatch(pattern, r.URL.EscapedPath(), key)
}

func readSource(r *http.Request, pattern string, src bindingSource) (string, bool) {
	var v string
	switch src.In {
	case bindingInPath:
		pv, ok := pathParamFromMatch(pattern, r.URL.EscapedPath(), src.Name)
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
	// Bind the raw value, never a trimmed one: the backend acts on the raw
	// value, so trimming checked "vs1" while the backend addressed " vs1 ". Only
	// an empty value is absent; a whitespace-only one is present to the backend
	// too, so it binds as-is rather than falling through to the next link.
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

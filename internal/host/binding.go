package host

import (
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

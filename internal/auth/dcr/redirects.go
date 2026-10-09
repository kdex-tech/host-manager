package dcr

import (
	"net/url"
	"slices"
	"strings"
)

// Named allowedRedirectSchemes policies. Every other entry is a literal URI
// scheme ("cursor" permits cursor://…).
const (
	SchemeLoopback   = "http-loopback" // http, loopback host only (RFC 8252 §7.3)
	SchemePrivateUse = "private-use"   // any dotted non-http(s) scheme (RFC 8252 §7.1)

	schemeHTTP        = "http"
	schemeHTTPS       = "https"
	maxRedirectURILen = 2048
)

// DefaultRedirectSchemes applies when a host configures none.
var DefaultRedirectSchemes = []string{schemeHTTPS, SchemeLoopback}

// dangerousSchemes are never honoured, even when listed: they are code
// execution / local file / data exfiltration vectors, not redirect targets.
var dangerousSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "blob": true,
}

// FilterRedirectURIs keeps the redirect URIs the policy admits, in order and
// without duplicates. It runs at registration AND whenever a stored client is
// read back, so tightening allowedRedirectSchemes takes effect on clients
// already registered. An empty result means no usable redirect: the caller
// refuses (registration) or treats the client as gone (read-back).
func FilterRedirectURIs(uris, schemes []string) []string {
	kept := make([]string, 0, len(uris))
	for _, u := range uris {
		if redirectAllowed(u, schemes) && !slices.Contains(kept, u) {
			kept = append(kept, u)
		}
	}
	return kept
}

// redirectAllowed reports whether one redirect URI is admitted by the host's
// allowedRedirectSchemes. Two entries are named POLICIES that constrain the
// URL's structure, not just its scheme; every other entry is a deterministic
// literal — the entry IS the URI scheme, so listing "cursor" permits cursor://…
//
//   - "http-loopback": scheme http, but only to a loopback host (RFC 8252 §7.3).
//   - "private-use":   any non-http(s) reverse-DNS/dotted scheme (RFC 8252 §7.1
//     SHOULD — reduces scheme-squatting; a bare single-label scheme is rejected
//     under this policy but can still be opted into as an explicit literal).
//   - anything else:   literal scheme match (u.Scheme == entry).
//
// Guardrails regardless of what is listed: a bare "http" literal is never
// honoured (cleartext + non-loopback == open redirect), nor are
// dangerousSchemes. Beyond the scheme policy it refuses shapes a user cannot
// judge on a consent page: userinfo (https://trusted@other/), fragments
// (RFC 6749 §3.1.2 forbids them), an empty or non-ASCII host (homoglyphs, bidi
// overrides), and very long URIs. DCR clients are forced public + PKCE with an
// exact-matched redirect_uri at /authorize, so a permitted custom scheme cannot
// yield a usable intercepted code.
func redirectAllowed(raw string, schemes []string) bool {
	if raw == "" || len(raw) > maxRedirectURILen || strings.Contains(raw, "#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return false
	}
	if host := u.Hostname(); host != "" && !isASCII(host) {
		return false
	}
	if (u.Scheme == schemeHTTP || u.Scheme == schemeHTTPS) && u.Hostname() == "" {
		return false
	}
	for _, s := range schemes {
		switch s {
		case SchemeLoopback:
			if u.Scheme == schemeHTTP {
				host := u.Hostname()
				if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
					return true
				}
			}
		case SchemePrivateUse:
			if u.Scheme != "" && u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS &&
				strings.Contains(u.Scheme, ".") {
				return true
			}
		default:
			// Literal: the entry IS the scheme. Never an empty scheme, a bare
			// "http" (cleartext non-loopback is an open redirect), or a
			// dangerous scheme, even if listed.
			if s == "" || s == schemeHTTP || dangerousSchemes[s] {
				continue
			}
			if u.Scheme == s {
				return true
			}
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

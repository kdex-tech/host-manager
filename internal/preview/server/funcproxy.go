package server

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/kdex-tech/host-manager/internal/preview/resolver"
	"github.com/kdex-tech/host-manager/internal/preview/stubs"
	"github.com/kdex-tech/host-manager/internal/preview/synth"
)

// newProxyMux wraps `inner` (host-manager's HostHandler) with an outer
// http.ServeMux that intercepts each synthesized function route. Requests
// whose path matches a route's BasePath are reverse-proxied to that route's
// URL (the supervisor's localhost:port or a static URL-form override);
// everything else falls through to `inner`.
//
// IMPORTANT (§4.5): we deliberately do NOT inject Authorization headers.
// The supervised function (or the user-supplied URL) is reached with the
// caller's original headers only. This sidesteps host-manager's FAT-minting
// path entirely.
//
// missingMode is reserved for Task 2.8 — Phase 2 v0 always falls through to
// `inner` for paths with no override (which produces host-manager's default
// 404 / not-ready response for any function path that wasn't synthesized).
// When 2.8 lands, the placeholder/skip/error semantics will gate which routes
// get registered here.
func newProxyMux(inner http.Handler, routes []synth.Route, _ resolver.MissingFnMode) http.Handler {
	mux := http.NewServeMux()

	// Stub 501 handlers for routes preview cannot meaningfully serve.
	// Registered BEFORE function routes and the '/' catchall so they take
	// precedence over host-manager's default routing for these paths.
	mux.Handle("/-/login", stubs.NotImplemented("login"))
	mux.Handle("/-/logout", stubs.NotImplemented("logout"))
	mux.Handle("/-/feedback", stubs.NotImplemented("feedback"))
	mux.Handle("/-/apitoken", stubs.NotImplemented("apitoken"))
	mux.Handle("/-/openapi/", stubs.NotImplemented("openapi"))

	for _, r := range routes {
		target, err := url.Parse(r.URL)
		if err != nil {
			// SynthesizeRoutes' URLs come from the supervisor (always valid)
			// or from URL-form overrides (validated at parse time in
			// resolver.ParseFnOverride). A parse failure here is a
			// programmer error elsewhere — falling back to inner is safer
			// than panicking in a request hot path.
			continue
		}
		basePath := strings.TrimRight(r.BasePath, "/")
		if basePath == "" {
			// A function whose BasePath is "" would shadow the entire site.
			// Skip it — preview should never have an unbounded route. (If
			// this becomes an issue, surface it as a load-time validation.)
			continue
		}
		proxy := newFnReverseProxy(target, basePath)
		// Two registrations so both /<basePath> and /<basePath>/* match.
		// Without the exact-match registration, the bare path would fall
		// through to `inner` (and 404).
		mux.Handle(basePath+"/", proxy)
		mux.Handle(basePath, proxy)
	}
	// Default: everything else (including all page routes, theme assets, etc.)
	// goes to host-manager.
	mux.Handle("/", inner)
	return mux
}

// newFnReverseProxy constructs a stdlib reverse proxy that strips basePath
// from the inbound request before forwarding to target. Forwarded URL.Path
// is the inbound path minus basePath; URL.Host/Scheme become the target's;
// the Host header is rewritten so the supervised process's HTTP router sees
// its own bound host (otherwise a hostname-based mux upstream would 404).
//
// Uses Rewrite (Go 1.20+) instead of the deprecated Director. Rewrite is
// passed an httputil.ProxyRequest whose Out is the outbound request;
// SetURL stamps Scheme/Host/Path-prefix from target.
func newFnReverseProxy(target *url.URL, basePath string) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host

			stripped := strings.TrimPrefix(pr.Out.URL.Path, basePath)
			if stripped == "" {
				stripped = "/"
			}
			pr.Out.URL.Path = stripped
			// RawPath, if set, must be re-synced or stdlib will prefer it
			// over Path on encoding (and re-emit the un-stripped path).
			if pr.Out.URL.RawPath != "" {
				pr.Out.URL.RawPath = strings.TrimPrefix(pr.Out.URL.RawPath, basePath)
				if pr.Out.URL.RawPath == "" {
					pr.Out.URL.RawPath = "/"
				}
			}
		},
	}
	return rp
}

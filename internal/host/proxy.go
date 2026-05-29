package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/kdex-tech/host-manager/internal/utils"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

//nolint:gocyclo
func (hh *HostHandler) reverseProxyHandler(fn *kdexv1alpha1.KDexFunction, issuer string) http.Handler {
	target, err := url.Parse(fn.Status.URL)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hh.log.Error(err, "failed to parse function URL", "url", fn.Status.URL)
			http.Error(w, "invalid function URL", http.StatusInternalServerError)
		})
	}

	var mapper *dmapper.Mapper
	if fn.Spec.ClaimMappings != nil {
		mapper, err = dmapper.NewMapper(fn.Spec.ClaimMappings)
		if err != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hh.log.Error(err, "failed to create mapper", "mapper", fn.Spec.ClaimMappings)
				http.Error(w, "invalid mapper", http.StatusInternalServerError)
			})
		}
	}

	signer, err := sign.NewSigner(
		fn.Status.URL,
		signerDuration,
		issuer,
		&hh.authConfig.ActivePair.Private,
		hh.authConfig.ActivePair.KeyId,
		mapper,
	)

	// Downscoped Function Access Token (FAT) Cache. TTL is slightly less
	// than the signer duration so a cache hit always yields a token with
	// meaningful remaining life downstream — see fatCacheTTLSkew below.
	tokenCache := hh.cacheManager.GetCache("token", cache.CacheOptions{
		TTL:      new(signerDuration - fatCacheTTLSkew),
		Uncycled: true,
	})

	proxy := &httputil.ReverseProxy{
		Rewrite: func(preq *httputil.ProxyRequest) {
			log := logf.FromContext(preq.In.Context())

			log.V(2).Info("PROXY: modifying request", "url", preq.In.URL)

			// 1. Set Target and Host
			preq.Out.URL.Scheme = target.Scheme
			preq.Out.URL.Host = target.Host
			preq.Out.Host = target.Host // Essential for FaaS routing

			// 2. Precise Path Joining
			// For Knative-deployed functions (no Backend), we preserve the full
			// incoming path because the generated function code expects to see
			// the BasePath. For Service-backed functions, the upstream service
			// is unaware of the BasePath, so we strip it before prepending the
			// backend's mount path.
			upstreamPath := preq.In.URL.Path
			if fn.Spec.Backend != nil {
				upstreamPath = strings.TrimPrefix(upstreamPath, fn.Spec.API.BasePath)
				if !strings.HasPrefix(upstreamPath, "/") {
					upstreamPath = "/" + upstreamPath
				}
			}
			preq.Out.URL.Path = path.Join(target.Path, upstreamPath)
			if strings.HasSuffix(preq.In.URL.Path, "/") && !strings.HasSuffix(preq.Out.URL.Path, "/") {
				preq.Out.URL.Path += "/"
			}

			// 3. Forward Query Parameters exactly
			// This copies the encoded query string (e.g., ?user=123&sort=asc)
			preq.Out.URL.RawQuery = preq.In.URL.RawQuery

			authContext, isLoggedIn := auth.GetAuthContext(preq.In.Context())
			if isLoggedIn {
				cookies := map[string]any{}
				for _, cookie := range preq.In.Cookies() {
					cookies[cookie.Name] = cookie.Value
				}
				if len(cookies) > 0 {
					authContext["cookies"] = cookies
				}
				headers := map[string]any{}
				for key, value := range preq.In.Header {
					// Strip sensitive headers from the snapshot so they
					// can't leak into the FAT through ClaimMappings that
					// extract `self.headers.<name>`. Specifically:
					//   - Authorization: the user's host-audience token
					//   - Cookie: the user's whole session cookie jar
					//   - X-Forwarded-*: attacker-spoofable on the
					//     inbound request (SetXForwarded appends the
					//     true chain to preq.Out, but the snapshot here
					//     is preq.In and runs before that).
					// See kdex-tech/host-manager#90.
					canonical := http.CanonicalHeaderKey(key)
					if canonical == "Authorization" || canonical == "Cookie" || canonical == "Set-Cookie" {
						continue
					}
					if strings.HasPrefix(canonical, "X-Forwarded-") || canonical == "Forwarded" {
						continue
					}
					headers[key] = value
				}
				if len(headers) > 0 {
					authContext["headers"] = headers
				}

				// Cache key derived from the DETERMINISTIC PROJECTION of the
				// authContext (what actually ends up in the signed JWT), not the
				// raw authContext. The raw form carries per-request headers
				// (Traceparent, X-Request-Id, If-None-Match, …) that invalidate
				// the cache on every call in OTel-instrumented call paths. See
				// kdex-tech/host-manager#37.
				projected, err := signer.Project(jwt.MapClaims(authContext))
				if err != nil {
					log.Error(err, "failed to project claims")
				} else {
					tokenKey := fmt.Sprintf("%s-%s", fn.Name, utils.Hash(projected))

					if token, exists, isCurrent, _ := tokenCache.Get(preq.In.Context(), tokenKey); exists && isCurrent {
						preq.Out.Header.Set("Authorization", "Bearer "+token)
					} else {
						token, err := signer.SignProjected(projected)
						if err != nil {
							log.Error(err, "failed to sign token")
						} else {
							if err := tokenCache.Set(preq.In.Context(), tokenKey, token); err != nil {
								log.Error(err, "failed to set token in cache")
							}
							preq.Out.Header.Set("Authorization", "Bearer "+token)
						}
					}
				}
			} else {
				preq.Out.Header.Del("Authorization")
			}

			// Delete all cookies but preserve X-API-TOKEN
			apiTokenCookie, err := preq.In.Cookie("X-API-TOKEN")
			if err == nil && apiTokenCookie != nil && apiTokenCookie.Value != "" {
				preq.Out.Header.Set("Cookie", apiTokenCookie.String())
			} else {
				preq.Out.Header.Del("Cookie")
			}

			// 4. Standard Proxy Headers
			preq.Out.Header.Set("X-Kdex-Forwarded", "true")
			preq.SetXForwarded()
		},
		ModifyResponse: func(resp *http.Response) error {
			log := logf.FromContext(resp.Request.Context())

			log.V(2).Info("PROXY: modifying response", "url", resp.Request.URL)
			// 5. Rewrite Set-Cookie Domain
			// This ensures cookies from the FaaS backend are tied to your proxy domain
			cookies := resp.Header["Set-Cookie"]
			for i, cookie := range cookies {
				// We remove the specific Domain attribute so the browser
				// defaults to the domain the user actually visited (your proxy).
				// You could also explicitly replace it with your proxy's domain.
				resp.Header["Set-Cookie"][i] = hh.stripCookieDomain(cookie)
			}
			return nil
		},
		Transport: newProxyTransport(hh.proxyTimeouts),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log := logf.FromContext(r.Context())

			log.Error(err, "PROXY: backend failure", "url", r.URL.String())

			code := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}

			http.Error(w, err.Error(), code)
		},
	}

	patternMux := http.NewServeMux()
	parsedRequirements := make(map[string]entitlements.ParsedRequirements)

	for p, item := range fn.Spec.API.Paths {
		// Use empty handler, we only care about the pattern match
		patternMux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {})

		for _, method := range []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"} {
			op := item.GetOp(method)
			if op != nil && op.Security != nil {
				raw := make([]kdexv1alpha1.SecurityRequirement, 0, len(*op.Security))
				for _, s := range *op.Security {
					raw = append(raw, kdexv1alpha1.SecurityRequirement(s))
				}
				parsedRequirements[method+" "+p] = hh.authChecker.ParseRequirements(raw)
			}
		}
	}

	fh := &KDexFunctionHandler{
		Function:           fn,
		parsedRequirements: parsedRequirements,
		patternMux:         patternMux,
	}

	// Capture the start time and log the completion
	fh.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := logf.FromContext(r.Context())

		start := time.Now()
		defer func() {
			code := http.StatusOK
			if ew := GetErrorResponseWriter(w); ew != nil {
				code = ew.statusCode
			}

			// Log the Completion
			log.V(2).Info("proxy request finished",
				"function", fn.Name,
				"statusCode", code,
				"duration", time.Since(start).String(),
			)
		}()

		// Log the Inbound Request
		log.V(2).Info("proxy request started",
			"function", fn.Name,
			"method", r.Method,
			"path", r.URL.Path,
			"target", target.String(),
		)

		// Snapshot the only hh field this handler reads (authChecker)
		// under a tight RLock, then release before doing the auth check
		// and proxy round-trip. Pre-fix the RLock was held across
		// proxy.ServeHTTP, which pinned hh.mu for the entire upstream
		// HTTP round-trip — a single hung backend silently wedged every
		// reconcile via writer-starvation on hh.mu. See
		// kdex-tech/host-manager#59.
		//
		// The captured AuthorizationChecker is safe to use after release:
		// its internals (ec, log) are immutable post-construction, and
		// the closure-captured proxy state (target, signer, tokenCache,
		// fh.patternMux, fh.parsedRequirements, fn) is set up once at
		// handler-build time.
		hh.mu.RLock()
		authChecker := hh.authChecker
		hh.mu.RUnlock()

		if authChecker != nil {
			_, pattern := fh.patternMux.Handler(r)
			key := r.Method + " " + pattern
			var reqs entitlements.ParsedRequirements
			if pr, ok := fh.parsedRequirements[key]; ok {
				reqs = pr
			} else {
				// Default to empty requirements (allows access if identity matches)
				reqs = authChecker.ParseRequirements(nil)
			}

			parsedUserEntitlements := authChecker.GetParsedEntitlements(r.Context())
			authorized, err := authChecker.VerifyResourceParsedEntitlements(
				"functions", fn.Spec.API.BasePath, parsedUserEntitlements, reqs)

			if err != nil || !authorized {
				if err != nil {
					log.Error(err, "authorization check failed", "function", fn.Name)
				} else {
					log.V(1).Info("unauthorized access attempt", "function", fn.Name)
				}
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
				return
			}
		}

		// Execute the proxy — runs WITHOUT holding hh.mu so a slow
		// upstream cannot starve the host's writers.
		proxy.ServeHTTP(w, r)
	})

	return fh
}

// Defaults applied to zero-valued ProxyTimeouts fields. ResponseHeaderTimeout
// covers a typical Knative scale-from-zero cold start of a Go function with
// gRPC + cloudsqlconn + OpenTelemetry deps (~20–40s on observed workloads);
// operators with heavier functions can override via the corresponding
// --proxy-*-timeout flag / chart value.
const (
	defaultProxyDialTimeout           = 5 * time.Second
	defaultProxyResponseHeaderTimeout = 60 * time.Second
	defaultProxyIdleConnTimeout       = 90 * time.Second
	defaultProxyKeepAlive             = 30 * time.Second

	// signerDuration is the lifetime of every minted FAT (Function Access
	// Token). The signer attaches exp = iat + signerDuration to each token.
	signerDuration = 5 * time.Minute

	// fatCacheTTLSkew shrinks the cache entry's lifetime below the token's
	// own exp so a cache hit always yields a token with at least this much
	// remaining life. Without skew, an entry served right at TTL boundary
	// would hand out a token that expires mid-request downstream.
	fatCacheTTLSkew = 30 * time.Second
)

// newProxyTransport builds the http.Transport used by every KDexFunction
// reverse proxy. Zero-valued ProxyTimeouts fields are filled with the
// defaults above so callers and tests can pass an empty struct.
func newProxyTransport(t ProxyTimeouts) *http.Transport {
	dial := t.DialTimeout
	if dial <= 0 {
		dial = defaultProxyDialTimeout
	}
	respHeader := t.ResponseHeaderTimeout
	if respHeader <= 0 {
		respHeader = defaultProxyResponseHeaderTimeout
	}
	idleConn := t.IdleConnTimeout
	if idleConn <= 0 {
		idleConn = defaultProxyIdleConnTimeout
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   dial,
			KeepAlive: defaultProxyKeepAlive,
		}).DialContext,
		ResponseHeaderTimeout: respHeader,
		IdleConnTimeout:       idleConn,
	}
}

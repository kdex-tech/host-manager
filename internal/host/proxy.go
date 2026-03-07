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
	"github.com/kdex-tech/entitlements"
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
		5*time.Minute,
		issuer,
		&hh.authConfig.ActivePair.Private,
		hh.authConfig.ActivePair.KeyId,
		mapper,
	)

	// Downscoped Function Access Token (FAT) Cache
	tokenCache := hh.cacheManager.GetCache("token", cache.CacheOptions{
		TTL:      new(5 * time.Minute),
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
			// Note: We do NOT strip the BasePath because KDex functions are
			// implemented using the full paths defined in their OpenAPI spec.
			preq.Out.URL.Path = path.Join(target.Path, preq.In.URL.Path)
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
					headers[key] = value
				}
				if len(headers) > 0 {
					authContext["headers"] = headers
				}

				tokenKey := fmt.Sprintf("%s-%s", fn.Name, utils.Hash(authContext))

				if token, exists, isCurrent, _ := tokenCache.Get(preq.In.Context(), tokenKey); exists && isCurrent {
					preq.Out.Header.Set("Authorization", "Bearer "+token)
				} else {
					token, err := signer.Sign(jwt.MapClaims(authContext))
					if err != nil {
						log.Error(err, "failed to sign token")
					} else {
						if err := tokenCache.Set(preq.In.Context(), tokenKey, token); err != nil {
							log.Error(err, "failed to set token in cache")
						}
						preq.Out.Header.Set("Authorization", "Bearer "+token)
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
		// TODO: make transport configurable
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second, // Connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: 15 * time.Second, // Wait for FaaS headers
			IdleConnTimeout:       90 * time.Second,
		},
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

		hh.mu.RLock()
		defer hh.mu.RUnlock()

		if hh.authChecker != nil {
			_, pattern := fh.patternMux.Handler(r)
			key := r.Method + " " + pattern
			var reqs entitlements.ParsedRequirements
			if pr, ok := fh.parsedRequirements[key]; ok {
				reqs = pr
			} else {
				// Default to empty requirements (allows access if identity matches)
				reqs = hh.authChecker.ParseRequirements(nil)
			}

			parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
			authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
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

		// Execute the proxy
		proxy.ServeHTTP(w, r)
	})

	return fh
}

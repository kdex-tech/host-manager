package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"slices"
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

// fatAudienceFor returns the audience to mint a Function Access Token for.
//
// For Knative-deployed functions (no Spec.Backend), each function has its
// own Knative Service so Status.URL identifies a recipient uniquely; the
// audience is Status.URL verbatim.
//
// For Service-backed functions (Spec.Backend.Type=Service), multiple sibling
// KDexFunction CRs commonly proxy to the same backend Service — typically
// the case when one upstream API is split across resource-family CRs to
// fit under the Spec.API.Paths MaxProperties=16 cap. The backend's JWT
// validator usually has a single audience configured; to satisfy it from
// any of those siblings' FATs, the audience is the Service origin
// (scheme + host[:port]) without the Spec.Backend.Service.Path suffix. All
// sibling functions backed by the same Service then mint FATs with the
// same audience.
//
// See kdex-tech/host-manager#98 for background on the shared-backend case.
func fatAudienceFor(fn *kdexv1alpha1.KDexFunction) string {
	if fn.Spec.Backend == nil {
		return fn.Status.URL
	}
	u, err := url.Parse(fn.Status.URL)
	if err != nil {
		return fn.Status.URL
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// isAPIKeyScheme reports whether a security scheme name is one of the host's
// stateless API-token (PASETO) apiKey* schemes advertised in
// OpenAPIBuilder.SecuritySchemes(). See kdex-tech/host-manager#103.
func isAPIKeyScheme(name string) bool {
	switch name {
	case "apiKeyCookie", "apiKeyHeader", "apiKeyQuery":
		return true
	default:
		return false
	}
}

// extractAPIToken returns the PASETO API token carried on the request, checking
// (in order) the X-API-TOKEN cookie, the X-API-TOKEN header, and the api_token
// query parameter — the three apiKey* scheme locations the host advertises.
// Returns "" when none is present.
func extractAPIToken(r *http.Request) string {
	if c, err := r.Cookie("X-API-TOKEN"); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("X-API-TOKEN"); h != "" {
		return h
	}
	if q := r.URL.Query().Get("api_token"); q != "" {
		return q
	}
	return ""
}

// extractBearerOrAPIToken returns the PASETO API token carried on the request,
// checking first the apiKey* locations (cookie / header / query) and then an
// `Authorization: Bearer <pat>` header — but only when the bearer credential
// looks like a PASETO PAT (bare "v4.public." or this host's brand prefix), so a
// host-audience JWT on the Authorization header is never mistaken for a PAT.
// Returns "" when none is present.
func extractBearerOrAPIToken(r *http.Request, tokenPrefix string) string {
	if tok := extractAPIToken(r); tok != "" {
		return tok
	}
	if ah := r.Header.Get("Authorization"); ah != "" {
		if rest, ok := strings.CutPrefix(ah, "Bearer "); ok {
			if auth.LooksLikePAT(rest, tokenPrefix) {
				return rest
			}
		}
	}
	return ""
}

//nolint:gocyclo
func (hh *HostHandler) reverseProxyHandler(fn *kdexv1alpha1.KDexFunction, issuer string) http.Handler {
	target, err := url.Parse(fn.Status.URL)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hh.log.Error(err, "failed to parse function URL", "url", fn.Status.URL)
			http.Error(w, "invalid function URL", http.StatusInternalServerError)
		})
	}

	// The FAT inherits the HOST's claimMappings (e.g. a backend claim ->
	// entitlements) PLUS any function-specific ones, so a rule authored once on
	// the host applies to every token the host issues — session AND FAT. Host
	// rules run first; function rules refine. Without this, a host rule that
	// merges bridge-resolved grants never runs at FAT mint and the grant is
	// dropped by the projection allowlist. See kdex-tech/host-manager#138.
	var mapper *dmapper.Mapper
	claimMappings := append(slices.Clone(hh.authConfig.ClaimMappings), fn.Spec.ClaimMappings...)
	if len(claimMappings) > 0 {
		mapper, err = dmapper.NewMapper(claimMappings)
		if err != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hh.log.Error(err, "failed to create mapper", "mapper", claimMappings)
				http.Error(w, "invalid mapper", http.StatusInternalServerError)
			})
		}
	}

	signer, err := sign.NewSigner(
		fatAudienceFor(fn),
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

			// mint_token AS-augmentation: splice the mint_token descriptor into a
			// tools/list response body forwarded upstream. The marker is set in
			// fh.Handler when the request was recognized as a tools/list call on
			// a mint-token-enabled function; non-JSON or non-tools/list bodies
			// pass through untouched.
			if discoveryURL, isToolsList := resp.Request.Context().Value(mintTokenListDiscoveryURLKey).(string); isToolsList &&
				strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
				raw, rerr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if rerr == nil {
					if spliced, ok := spliceMintTokenDescriptor(raw, discoveryURL); ok {
						raw = spliced
					}
					resp.Body = io.NopCloser(bytes.NewReader(raw))
					resp.ContentLength = int64(len(raw))
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(raw)))
				} else {
					resp.Body = io.NopCloser(bytes.NewReader(raw))
				}
			}

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

			// Redact the query string before logging: the proxy forwards
			// arbitrary function requests, whose query params can carry
			// credentials (tokens, codes), and this is Error-level so it is
			// always emitted. Log the path only. See #11.
			loggedURL := *r.URL
			loggedURL.RawQuery = ""
			loggedURL.Fragment = ""

			log.Error(err, "PROXY: backend failure", "url", loggedURL.String())

			code := http.StatusBadGateway
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}

			http.Error(w, err.Error(), code)
		},
	}

	patternMux := http.NewServeMux()
	parsedRequirements := make(map[string]entitlements.ParsedRequirements)
	bindingSpecs := make(map[string]bindingSpec)

	// acceptsAPIKey opts this function into the PASETO->authContext bridge when
	// any operation declares an apiKey* security scheme. Per-function (not
	// per-operation) granularity, matching the existing identity gate. See
	// kdex-tech/host-manager#103.
	acceptsAPIKey := false

	for p, item := range fn.Spec.API.Paths {
		// Use empty handler, we only care about the pattern match
		patternMux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {})

		for _, method := range []string{"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"} {
			op := item.GetOp(method)
			if op == nil {
				continue
			}
			key := method + " " + p

			// Parse the binding declaration even when the op has no security
			// block: a malformed declaration is an authoring error worth
			// surfacing wherever it appears.
			if spec, err := parseBindingSpec(op.Extensions); err != nil {
				hh.log.Error(err, "invalid x-entitlement-binding; placeholders on this route will not bind",
					"function", fn.Name, "route", key)
			} else if spec != nil {
				bindingSpecs[key] = spec
			}

			if op.Security != nil {
				raw := make([]kdexv1alpha1.SecurityRequirement, 0, len(*op.Security))
				for _, s := range *op.Security {
					sr := kdexv1alpha1.SecurityRequirement(s)
					raw = append(raw, sr)
					for scheme := range sr {
						if isAPIKeyScheme(scheme) {
							acceptsAPIKey = true
						}
					}
				}
				parsedRequirements[key] = hh.authChecker.ParseRequirements(raw)
			}
		}
	}

	fh := &KDexFunctionHandler{
		Function:           fn,
		parsedRequirements: parsedRequirements,
		bindingSpecs:       bindingSpecs,
		patternMux:         patternMux,
		acceptsAPIKey:      acceptsAPIKey,
		issuer:             issuer,
	}

	// Detect whether THIS function is oauth2-protected (declares the built-in
	// "oauth2" scheme on any operation) and, if so, capture its RFC 8707 resource
	// URI. A PAT presented on Authorization: Bearer is then validated against this
	// resource audience rather than the host audience. See Plan B Task 9.
	if res, ok := hh.oauth2ProtectedResources()[fn.Spec.API.BasePath]; ok {
		fh.oauth2Protected = true
		fh.oauth2Resource = res.Resource
	}

	if fh.oauth2Protected && hh.authConfig != nil && hh.authConfig.MintTokenEnabled {
		fh.mintTokenEnabled = true
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
		authConfig := hh.authConfig
		authExchanger := hh.authExchanger
		hh.mu.RUnlock()

		// PASETO -> authContext bridge. Fires only when (a) this function's API
		// declared an apiKey* scheme (fh.acceptsAPIKey) OR is oauth2-protected
		// (fh.oauth2Protected) AND (b) WithAuthentication did not already populate
		// authContext (JWT wins on mixed-token requests). On success the request
		// carries a structured authContext (sub/roles/entitlements/scp) derived
		// from the token subject, so the identity gate below and the FAT mint in
		// the proxy Rewrite treat the API-token caller exactly like a JWT-authed
		// one — the raw PASETO is still forwarded (cookie preserved in Rewrite;
		// X-API-TOKEN header and api_token query pass through untouched). See
		// kdex-tech/host-manager#103.
		//
		// An oauth2-protected function may declare no apiKey* scheme at all
		// (acceptsAPIKey false), so the bridge must still run for it.
		//
		// Resource binding is a property of the TOKEN, not of the function. Only
		// one issuer mints a resource-path audience: the RFC 8707 branch of the
		// token endpoint (auth.OAuth2.writeResourcePATResponse), reached when an
		// authorization_code/refresh_token request carries a recognized `resource`
		// — the DCR/MCP-client flow. Every other issuer mints the HOST audience,
		// notably /-/apitokens/mint, which backs the developer-keys UI. So the
		// acceptable audiences are derived from what the function's schemes admit,
		// tried most-specific first:
		//
		//   oauth2-protected  -> its RFC 8707 resource URI (Plan B Task 9)
		//   apiKey-accepting  -> the host audience
		//
		// Both apply to a function declaring both (knowdb-mcp does). Accepting the
		// host audience there does NOT weaken RFC 8707: a PAT bound to resource A
		// presented at resource B fails every entry (A != B, A != host), so
		// cross-resource replay stays blocked. Conditioning the resource audience
		// on the function alone instead made a CR's own apiKeyHeader/apiKeyQuery
		// alternatives unsatisfiable — no minted developer key could ever pass.
		if (fh.acceptsAPIKey || fh.oauth2Protected) && authConfig != nil && authConfig.TokenManager != nil {
			if _, alreadyLoggedIn := auth.GetAuthContext(r.Context()); !alreadyLoggedIn {
				expectedAuds := make([]string, 0, 2)
				if fh.oauth2Protected && fh.oauth2Resource != "" {
					expectedAuds = append(expectedAuds, fh.oauth2Resource)
				}
				if fh.acceptsAPIKey || !fh.oauth2Protected {
					expectedAuds = append(expectedAuds, authConfig.Audience)
				}
				if tok := extractBearerOrAPIToken(r, authConfig.TokenPrefix()); tok != "" && len(expectedAuds) > 0 {
					data, err := authConfig.TokenManager.ValidateToken(r.Context(), tok, expectedAuds[0])
					for _, aud := range expectedAuds[1:] {
						if err == nil {
							break
						}
						data, err = authConfig.TokenManager.ValidateToken(r.Context(), tok, aud)
					}
					if err != nil {
						// Invalid / expired / revoked / audience-mismatch token:
						// leave the request anonymous and let the gate decide.
						log.V(1).Info("api token rejected", "function", fn.Name, "err", err.Error())
					} else {
						// Reuse the JWT-mint path's subject resolver so PASETO and
						// JWT callers get identical structured entitlements.
						roles, ents, rerr := authExchanger.ResolveInternalRolesAndEntitlements(data.Subject)
						if rerr != nil {
							log.Error(rerr, "failed to resolve api token subject", "function", fn.Name, "subject", data.Subject)
						} else {
							ac := auth.AuthContext{
								"sub":          data.Subject,
								"roles":        roles,
								"entitlements": ents,
								// The token's static scope rides along under its own
								// key; the structured entitlements above are the
								// authoritative authz model.
								"scp": data.Scope,
								// Mark this identity as PAT-bridge-originated. A PAT
								// minted through the authorization-code (oauth2) flow
								// IS an oauth2 authentication, so GetParsedEntitlements
								// mirrors these role-resolved entitlements into the
								// "oauth2" scheme bucket — letting this caller satisfy
								// an operation that declares ONLY {oauth2: [...]}. This
								// marker is read solely by GetParsedEntitlements and is
								// scoped to the PAT path; JWT/cookie/apiKey callers
								// never carry it. See kdex-tech/host-manager §4.
								auth.PATBridgeClaim: true,
							}
							// Resolve the subject's data-driven backend claims FRESH
							// at request time and merge them (non-conflicting) onto
							// the authContext. Runs only on the !alreadyLoggedIn
							// bridge path, so a JWT/cookie caller — including a
							// downscoped capability token whose attenuated
							// entitlements WithAuthentication already placed in the
							// authContext — is never re-resolved or re-inflated here.
							// See #138.
							for k, v := range authExchanger.ResolveSubjectClaims(data.Subject) {
								if _, exists := ac[k]; !exists {
									ac[k] = v
								}
							}
							r = r.WithContext(auth.SetAuthContext(r.Context(), ac))
						}
					}
				}
			}
		}

		// Enrich the authContext with the SAME host + fn.Spec.ClaimMappings mapper
		// the FAT signer uses (built above), BEFORE the context is used to derive
		// `held` (the mint_token attenuation source), the identity gate, or the
		// FAT — so all three read one consistent, fully-enriched entitlement set.
		// Covers both a bridged PAT (context assembled above) and a JWT/cookie
		// caller (context set by the middleware); mutates the context map in place.
		// Idempotent for an already-enriched context and attenuation-safe: a
		// downscoped capability token carries no source claims to re-expand. This
		// is the authContext-enrichment invariant; no claim is special-cased. #142
		if ac, ok := auth.GetAuthContext(r.Context()); ok {
			auth.EnrichAuthContext(ac, mapper)
		}

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

			// Bind {param} requirements from the request before verifying, so the
			// gate checks the store actually being addressed rather than a
			// wildcard any single-store grant satisfies (entitlements#4).
			//
			// A bind error DENIES and must never fall through to Verify: an
			// unbound placeholder is an ordinary literal there, and a held
			// wildcard matches any literal, so falling through would silently
			// admit every wildcard holder. The error is the invariant enforcing
			// itself -- it means the CR declared an identity this layer cannot
			// supply.
			//
			// BindRequirements is a no-op for placeholder-free requirement sets,
			// so this is safe to call unconditionally -- no guard needed.
			spec := fh.bindingSpecs[key]
			binding := resolveBinding(r, pattern, spec, placeholderKeys(spec, pattern))
			boundReqs, bindErr := authChecker.BindRequirements(reqs, binding)
			if bindErr != nil {
				log.Error(bindErr, "requirement binding failed; denying",
					"function", fn.Name, "route", key)
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			reqs = boundReqs

			parsedUserEntitlements := authChecker.GetParsedEntitlements(r.Context())
			authorized, err := authChecker.VerifyResourceParsedEntitlements(
				"functions", fn.Spec.API.BasePath, parsedUserEntitlements, reqs)

			if err != nil || !authorized {
				if err != nil {
					log.Error(err, "authorization check failed", "function", fn.Name)
				} else {
					log.V(1).Info("unauthorized access attempt", "function", fn.Name)
				}
				// Defense-in-depth: only emit the 401 challenge when both flags are
				// set AND oauth2Resource is non-empty. An empty resource would produce
				// a malformed metadata URL (just the issuer root), so we fall through
				// to the anti-enumeration 404 in that degenerate case.
				if fh.oauth2Protected && fh.oauth2Resource != "" {
					w.Header().Set("WWW-Authenticate",
						`Bearer resource_metadata="`+fh.issuer+`/.well-known/oauth-protected-resource`+fn.Spec.API.BasePath+`"`)
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
				return
			}
		}

		// mint_token AS-augmentation: peek the JSON-RPC body of an
		// oauth2-protected MCP function. A tools/call for mint_token is handled
		// locally (never forwarded); a tools/list is marked so ModifyResponse
		// can splice the descriptor. All other bodies pass through untouched.
		if fh.mintTokenEnabled && r.Method == http.MethodPost && r.Body != nil {
			// Peek up to maxMintPeekBytes+1 to classify the JSON-RPC body without
			// buffering an arbitrarily large request.
			peek, rerr := io.ReadAll(io.LimitReader(r.Body, maxMintPeekBytes+1))
			if rerr == nil && len(peek) <= maxMintPeekBytes {
				// Small enough to fully buffer (EOF reached within the cap): the
				// original body is drained, so close it and forward the buffer.
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(peek))
				if id, args, matched := isMintTokenCall(peek); matched {
					ac, _ := auth.GetAuthContext(r.Context())
					sub, _ := ac["sub"].(string)
					held := stringSliceFromClaim(ac["entitlements"])
					hh.writeMintTokenRPC(w, r, id, sub, held, args)
					return
				}
				// whoami is a peer of mint_token: answered by the AS and never
				// forwarded, because only the AS knows who the caller is — the
				// backend sees a proxied request, not the credential.
				if id, matched := isWhoamiCall(peek); matched {
					hh.writeWhoamiRPC(w, r, id)
					return
				}
				if isToolsListCall(peek) {
					// Resolve the caller-facing /-/openapi discovery URL from the
					// INBOUND request here, where the ingress/Traefik-provided
					// X-Forwarded-* headers are intact — the outbound request's
					// SetXForwarded() would clobber them with internal values.
					r = r.WithContext(context.WithValue(
						r.Context(), mintTokenListDiscoveryURLKey, openapiDiscoveryURL(r)))
				}
			} else {
				// Oversized (or read error): NEVER truncate the forwarded body.
				// Prepend the peeked bytes back onto the still-unread remainder and
				// forward the full stream uninspected. The composed body's Close
				// closes the original underlying body (no leak).
				r.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(peek), r.Body), r.Body}
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

	// maxMintPeekBytes bounds how much of an MCP function's POST body the
	// mint_token interceptor buffers to classify it as a tools/call / tools/list
	// JSON-RPC request. A legitimate mint call is small; larger bodies are
	// forwarded in full and uninspected (never truncated).
	maxMintPeekBytes = 1 << 20
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

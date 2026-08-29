package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/utils"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// wildcardSegmentRe matches Go 1.22 ServeMux pattern wildcards: `{name}` or
// `{name...}`. Used by patternRegistered to derive a probe URL.
var wildcardSegmentRe = regexp.MustCompile(`\{[^}]+\}`)

// patternRegistered reports whether pattern (in `"METHOD /path"` form) is
// already attached to mux. It synthesizes a probe URL that resolves to that
// pattern and inspects mux.Handler's reply. Probe URLs replace each `{...}`
// segment with a sentinel ("__kdex_probe__") unlikely to collide with any
// concrete prefix already registered on the mux.
func patternRegistered(mux *http.ServeMux, pattern string) bool {
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		return false
	}
	// Strip the {$} end-of-path anchor so the probe URL is a concrete path.
	probe := strings.TrimSuffix(path, "{$}")
	probe = wildcardSegmentRe.ReplaceAllString(probe, "__kdex_probe__")
	if !strings.HasPrefix(probe, "/") {
		probe = "/" + probe
	}
	req, err := http.NewRequest(method, probe, nil)
	if err != nil {
		return false
	}
	_, matched := mux.Handler(req)
	return matched == pattern
}

func (hh *HostHandler) addHandlerAndRegister(
	mux *http.ServeMux,
	pr pageRender,
	registeredPaths map[string]ko.PathInfo,
	translations *Translations,
) (err error) {
	// Snapshot basePath once so every downstream use (finalPath, probe checks,
	// error messages) reads a consistent value, even if pr.ph's underlying
	// KDexPageSpec pointer is concurrently swapped by a reconcile.
	basePath := pr.ph.BasePath()
	if basePath == "" {
		hh.log.V(1).Info("page has empty basePath, skipping", "page", pr.ph.Name)
		return nil
	}

	finalPath := toFinalPath(basePath)
	label := pr.ph.Label()

	handler := hh.pageHandlerFunc(pr.ph, translations)

	regFunc := func(p string, n string, l string, pattern bool, localized bool) {
		reqs := hh.convertRequirements(pr.ph.Page.Security)

		op := &openapi.Operation{
			Description: fmt.Sprintf("Get HTML for %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), utils.IfElse(localized, " (localized)", "")),
			OperationID: fmt.Sprintf("%s%s%s-get", n, utils.IfElse(pattern, "-pattern", ""), utils.IfElse(localized, "-localized", "")),
			Parameters:  ko.ExtractParameters(p, "", http.Header{}),
			Responses: openapi.NewResponses(
				openapi.WithStatus(200, &openapi.ResponseRef{
					Value: &openapi.Response{
						Content: openapi.Content{
							"text/html": &openapi.MediaType{
								Schema: &openapi.SchemaRef{
									Value: &openapi.Schema{
										Format: "html",
										Type:   &openapi.Types{openapi.TypeString},
									},
								},
							},
						},
						Description: new(fmt.Sprintf("HTML for %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), utils.IfElse(localized, " (localized)", ""))),
					},
				}),
				openapi.WithStatus(303, &openapi.ResponseRef{
					Ref: ko.RespRefSeeOther,
				}),
				openapi.WithStatus(400, &openapi.ResponseRef{
					Ref: ko.RespRefBadRequest,
				}),
				openapi.WithStatus(404, &openapi.ResponseRef{
					Ref: ko.RespRefNotFound,
				}),
				openapi.WithStatus(500, &openapi.ResponseRef{
					Ref: ko.RespRefInternalServerError,
				}),
			),
			Security: reqs,
			Summary:  fmt.Sprintf("Get %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), utils.IfElse(localized, " (localized)", "")),
			Tags:     []string{n, "page"},
		}

		hh.registerPath(p, ko.PathInfo{
			API: ko.OpenAPI{
				BasePath: p,
				Paths: map[string]ko.PathItem{
					p: {
						Description: fmt.Sprintf("HTML page %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), utils.IfElse(localized, " (localized)", "")),
						Get:         op,
						Summary:     fmt.Sprintf("Page %s%s%s", l, utils.IfElse(pattern, " (pattern)", ""), utils.IfElse(localized, " (localized)", "")),
					},
				},
			},
			Type: ko.PagePathType,
		}, registeredPaths)
	}

	// Defensive idempotency: query the mux state directly before registering,
	// so duplicate registrations are skipped cleanly instead of panicking
	// through the recover below. The recover is kept as a safety net for
	// genuinely invalid patterns (mux.HandleFunc also panics on those).
	registerIfNew := func(pattern string) bool {
		if patternRegistered(mux, pattern) {
			hh.log.V(1).Info(
				"pattern already registered, skipping",
				"pattern", pattern, "page", pr.ph.Name, "basePath", basePath,
			)
			return false
		}
		mux.HandleFunc(pattern, handler)
		return true
	}

	// capture any panics from invalid patterns
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("error registering %s (final %s): %v", basePath, finalPath, r)
		}
	}()

	if registerIfNew("GET " + finalPath) {
		regFunc(finalPath, pr.ph.Name, label, false, false)
	}
	if registerIfNew("GET /{l10n}" + finalPath) {
		regFunc("/{l10n}"+finalPath, pr.ph.Name, label, false, true)
	}

	if pr.ph.Page != nil && pr.ph.Page.PatternPath != "" {
		patternPath := pr.ph.Page.PatternPath
		if registerIfNew("GET " + patternPath) {
			regFunc(patternPath, pr.ph.Name, label, true, false)
		}
		if registerIfNew("GET /{l10n}" + patternPath) {
			regFunc("/{l10n}"+patternPath, pr.ph.Name, label, true, true)
		}
	}

	return nil
}

func (hh *HostHandler) authorizeHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.IsAuthEnabled() {
		return
	}

	oauth2 := &auth.OAuth2{
		AuthConfig:        hh.authConfig,
		AuthExchanger:     hh.authExchanger,
		ResourceAudiences: hh.oauth2ResourceAudiences(),
		AccessTokenTTL:    hh.authConfig.TokenTTL,
	}

	const path = "/-/oauth/authorize"
	// Apply Authentication Middleware
	handler := hh.authConfig.AddAuthentication(http.HandlerFunc(oauth2.AuthorizeHandler), hh.authExchanger)
	mux.Handle("GET "+path, handler)

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "The OAuth2 authorization endpoint",
					Get: &openapi.Operation{
						Description: "GET to start authorization flow",
						OperationID: "authorize-get",
						Parameters: openapi.Parameters{
							ko.QueryParam("client_id", "The client ID"),
							ko.QueryParam("redirect_uri", "The redirect URI"),
							ko.QueryParam("response_type", "The response type (must be 'code')"),
							ko.QueryParam("scope", "The requested scopes"),
							ko.QueryParam("state", "The state parameter for CSRF protection"),
						},
						Responses: openapi.NewResponses(
							openapi.WithStatus(302, &openapi.ResponseRef{
								Ref: ko.RespRefFound,
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OAuth2 Authorization",
						Tags:    []string{"system", "oauth2", "auth"},
					},
					Summary: "OAuth2 authorization",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) checkHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/-/check"
	// Apply Authentication Middleware, then OPT IN to API-token identity.
	//
	// /-/check is a pure reporting endpoint — it answers "does the caller hold
	// this grant?" and confers nothing — so an API key should be able to ask
	// about itself. That is what kdex-tech/host-manager#175 was filed for.
	//
	// The opt-in is per route on purpose. Authenticating PATs in the global
	// middleware instead made a developer key a session-grade identity at
	// /-/oauth/authorize (redeemable for a JWT + rotating refresh token, which
	// escapes the key's own revocation) and at /-/apitokens/mint, and it
	// simultaneously displaced the proxy PAT bridge that aa73843 depends on.
	// Nothing inherits this by default.
	handler := hh.authConfig.WithAPITokenIdentity(hh.authExchanger)(
		hh.authConfig.AddAuthentication(http.HandlerFunc(hh.CheckHandler), hh.authExchanger))
	mux.Handle("POST "+path, handler)

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Enables checking multiple resource entitlements for the current user in a single request.",
					Post: &openapi.Operation{
						Description: "POST a list of resource identifiers to check authorization.",
						OperationID: "check-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Content: openapi.Content{
									"application/json": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Properties: openapi.Schemas{
													"checks": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Items: &openapi.SchemaRef{
																Value: &openapi.Schema{
																	Type: &openapi.Types{openapi.TypeString},
																},
															},
															Type: &openapi.Types{openapi.TypeArray},
														},
													},
												},
												Required: []string{"checks"},
												Type:     &openapi.Types{openapi.TypeObject},
											},
										},
									},
								},
								Description: "Check request body containing resource identifiers",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"passed": &openapi.SchemaRef{
												Value: &openapi.Schema{
													Items: &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													Type: &openapi.Types{openapi.TypeArray},
												},
											},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Subset of resource identifiers that passed the check"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Check Entitlements",
						Tags:    []string{"system", "auth"},
					},
					Summary: "Check multiple entitlements",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) discoveryHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.IsAuthEnabled() {
		return
	}

	const oauth2path = "/.well-known/oauth-authorization-server"
	mux.HandleFunc("GET "+oauth2path, func(w http.ResponseWriter, r *http.Request) {
		if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
			return
		}
		issuer := hh.serverAddress(r)
		regEndpoint := ""
		if hh.authConfig != nil && hh.authConfig.DCR.Enabled {
			regEndpoint = issuer + "/-/oauth/register"
		}
		auth.DiscoveryHandler(issuer, regEndpoint)(w, r)
	})
	registeredPaths[oauth2path] = ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: oauth2path,
			Paths: map[string]ko.PathItem{
				oauth2path: {
					Description: "Serve the OAuth 2.0 Authorization Server configuration",
					Get: &openapi.Operation{
						Description: "GET the OAuth 2.0 Authorization Server configuration",
						OperationID: "oauth2-authorization-server-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "json",
										Type:   &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("OpenID Configuration"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OAuth 2.0 Authorization Server configuration",
						Tags:    []string{"system", "oidc", "auth"},
					},
					Summary: "The OAuth 2.0 Authorization Server configuration",
				},
			},
		},
		Type: ko.SystemPathType,
	}

	const oidcPath = "/.well-known/openid-configuration"
	mux.HandleFunc("GET "+oidcPath, func(w http.ResponseWriter, r *http.Request) {
		if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
			return
		}
		issuer := hh.serverAddress(r)
		regEndpoint := ""
		if hh.authConfig != nil && hh.authConfig.DCR.Enabled {
			regEndpoint = issuer + "/-/oauth/register"
		}
		auth.DiscoveryHandler(issuer, regEndpoint)(w, r)
	})
	registeredPaths[oidcPath] = ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: oidcPath,
			Paths: map[string]ko.PathItem{
				oidcPath: {
					Description: "Serve the OpenID configuration",
					Get: &openapi.Operation{
						Description: "GET the OpenID configuration",
						OperationID: "discovery-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "json",
										Type:   &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("OpenID Configuration"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OpenID Discovery",
						Tags:    []string{"system", "oidc", "auth"},
					},
					Summary: "The OpenID configuration",
				},
			},
		},
		Type: ko.SystemPathType,
	}
}

func (hh *HostHandler) faviconHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/favicon.ico"
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
			return
		}
		hh.favicon.FaviconHandler(w, r)
	})
	registeredPaths[path] = ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "The favicon SVG resource",
					Get: &openapi.Operation{
						Description: "GET the favicon SVG",
						OperationID: "favicon-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "xml",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"image/svg+xml"},
								),
								Description: new("SVG Favicon"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Favicon SVG",
						Tags:    []string{"system", "favicon"},
					},
					Summary: "Favicon SVG resource",
				},
			},
		},
		Type: ko.SystemPathType,
	}
}

func (hh *HostHandler) jwksHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.IsAuthEnabled() {
		return
	}

	const path = "/.well-known/jwks.json"
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		if hh.applyCachingHeaders(w, r, hh.reconcileTime) {
			return
		}
		auth.JWKSHandler(hh.authConfig.KeyPairs)(w, r)
	})
	registeredPaths[path] = ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Serve the JWT key set",
					Get: &openapi.Operation{
						Description: "GET the JWT key set",
						OperationID: "jwks-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "json",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"application/json"},
								),
								Description: new("JWKS"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "The JWKS",
						Tags:    []string{"system", "jwks", "jwt", "auth"},
					},
					Summary: "The JWT key set",
				},
			},
		},
		Type: ko.SystemPathType,
	}
}

func (hh *HostHandler) loginHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.IsAuthEnabled() {
		return
	}

	const loginPath = "/-/login"
	mux.HandleFunc("GET "+loginPath, hh.LoginGet)
	mux.HandleFunc("POST "+loginPath, hh.LoginPost)

	hh.registerPath(loginPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: loginPath,
			Paths: map[string]ko.PathItem{
				loginPath: {
					Description: "Provides the login experience",
					Get: &openapi.Operation{
						Description: "GET the login view",
						OperationID: "login-get",
						Parameters: openapi.Parameters{
							ko.QueryParam("return", "The URL to redirect to after successful login"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "html",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"text/html"},
								),
								Description: new("HTML login page"),
							}),
							openapi.WithStatus(303, &openapi.ResponseRef{
								Ref: ko.RespRefSeeOther,
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(404, &openapi.ResponseRef{
								Ref: ko.RespRefNotFound,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Get login experience",
						Tags:    []string{"system", "login", "auth"},
					},
					Post: &openapi.Operation{
						Description: "POST to login action",
						OperationID: "login-post",
						Responses: openapi.NewResponses(
							openapi.WithStatus(303, &openapi.ResponseRef{
								Ref: ko.RespRefSeeOther,
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
						),
						Summary: "Login action",
						Tags:    []string{"system", "login", "auth"},
					},
					Summary: "Login experience",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	const loginClientRoutePath = "/-/login/{path...}"
	mux.HandleFunc("GET "+loginClientRoutePath, hh.LoginGet)

	hh.registerPath(loginClientRoutePath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: loginClientRoutePath,
			Paths: map[string]ko.PathItem{
				loginClientRoutePath: {
					Description: "Serves the login page shell for any sub-path beneath /-/login, enabling client-side routing between login views following the @kdex/ui app router pattern.",
					Get: &openapi.Operation{
						Description: "GET the login shell for a client-side route. The captured path is not interpreted server-side; every sub-path returns the same shell and the client router selects the active view from the URL. Because the login page is mounted under the reserved /-/ prefix (the app router's default path separator), a client hosting a router here must configure a data-path-separator that does not contain /-/.",
						OperationID: "login-clientroute-get",
						Parameters: openapi.Parameters{
							ko.WildcardPathParam("path", "Client-side route sub-path (e.g. viewport/appId/appPath); consumed by the @kdex/ui app router, not the server"),
							ko.QueryParam("return", "The URL to redirect to after successful login"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "html",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"text/html"},
								),
								Description: new("HTML login page shell"),
							}),
							openapi.WithStatus(303, &openapi.ResponseRef{
								Ref: ko.RespRefSeeOther,
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(404, &openapi.ResponseRef{
								Ref: ko.RespRefNotFound,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Get login experience (client-side route)",
						Tags:    []string{"system", "login", "auth"},
					},
					Summary: "Login experience client-side routing",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	const logoutPath = "/-/logout"
	mux.HandleFunc("POST "+logoutPath, hh.LogoutPost)

	hh.registerPath(logoutPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: logoutPath,
			Paths: map[string]ko.PathItem{
				logoutPath: {
					Description: "Provides the logout experience",
					Post: &openapi.Operation{
						Description: "POST to logout action",
						OperationID: "logout-post",
						Responses: openapi.NewResponses(
							openapi.WithStatus(302, &openapi.ResponseRef{
								Ref: ko.RespRefFound,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Logout action",
						Tags:    []string{"system", "logout", "auth"},
					},
					Summary: "Logout experience",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) navigationHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/-/navigation/{navKey}/{l10n}/{basePathMinusLeadingSlash...}"
	mux.HandleFunc("GET "+path, hh.NavigationGet)

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Dynamic HTML navigation components, supporting localization and breadcrumb contexts.",
					Get: &openapi.Operation{
						Description: "GET Dynamic HTML navigation",
						OperationID: "navigation-get",
						Parameters: openapi.Parameters{
							ko.WildcardPathParam("basePathMinusLeadingSlash", "The base path without the leading slash"),
							ko.PathParam("l10n", "The language tag"),
							ko.PathParam("navKey", "The navigation key"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "html",
										Type:   &openapi.Types{openapi.TypeString},
									},
									[]string{"text/html"},
								),
								Description: new("HTML navigation fragment"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(404, &openapi.ResponseRef{
								Ref: ko.RespRefNotFound,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Dynamic HTML navigation",
						Tags:    []string{"system", "navigation"},
					},
					Summary: "Dynamic HTML navigation components",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) notReadyHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// applyCachingHeadersWithLang folds the language tag into the ETag
	// so en-CA and fr-CA announcement renders get distinct ETags.
	// See kdex-tech/host-manager#43.
	if hh.applyCachingHeadersWithLang(w, r, nil, hh.reconcileTime, l.String()) {
		return
	}

	rendered := hh.renderUtilityPage(
		kdexv1alpha1.AnnouncementUtilityPageType,
		l,
		map[string]any{},
		&hh.Translations,
	)

	if rendered == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	log.V(1).Info("serving announcement page", "language", l.String())

	w.Header().Set("Content-Language", l.String())
	w.Header().Set("Content-Type", "text/html")

	_, err = w.Write([]byte(rendered))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (hh *HostHandler) oauthHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.authConfig.IsOIDCEnabled() {
		return
	}

	oauth2 := &auth.OAuth2{
		AuthConfig:        hh.authConfig,
		AuthExchanger:     hh.authExchanger,
		ResourceAudiences: hh.oauth2ResourceAudiences(),
		AccessTokenTTL:    hh.authConfig.TokenTTL,
	}
	// Shared with the redirect_uri derivation in internal/auth: the provider
	// compares the registered URI exactly, so the path we serve and the path we
	// send must be the same string by construction.
	const path = auth.OAuthCallbackPath
	mux.HandleFunc("GET "+path, oauth2.OAuthGet)

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "The OAuth2 support endpoint",
					Get: &openapi.Operation{
						Description: "GET OAuth2 Callback",
						OperationID: "oauth-get",
						Parameters: openapi.Parameters{
							ko.QueryParam("code", "The authorization code"),
							ko.QueryParam("state", "The state parameter for CSRF protection"),
						},
						Responses: openapi.NewResponses(
							openapi.WithStatus(303, &openapi.ResponseRef{
								Ref: ko.RespRefSeeOther,
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OAuth2 Callback",
						Tags:    []string{"system", "oauth2", "auth"},
					},
					Summary: "OAuth2 support",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) openapiHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/-/openapi"

	mux.HandleFunc("GET "+path, hh.OpenAPIGet)

	// Register the path itself so it appears in the spec
	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Serves the generated OpenAPI 3.0 specification for this host.",
					Get: &openapi.Operation{
						Description: "GET OpenAPI 3.0 Spec",
						OperationID: "openapi-get",
						Parameters: openapi.Parameters{
							ko.ArrayQueryParam("path", "Filter by paths"),
							ko.ArrayQueryParam("tag", "Filter by tags"),
							ko.ArrayQueryParam("type", "Filter by path types"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										AdditionalProperties: openapi.AdditionalProperties{
											Has: new(true),
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("OpenAPI documentation"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OpenAPI 3.0 Spec",
						Tags:    []string{"system", "openapi"},
					},
					Summary: "Generated OpenAPI 3.0 specification",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) schemaHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const listPath = "/-/schemas"
	mux.HandleFunc("GET "+listPath, hh.SchemaListGet)

	const path = "/-/schemas/{path...}"
	mux.HandleFunc("GET "+path, hh.SchemaGet)

	// Register the schemas list path so it appears in the spec
	hh.registerPath(listPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: listPath,
			Paths: map[string]ko.PathItem{
				listPath: {
					Description: "Lists all registered JSON schemas and their URLs.",
					Get: &openapi.Operation{
						Description: "List all schemas",
						OperationID: "schema-list",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"items": &openapi.SchemaRef{
												Value: &openapi.Schema{
													Items: &openapi.SchemaRef{
														Value: &openapi.Schema{
															Properties: openapi.Schemas{
																"name": &openapi.SchemaRef{
																	Value: &openapi.Schema{
																		Type: &openapi.Types{openapi.TypeString},
																	},
																},
																"urls": &openapi.SchemaRef{
																	Value: &openapi.Schema{
																		Items: openapi.NewSchemaRef("", openapi.NewStringSchema()),
																		Type:  &openapi.Types{openapi.TypeArray},
																	},
																},
															},
															Type: &openapi.Types{openapi.TypeObject},
														},
													},
													Type: &openapi.Types{openapi.TypeArray},
												},
											},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Schema list"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Schema List",
						Tags:    []string{"system", "jsonschema", "schema", "openapi"},
					},
					Summary: "List all schemas",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	// Register the path itself so it appears in the spec
	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Serves individual JSONschema from the registered OpenAPI specifications. The path should be in the format /-/schemas/{basePath}/{schemaName} (e.g., /-/schemas/v1/users/User) or simply /-/schemas/{schemaName} for a global lookup.",
					Get: &openapi.Operation{
						Description: "GET JSONschema",
						OperationID: "schema-get",
						Parameters: openapi.Parameters{
							ko.WildcardPathParam("path", "The schema path (e.g., v1/users/User or User)"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("JSONschema fragment"),
							}),
							openapi.WithStatus(404, &openapi.ResponseRef{
								Ref: ko.RespRefNotFound,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "JSONschema",
						Tags:    []string{"system", "jsonschema", "schema", "openapi"},
					},
					Summary: "JSONschema Provider",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) snifferHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.sniffer != nil {
		const inspectPath = "/-/sniffer/inspect/{uuid}"
		mux.HandleFunc("GET "+inspectPath, hh.InspectHandler)

		hh.registerPath(inspectPath, ko.PathInfo{
			API: ko.OpenAPI{
				BasePath: inspectPath,
				Paths: map[string]ko.PathItem{
					inspectPath: {
						Description: "Provides inspection dashboard for the Request Sniffer's computed results.",
						Get: &openapi.Operation{
							Description: "GET Sniffer dashboard",
							OperationID: "sniffer-dashboard-get",
							Parameters: openapi.Parameters{
								ko.QueryParam("format", "The output format (e.g., 'text' or 'html')"),
								ko.PathParam("uuid", "The request UUID"),
							},
							Responses: openapi.NewResponses(
								openapi.WithName("200", &openapi.Response{
									Description: new("Dashboard"),
									Content: openapi.NewContentWithSchema(
										&openapi.Schema{
											Format: "text",
											Type:   &openapi.Types{openapi.TypeString},
										},
										[]string{"text/plain"},
									),
								}),
								openapi.WithName("200", &openapi.Response{
									Description: new("Dashboard"),
									Content: openapi.NewContentWithSchema(
										&openapi.Schema{
											Format: "html",
											Type:   &openapi.Types{openapi.TypeString},
										},
										[]string{"text/html"},
									),
								}),
								openapi.WithStatus(404, &openapi.ResponseRef{
									Ref: ko.RespRefNotFound,
								}),
								openapi.WithStatus(500, &openapi.ResponseRef{
									Ref: ko.RespRefInternalServerError,
								}),
							),
							Summary: "Sniffer Dashboard",
							Tags:    []string{"system", "sniffer", "dashboard"},
						},
						Summary: "Provides inspection dashboard",
					},
				},
			},
			Type: ko.SystemPathType,
		}, registeredPaths)

		const docsPath = "/-/sniffer/docs"
		mux.HandleFunc("GET "+docsPath, hh.sniffer.DocsHandler)

		hh.registerPath(docsPath, ko.PathInfo{
			API: ko.OpenAPI{
				BasePath: docsPath,
				Paths: map[string]ko.PathItem{
					docsPath: {
						Description: "Provides Markdown documentation for the Request Sniffer's supported headers and behaviors.",
						Get: &openapi.Operation{
							Description: "GET Sniffer Docs",
							OperationID: "sniffer-docs-get",
							Parameters:  openapi.Parameters{},
							Responses: openapi.NewResponses(
								openapi.WithName("200", &openapi.Response{
									Description: new("Markdown"),
									Content: openapi.NewContentWithSchema(
										&openapi.Schema{
											Format: "markdown",
											Type:   &openapi.Types{openapi.TypeString},
										},
										[]string{"text/markdown"},
									),
								}),
								openapi.WithStatus(500, &openapi.ResponseRef{
									Ref: ko.RespRefInternalServerError,
								}),
							),
							Summary: "Sniffer Docs",
							Tags:    []string{"system", "sniffer", "docs"},
						},
						Summary: "Request Sniffer Documentation",
					},
				},
			},
			Type: ko.SystemPathType,
		}, registeredPaths)
	}
}

func (hh *HostHandler) stateHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/-/state/"
	mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		authContext, ok := auth.GetAuthContext(r.Context())
		if !ok {
			// The purest Unauthenticated row there is: no credential was
			// presented at all. This answered a bare 401, which violates
			// RFC 7235 (a 401 MUST carry a challenge) and the contract's
			// own "every 401 carries a challenge" constraint.
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Unauthenticated,
				Issuer:  hh.issuerAddress(),
			})
			return
		}

		log := logf.FromContext(r.Context())

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(authContext); err != nil {
			log.Error(err, "failed to encode claims")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	})

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Returns the current authenticated session state (claims) without requiring the client to parse the JWT.",
					Get: &openapi.Operation{
						Description: "GET authenticated session state",
						OperationID: "state-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "json",
										Type:   &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Current session claims"),
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Authenticated session state",
						Tags:    []string{"system", "state", "auth"},
					},
					Summary: "The current authenticated session state (claims)",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) tokenHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if !hh.IsAuthEnabled() {
		return
	}

	oauth2 := &auth.OAuth2{
		AuthConfig:        hh.authConfig,
		AuthExchanger:     hh.authExchanger,
		ResourceAudiences: hh.oauth2ResourceAudiences(),
		AccessTokenTTL:    hh.authConfig.TokenTTL,
	}
	const path = "/-/token"
	mux.HandleFunc("POST "+path, oauth2.OAuth2TokenHandler)
	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "The OAuth2 token endpoint",
					Post: &openapi.Operation{
						Description: "POST to exchange credentials for a token",
						OperationID: "token-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Content: openapi.Content{
									"application/x-www-form-urlencoded": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Properties: openapi.Schemas{
													"client_id": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"client_secret": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"code": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"grant_type": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"password": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"redirect_uri": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"scope": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
													"username": &openapi.SchemaRef{
														Value: &openapi.Schema{
															Type: &openapi.Types{openapi.TypeString},
														},
													},
												},
												Required: []string{"grant_type", "client_id"},
												Type:     &openapi.Types{openapi.TypeObject},
											},
										},
									},
								},
								Description: "Token request body",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Format: "json",
										Type:   &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Token Response"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "OAuth2 Token",
						Tags:    []string{"system", "oauth2", "auth"},
					},
					Summary: "The OAuth2 token endpoint",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

func (hh *HostHandler) translationHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	const path = "/-/translation/{l10n}"
	mux.HandleFunc("GET "+path, hh.TranslationGet)

	hh.registerPath(path, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: path,
			Paths: map[string]ko.PathItem{
				path: {
					Description: "Provides localization keys and their translated values for a given language tag as JSON.",
					Get: &openapi.Operation{
						Description: "GET localization keys and their translated values",
						OperationID: "translation-get",
						Parameters: openapi.Parameters{
							ko.ArrayQueryParam("key", "Filter by specific translation keys"),
							ko.PathParam("l10n", "The language tag"),
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Description: new("JSON translation map"),
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										AdditionalProperties: openapi.AdditionalProperties{
											Has: new(true),
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "Localization keys and their translated values",
						Tags:    []string{"system", "translation", "localization"},
					},
					Summary: "Localization keys and their translated values",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

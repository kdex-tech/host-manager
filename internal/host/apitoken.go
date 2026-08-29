package host

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// maxAPITokenRequestBytes caps API-token request bodies (mint, verify,
// revoke). These payloads are short metadata-only documents.
const maxAPITokenRequestBytes = 64 << 10

type MintRequest struct {
	// Action is the action of the tokens to mint (metadata-based revocation).
	Action string `json:"act"`
	// Audience is the audience of the tokens to mint (metadata-based revocation).
	Audience string `json:"aud"`
	// Scope is the scope of the tokens to mint (metadata-based revocation).
	Scope string `json:"scp"`
	// Sub is the subject of the tokens to mint (metadata-based revocation).
	Sub string `json:"sub"`
	// TTL is the duration for which the tokens should be valid (metadata-based revocation).
	// Default: 24h.
	TTL string `json:"ttl"`
}

type MintResponse struct {
	Token string `json:"token"`
}

type VerifyRequest struct {
	Token string `json:"token"`
}

// RevokeRequest is the request body for the token revocation endpoint.
type RevokeRequest struct {
	// Action is the action of the tokens to revoke (metadata-based revocation).
	Action string `json:"act"`
	// Audience is the audience of the tokens to revoke (metadata-based revocation).
	Audience string `json:"aud"`
	// Sub is the subject of the tokens to revoke (metadata-based revocation).
	Sub string `json:"sub"`
	// TTL is the duration for which the revocation should be persisted in the cache (metadata-based revocation).
	// Default: 24h.
	TTL string `json:"ttl"`
	// Token is the full signed token to revoke.
	Token string `json:"token"`
}

// RevokeResponse is the response body for the token revocation endpoint.
type RevokeResponse struct {
	// Status is the result of the revocation request.
	Status string `json:"status"`
}

// apitokenRevokeHandler handles token revocation requests.
// It allows users to revoke their own tokens or for authorized administrators
// (with the "apitokens:revoke" entitlement) to revoke any token.
func (hh *HostHandler) apitokenRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ac, ok := auth.GetAuthContext(r.Context())
	if !ok {
		log.V(1).Info("no auth context; rejecting")
		denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
		return
	}

	requestingSub, err := ac.GetSubject()
	if err != nil || requestingSub == "" {
		log.V(1).Info("no subject in auth context; rejecting")
		denial.Write(w, r, denial.Opts{Outcome: denial.Unauthenticated, Issuer: hh.issuerAddress()})
		return
	}

	var req RevokeRequest
	if err := kdexhttp.DecodeJSONBody(w, r, maxAPITokenRequestBytes, &req); err != nil {
		log.Error(err, "Failed to decode request body")
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.authConfig == nil || hh.authConfig.TokenManager == nil {
		log.Error(nil, "Token manager not configured")
		http.Error(w, "Token manager not configured", http.StatusNotImplemented)
		return
	}

	targetSub := ""
	if req.Token != "" {
		// Revocation extracts subject from a token regardless of which
		// audience it was minted for — the token is being inspected,
		// not used for authentication on the current request. Skip the
		// audience check by passing "". See kdex-tech/host-manager#69.
		data, err := hh.authConfig.TokenManager.ValidateToken(r.Context(), req.Token, "")
		if err != nil {
			log.Error(err, "Invalid token provided for revocation")
			http.Error(w, "Invalid token", http.StatusBadRequest)
			return
		}
		targetSub = data.Subject
	} else if req.Audience != "" && req.Sub != "" && req.Action != "" {
		targetSub = req.Sub
	} else {
		log.Error(nil, "Neither token nor full metadata provided for revocation")
		http.Error(w, "Neither token nor full metadata provided", http.StatusBadRequest)
		return
	}

	if targetSub != requestingSub {
		requirement := kdexv1alpha1.SecurityRequirement{
			"bearer": []string{"apitokens:revoke"},
		}

		authorized, err := hh.authChecker.CheckAccess(
			r.Context(),
			"apitokens",
			requestingSub,
			[]kdexv1alpha1.SecurityRequirement{requirement},
			"revoke",
		)
		if err != nil || !authorized {
			log.V(1).Info("revoke denied: caller may not revoke for another subject",
				"subject", requestingSub)
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Classify(
					r.Context(), hh.authChecker, "apitokens", requestingSub, "revoke"),
				Issuer: hh.issuerAddress(),
			})
			return
		}
	}

	if req.Token != "" {
		if err := hh.authConfig.TokenManager.RevokeToken(r.Context(), req.Token); err != nil {
			log.Error(err, "Failed to revoke token")
			http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
			return
		}
	} else {
		ttl := 24 * time.Hour
		if req.TTL != "" {
			if t, err := time.ParseDuration(req.TTL); err == nil {
				ttl = t
			}
		}

		if err := hh.authConfig.TokenManager.RevokeByMetadata(r.Context(), req.Audience, req.Sub, req.Action, ttl); err != nil {
			log.Error(err, "Failed to revoke tokens by metadata")
			http.Error(w, "Failed to revoke tokens by metadata", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(RevokeResponse{Status: "revoked"}); err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokenDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	if r.Method != http.MethodGet {
		log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	keys := []map[string]string{}

	for _, keyPair := range hh.authConfig.TokenManager.KeyPairs() {
		pubStr := "k4.public." + base64.RawURLEncoding.EncodeToString(keyPair.PublicKey.ExportBytes())

		keys = append(keys, map[string]string{
			"kid": keyPair.KeyId,
			"alg": "v4.public",
			"key": pubStr,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(map[string]any{
		"keys": keys,
	})
	if err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokenMintHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MintRequest
	if err := kdexhttp.DecodeJSONBody(w, r, maxAPITokenRequestBytes, &req); err != nil {
		log.Error(err, "Failed to decode request body")
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	audience := req.Audience
	if audience == "" {
		log.Error(nil, "aud is required")
		http.Error(w, "aud is required", http.StatusBadRequest)
		return
	}

	subject := req.Sub
	if subject == "" {
		log.Error(nil, "sub is required")
		http.Error(w, "sub is required", http.StatusBadRequest)
		return
	}

	// 1. Check Entitlement
	requirement := kdexv1alpha1.SecurityRequirement{
		"bearer": []string{"apitokens:mint"},
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	authorized, err := hh.authChecker.CheckAccess(
		r.Context(),
		"apitokens",
		subject,
		[]kdexv1alpha1.SecurityRequirement{requirement},
		"mint",
	)
	if err != nil || !authorized {
		log.V(1).Info("mint denied", "subject", subject)
		denial.Write(w, r, denial.Opts{
			Outcome: denial.Classify(r.Context(), hh.authChecker, "apitokens", subject, "mint"),
			Issuer:  hh.issuerAddress(),
		})
		return
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		ttl = 24 * time.Hour // Default
	}

	if hh.authConfig.TokenManager == nil {
		log.Error(nil, "Token manager not configured")
		http.Error(w, "Token manager not configured", http.StatusNotImplemented)
		return
	}

	token, err := hh.authConfig.TokenManager.MintStatelessKey(audience, subject, req.Action, req.Scope, ttl)
	if err != nil {
		log.Error(err, "Failed to mint token")
		http.Error(w, "Failed to mint token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(MintResponse{Token: token})
	if err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokenVerifyHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := kdexhttp.DecodeJSONBody(w, r, maxAPITokenRequestBytes, &req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.authConfig.TokenManager == nil {
		http.Error(w, "Token manager not configured", http.StatusInternalServerError)
		return
	}

	tokenString := req.Token
	if after, ok := strings.CutPrefix(tokenString, "Bearer "); ok {
		tokenString = after
	}

	// Verify enforces the host's own audience: a token minted for a
	// different audience must NOT be considered valid for use here.
	// Pre-#69 this defaulted to "accept any audience" — confused-deputy.
	data, err := hh.authConfig.TokenManager.ValidateToken(r.Context(), tokenString, hh.authConfig.Audience)
	if err != nil {
		log.Error(err, "Token verification failed")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokensHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authConfig == nil || hh.authConfig.TokenManager == nil {
		return
	}

	discoveryPath := "/.well-known/pks.json"
	mux.HandleFunc("GET "+discoveryPath, hh.apitokenDiscoveryHandler)

	mintPath := "/-/apitokens/mint"
	apiTokenHandler := hh.authConfig.AddAuthentication(http.HandlerFunc(hh.apitokenMintHandler), hh.authExchanger)
	mux.Handle("POST "+mintPath, apiTokenHandler)

	verifyPath := "/-/apitokens/verify"
	apitokenVerifyHandler := hh.authConfig.AddAuthentication(http.HandlerFunc(hh.apitokenVerifyHandler), hh.authExchanger)
	mux.Handle("POST "+verifyPath, apitokenVerifyHandler)

	revokePath := "/-/apitokens/revoke"
	apitokenRevokeHandler := hh.authConfig.AddAuthentication(http.HandlerFunc(hh.apitokenRevokeHandler), hh.authExchanger)
	mux.Handle("POST "+revokePath, apitokenRevokeHandler)

	hh.registerPath(discoveryPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: discoveryPath,
			Paths: map[string]ko.PathItem{
				discoveryPath: {
					Description: "Returns the public keys for verifying PASETO tokens in a format similar to JWKS but for PASETO v4.public keys.",
					Get: &openapi.Operation{
						Description: "GET the public keys for PASETO verification",
						OperationID: "apitoken-discovery-get",
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"keys": &openapi.SchemaRef{
												Value: &openapi.Schema{
													Items: &openapi.SchemaRef{
														Value: &openapi.Schema{
															Properties: openapi.Schemas{
																"alg": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
																"key": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
																"kid": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
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
								Description: new("PASETO Public Keys"),
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Summary: "PASETO Public Keys Discovery",
						Tags:    []string{"system", "apitoken", "auth"},
					},
					Summary: "PASETO public keys discovery",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(mintPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: mintPath,
			Paths: map[string]ko.PathItem{
				mintPath: {
					Description: "Mints a new stateless PASETO API token for a given subject and audience.",
					Post: &openapi.Operation{
						Description: "POST to mint a new PASETO API token",
						OperationID: "apitoken-mint-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Content: openapi.Content{
									"application/json": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Properties: openapi.Schemas{
													"act": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"aud": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"scp": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"sub": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"ttl": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
												},
												Required: []string{"aud", "sub"},
												Type:     &openapi.Types{openapi.TypeObject},
											},
										},
									},
								},
								Description: "Mint request body",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"token": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Minted PASETO Token"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							// An anonymous caller now gets 401 + a challenge,
							// not the 403 this endpoint used to answer for
							// every denial. /-/openapi is the denial
							// contract's load-bearing dependency -- retiring
							// the anti-enumeration 404 is only safe because
							// the spec already publishes every path -- so a
							// spec that misdescribes the host's own auth
							// endpoints undercuts the whole design.
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(403, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("Forbidden"),
								},
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Security: &openapi.SecurityRequirements{
							openapi.SecurityRequirement{
								"bearer": {"apitokens:mint"},
							},
						},
						Summary: "Mint PASETO API Token",
						Tags:    []string{"system", "apitoken", "auth"},
					},
					Summary: "Mint PASETO API token",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(verifyPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: verifyPath,
			Paths: map[string]ko.PathItem{
				verifyPath: {
					Description: "Verifies a PASETO API token and returns its decoded claims.",
					Post: &openapi.Operation{
						Description: "POST to verify a PASETO API token",
						OperationID: "apitoken-verify-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Content: openapi.Content{
									"application/json": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Properties: openapi.Schemas{
													"token": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
												},
												Required: []string{"token"},
												Type:     &openapi.Types{openapi.TypeObject},
											},
										},
									},
								},
								Description: "Verify request body",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"act": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"aud": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"exp": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeInteger}}},
											"iat": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeInteger}}},
											"iss": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"jti": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"kid": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"nbf": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeInteger}}},
											"scp": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"sub": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Verified Token Claims"),
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
						Summary: "Verify PASETO API Token",
						Tags:    []string{"system", "apitoken", "auth"},
					},
					Summary: "Verify PASETO API token",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(revokePath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: revokePath,
			Paths: map[string]ko.PathItem{
				revokePath: {
					Description: "Revokes PASETO API tokens by their signed string or metadata.",
					Post: &openapi.Operation{
						Description: "POST to revoke PASETO API tokens",
						OperationID: "apitoken-revoke-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Content: openapi.Content{
									"application/json": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Properties: openapi.Schemas{
													"act":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"aud":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"sub":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"token": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"ttl":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
												},
												Type: &openapi.Types{openapi.TypeObject},
											},
										},
									},
								},
								Description: "Revoke request body",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Properties: openapi.Schemas{
											"status": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Revocation Confirmation"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: ko.RespRefBadRequest,
							}),
							// 401 for an anonymous caller, same as mint
							// above -- pre-existing omission, same reason.
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: ko.RespRefUnauthorized,
							}),
							openapi.WithStatus(403, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("Forbidden"),
								},
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: ko.RespRefInternalServerError,
							}),
						),
						Security: &openapi.SecurityRequirements{
							openapi.SecurityRequirement{
								"bearer": {"apitokens:revoke"},
							},
						},
						Summary: "Revoke PASETO API Token",
						Tags:    []string{"system", "apitoken", "auth"},
					},
					Summary: "Revoke PASETO API token",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

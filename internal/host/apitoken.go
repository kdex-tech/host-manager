package host

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type MintRequest struct {
	Action   string `json:"action"`
	Audience string `json:"aud"`
	Scope    string `json:"scope"`
	Sub      string `json:"sub"`
	TTL      string `json:"ttl"`
}

type MintResponse struct {
	Token string `json:"token"`
}

type VerifyRequest struct {
	Token string `json:"token"`
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
	err := json.NewEncoder(w).Encode(map[string]interface{}{
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		"tokens",
		subject,
		[]kdexv1alpha1.SecurityRequirement{requirement},
		"mint",
	)
	if err != nil || !authorized {
		log.Error(err, "Failed to check access")
		http.Error(w, "Forbidden", http.StatusForbidden)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	data, err := hh.authConfig.TokenManager.ValidateToken(tokenString)
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
								Ref: "#/components/responses/InternalServerError",
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
													"action": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"aud":    &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"scope":  &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"sub":    &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"ttl":    &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
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
								Ref: "#/components/responses/BadRequest",
							}),
							openapi.WithStatus(403, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("Forbidden"),
								},
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: "#/components/responses/InternalServerError",
							}),
						),
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
											"Action":  &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"Scope":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
											"Subject": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
										},
										Type: &openapi.Types{openapi.TypeObject},
									},
									[]string{"application/json"},
								),
								Description: new("Verified Token Claims"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: "#/components/responses/BadRequest",
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: "#/components/responses/Unauthorized",
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: "#/components/responses/InternalServerError",
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
}

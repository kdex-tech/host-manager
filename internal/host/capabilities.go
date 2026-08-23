package host

import (
	"encoding/json"
	"net/http"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// capabilitiesMintPath is the REST surface for capability minting — the same
// core the mint_token MCP tool calls, reachable without composing a JSON-RPC
// envelope and without a function that happens to declare the oauth2 scheme.
//
// Named as a sibling of /-/apitokens/mint (both mint a credential) rather than
// under /-/transfer/ (which stays purely the redemption surface), because this
// route also serves delivery:"bearer", which produces no transfer link at all.
// See kdex-tech/host-manager#186.
const capabilitiesMintPath = "/-/capabilities/mint"

// maxCapabilityRequestBytes caps mint bodies. The payload is an entitlement
// list plus a target path — kilobytes at the outside.
const maxCapabilityRequestBytes = 64 << 10

// capabilitiesHandler registers the REST mint route whenever minting is enabled
// on the host.
//
// Deliberately NOT gated on anything about the host's functions. The MCP path
// is armed per-function by `oauth2Protected`, which made a host-level
// capability silently unavailable when no application CR happened to declare
// the oauth2 scheme. This route is the surface that always exists.
func (hh *HostHandler) capabilitiesHandler(mux *http.ServeMux, registeredPaths map[string]ko.PathInfo) {
	if hh.authConfig == nil || !hh.authConfig.MintTokenEnabled {
		return
	}

	// Opt in to PASETO developer keys. WithAuthentication alone leaves a PAT
	// anonymous by design, so without this the REST surface would accept only a
	// session cookie or an OAuth2 access token — useless to the CI jobs and ops
	// scripts it exists to serve, and strictly weaker than the MCP path, whose
	// proxy bridge already authenticates all three PAT deliveries.
	//
	// Safe here in a way it is NOT at /-/apitokens/mint or /-/oauth/authorize,
	// which refuse a PAT so a key cannot mint a longer-lived credential than
	// itself: a capability is bounded BELOW the key by construction — its
	// entitlements are attenuated from the caller's own, its lifetime is clamped
	// to MintTokenTTLCap, and url delivery is single-use. Only a HOST-audience
	// key is accepted; a function-bound key stays anonymous.
	mux.Handle("POST "+capabilitiesMintPath,
		hh.authConfig.WithAPITokenIdentity(hh.authExchanger)(
			hh.authConfig.AddAuthentication(
				http.HandlerFunc(hh.capabilityMintHandler), hh.authExchanger)))

	hh.registerPath(capabilitiesMintPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: capabilitiesMintPath,
			Paths: map[string]ko.PathItem{
				capabilitiesMintPath: {
					Description: "Mints a short-lived, attenuated capability carrying a subset of the caller's own entitlements.",
					Post: &openapi.Operation{
						Description: "POST to mint a capability. Every requested entitlement must already be held by " +
							"the caller — the mint attenuates, never escalates. delivery \"bearer\" (the default) " +
							"returns a token to send as Authorization: Bearer. delivery \"url\" returns a single-use, " +
							"credential-less /-/transfer/<handle> link performing exactly the bound target, and " +
							"requires that the host enables urlDelivery. ttl and uses are clamped by host policy; " +
							"url delivery is always single-use, and a destructive verb forces uses=1 and the shortest ttl.",
						OperationID: "capability-mint-post",
						RequestBody: &openapi.RequestBodyRef{
							Value: &openapi.RequestBody{
								Required: true,
								Content: openapi.Content{
									"application/json": &openapi.MediaType{
										Schema: &openapi.SchemaRef{
											Value: &openapi.Schema{
												Type:     &openapi.Types{openapi.TypeObject},
												Required: []string{"entitlements"},
												Properties: openapi.Schemas{
													"entitlements": &openapi.SchemaRef{Value: &openapi.Schema{
														Type:        &openapi.Types{openapi.TypeArray},
														Description: "kdex-entitlements patterns (<resource>:<resourceName>:<verb>); each must be held by the caller.",
														Items:       &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													}},
													"ttl_seconds": &openapi.SchemaRef{Value: &openapi.Schema{
														Type:        &openapi.Types{openapi.TypeInteger},
														Description: "Requested lifetime in seconds; capped server-side by mintToken.ttlCapSeconds.",
													}},
													"uses": &openapi.SchemaRef{Value: &openapi.Schema{
														Type:        &openapi.Types{openapi.TypeInteger},
														Description: "Requested use budget; capped by mintToken.usesCap. Forced to 1 for url delivery and for destructive verbs.",
													}},
													"delivery": &openapi.SchemaRef{Value: &openapi.Schema{
														Type:        &openapi.Types{openapi.TypeString},
														Enum:        []any{"bearer", "url"},
														Description: "How to deliver the capability. Defaults to bearer.",
													}},
													"target": &openapi.SchemaRef{Value: &openapi.Schema{
														Type:        &openapi.Types{openapi.TypeObject},
														Description: "Required for url delivery: the single operation the link performs. Download-only.",
														Required:    []string{"method", "path"},
														Properties: openapi.Schemas{
															"method": &openapi.SchemaRef{Value: &openapi.Schema{
																Type: &openapi.Types{openapi.TypeString},
																Enum: []any{"GET"},
															}},
															"path": &openapi.SchemaRef{Value: &openapi.Schema{
																Type:        &openapi.Types{openapi.TypeString},
																Description: "Absolute path, not under the reserved /-/ prefix and containing no . or .. segments.",
															}},
														},
													}},
												},
											},
										},
									},
								},
								Description: "Capability mint request",
							},
						},
						Responses: openapi.NewResponses(
							openapi.WithName("200", &openapi.Response{
								Content: openapi.NewContentWithSchema(
									&openapi.Schema{
										Type:     &openapi.Types{openapi.TypeObject},
										Required: []string{"expires_at", "entitlements", "uses_remaining"},
										Properties: openapi.Schemas{
											"token": &openapi.SchemaRef{Value: &openapi.Schema{
												Type:        &openapi.Types{openapi.TypeString},
												Description: "Present for bearer delivery only.",
											}},
											"url": &openapi.SchemaRef{Value: &openapi.Schema{
												Type:        &openapi.Types{openapi.TypeString},
												Description: "Present for url delivery only: the redeemable /-/transfer/<handle> link.",
											}},
											"expires_at":     &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeInteger}}},
											"entitlements":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeArray}, Items: &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}}}},
											"uses_remaining": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeInteger}}},
										},
									},
									[]string{"application/json"},
								),
								Description: new("The minted capability"),
							}),
							openapi.WithStatus(400, &openapi.ResponseRef{
								Ref: "#/components/responses/BadRequest",
							}),
							openapi.WithStatus(401, &openapi.ResponseRef{
								Ref: "#/components/responses/Unauthorized",
							}),
							openapi.WithStatus(403, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("Policy refusal: an entitlement is not held by the caller, or the " +
										"requested delivery is disabled on this host."),
								},
							}),
							openapi.WithStatus(500, &openapi.ResponseRef{
								Ref: "#/components/responses/InternalServerError",
							}),
							openapi.WithStatus(503, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("URL delivery is enabled but no cache is configured to hold the capability."),
								},
							}),
						),
						Security: &openapi.SecurityRequirements{
							openapi.SecurityRequirement{"bearer": {}},
							openapi.SecurityRequirement{"apiKeyHeader": {}},
						},
						Summary: "Mint a capability",
						Tags:    []string{"system", "capability", "auth"},
					},
					Summary: "Mint a capability",
				},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

// capabilityMintHandler is the REST twin of writeMintTokenRPC: same core, same
// attenuation, same clamping — but real HTTP status codes instead of MCP's
// isError-over-200, so an ordinary client can branch on the response.
func (hh *HostHandler) capabilityMintHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	var req MintTokenRequest
	if err := kdexhttp.DecodeJSONBody(w, r, maxCapabilityRequestBytes, &req); err != nil {
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	// Identity comes from the request's auth context exactly as it does on the
	// MCP path, so every credential surface the host accepts works here too.
	ac, _ := auth.GetAuthContext(r.Context())
	sub, _ := ac["sub"].(string)
	if sub == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	held := stringSliceFromClaim(ac["entitlements"])

	res, err := hh.mintCapabilityToken(r.Context(), sub, held, req, transferBaseURL(r))
	if err != nil {
		status := mintStatus(err)
		if status == http.StatusInternalServerError {
			// Signing/marshalling faults: log the detail, tell the caller nothing.
			log.Error(err, "capability mint failed")
			http.Error(w, http.StatusText(status), status)
			return
		}
		// Refusals are the caller's to act on, so the reason travels — the same
		// text the MCP surface puts in its isError result.
		http.Error(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		// The capability is already minted and the status is already sent; all
		// that is left is to say the response body was truncated.
		log.Error(err, "capability mint: failed to encode response")
	}
}

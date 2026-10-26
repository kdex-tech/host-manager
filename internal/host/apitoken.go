package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// revokeTTLDescription is the OpenAPI description of RevokeRequest.TTL. The
// revocation lifetime is built from apitoken.RevocationHorizon so the document
// cannot drift from the constant.
var revokeTTLDescription = fmt.Sprintf("Go duration that can lengthen a metadata revocation beyond its lifetime, max(%d years, the host's max_ttl); it never shortens one, and an unusable value is ignored. A revocation revokes the tokens issued up to it, so a key re-minted afterwards under the same name is valid.",
	apitoken.RevocationHorizon/(365*24*time.Hour))

// maxAPITokenRequestBytes caps API-token request bodies (mint, verify,
// revoke). These payloads are short metadata-only documents.
const maxAPITokenRequestBytes = 64 << 10

// The plain apitokens verbs (mint, revoke) act on the CALLER's own tokens.
// Acting on another subject's tokens takes one of these, scoped to the target
// subject (apitokens:<sub>:<verb>). They are distinct verbs so that the blanket
// self-service grant site charts bind to every authenticated subject --
// {resources: [apitokens], verbs: [mint, revoke]}, no resourceNames -- does not
// reach them; a role with verbs: [all] still does. GHSA-qp3j-f436-pggf.
const (
	// apitokenVerbImpersonate mints a token for another subject. The token
	// re-resolves THAT subject's roles on every request, so this is
	// impersonation, not a lesser key-management right.
	apitokenVerbImpersonate = "impersonate"
	// apitokenVerbRevokeAny revokes another subject's tokens.
	apitokenVerbRevokeAny = "revoke-any"
)

// A confidential client holding provisionedMintScope may mint API tokens for
// the subjects it provisioned. It is an opaque CLASS scope: it matches only by
// exact name, so no `all` verb or wildcard apitokens grant implies it, and it
// covers an open-ended, changing set of subjects that no instance grant
// (apitokens:<sub>:impersonate) can name. Which subjects is decided per mint
// by the target's provisionedByClaim, a claim only host-manager reads, so
// its name is fixed: the site's Lookup returns it, holding the provisioning
// client's id, for as long as the subject still belongs to that client.
// See kdex-tech/host-manager#237.
const (
	provisionedMintScope = "apitokens_impersonate_provisioned"
	provisionedByClaim   = "provisioned_by"
)

type MintRequest struct {
	// Action is the action of the tokens to mint (metadata-based revocation).
	Action string `json:"act"`
	// Audience is the audience of the tokens to mint (metadata-based revocation).
	Audience string `json:"aud"`
	// Scope is the scope of the tokens to mint (metadata-based revocation).
	Scope string `json:"scp"`
	// Sub is the subject of the tokens to mint (metadata-based revocation).
	Sub string `json:"sub"`
	// TTL is the token lifetime, a Go duration. Absent: 24h, capped at the
	// host's maxTTL. Unparseable, non-positive or above maxTTL: refused (400).
	TTL string `json:"ttl"`
}

type MintResponse struct {
	Token string `json:"token"`
}

type VerifyRequest struct {
	Token string `json:"token"`
}

// revokeAllField is RevokeRequest.All's JSON name, for the OpenAPI schema.
const revokeAllField = "all"

// RevokeRequest is the request body for the token revocation endpoint.
type RevokeRequest struct {
	// Action is the action of the tokens to revoke (metadata-based revocation).
	Action string `json:"act"`
	// All revokes Sub on this host as of now: every API token issued for it
	// on any audience, whatever its act, including keys nobody recorded, and
	// every credential that authenticated before it can no longer mint
	// another. It takes sub and nothing else. See kdex-tech/host-manager#257.
	All bool `json:"all"`
	// Audience is the audience of the tokens to revoke (metadata-based revocation).
	Audience string `json:"aud"`
	// Sub is the subject of the tokens to revoke (metadata-based revocation).
	Sub string `json:"sub"`
	// TTL lengthens a metadata revocation beyond its lifetime,
	// max(apitoken.RevocationHorizon, maxTTL) (TokenManager.RevocationTTL);
	// it can never shorten one. An unusable value is ignored.
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
// It allows users to revoke their own tokens, and callers holding
// apitokens:<target>:revoke-any to revoke another subject's tokens.
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
	if req.All {
		// An aud would read as "this audience only", which all is not.
		if req.Sub == "" || req.Audience != "" || req.Action != "" || req.Token != "" {
			log.V(1).Info("revoke-all refused: it takes sub only")
			http.Error(w, "all takes sub, and none of aud, act or token: it revokes every audience", http.StatusBadRequest)
			return
		}
		targetSub = req.Sub
	} else if req.Token != "" {
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
		// Keyed on the TARGET subject. It was keyed on requestingSub, so a
		// grant scoped to the caller's own name -- or the blanket
		// self-service revoke grant -- revoked anyone's tokens.
		requirement := kdexv1alpha1.SecurityRequirement{
			"bearer": []string{"apitokens:" + apitokenVerbRevokeAny},
		}

		authorized, err := hh.authChecker.CheckAccess(
			r.Context(),
			"apitokens",
			targetSub,
			[]kdexv1alpha1.SecurityRequirement{requirement},
			apitokenVerbRevokeAny,
		)
		if err != nil || !authorized {
			// The V(1) is right for the POLICY case: an under-entitled
			// caller is expected traffic, not a fault (#181). It is wrong
			// for the ERROR case -- a checker outage at an auth gate would
			// otherwise leave no V(0) trace and render silently as a policy
			// 403. Same split the function proxy makes.
			if err != nil {
				log.Error(err, "revoke authorization check failed",
					"subject", requestingSub, "target", targetSub)
			} else {
				log.V(1).Info("revoke denied: caller may not revoke for another subject",
					"subject", requestingSub, "target", targetSub)
			}
			// Derived once, on the denial path only. This gate runs through
			// CheckAccess, which parses its own copy internally, so there is
			// nothing in scope to hand Classify.
			denial.Write(w, r, denial.Opts{
				Outcome: denial.Classify(
					r.Context(), hh.authChecker,
					hh.authChecker.GetParsedEntitlements(r.Context()),
					"apitokens", targetSub, apitokenVerbRevokeAny),
				// Locked: hh.mu.RLock is held from above.
				Issuer: hh.issuerAddressLocked(),
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
		// The TokenManager raises any ttl to its revocation lifetime, so a
		// caller can lengthen a revocation but never shorten one. An unusable
		// ttl could only have lengthened it, so it is ignored rather than
		// allowed to fail a security action.
		var ttl time.Duration
		if req.TTL != "" {
			if parsed, err := time.ParseDuration(req.TTL); err == nil && parsed > 0 {
				ttl = parsed
			} else {
				log.V(1).Info("ignoring an unusable revocation ttl", "ttl", req.TTL)
			}
		}

		var err error
		if req.All {
			err = hh.authConfig.TokenManager.RevokeSubject(r.Context(), req.Sub, ttl)
		} else {
			err = hh.authConfig.TokenManager.RevokeByMetadata(r.Context(), req.Audience, req.Sub, req.Action, ttl)
		}
		if err != nil {
			log.Error(err, "Failed to revoke tokens by metadata", "all", req.All)
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

// provisionedVerdict is the outcome of the provisioned-subject check.
type provisionedVerdict int

const (
	// notProvisioned: the caller does not qualify, or the Lookup does not
	// attribute the subject to it.
	notProvisioned provisionedVerdict = iota
	// provisionedByCaller: the Lookup attributes the subject to the caller.
	provisionedByCaller
	// provisionedUnknown: the caller qualifies, but the Lookup was unavailable.
	provisionedUnknown
)

// checkProvisioned decides whether caller may mint for target under
// provisionedMintScope.
//   - The caller must be a configured client authenticating as itself with
//     client_credentials. Because #243 refuses every user identity named
//     like a client, no user session can pass, even one holding the scope.
//   - The target must not itself name a client, or the token would carry that
//     client's KDexRoleBindings (the PAT paths resolve roles by sub, #243).
//   - Ownership is the target's provisionedByClaim, resolved live so that
//     claiming the account ends the client's right on the next mint.
//
// Callers must not hold hh.mu: it is taken here only to read the checker and
// the exchanger, never across the Lookup. See kdex-tech/host-manager#237.
func (hh *HostHandler) checkProvisioned(ctx context.Context, ac auth.AuthContext, caller, target string) provisionedVerdict {
	if client, ok := ac.ClientCredentialsSubject(); !ok || client != caller {
		return notProvisioned
	}

	hh.mu.RLock()
	holds := hh.authChecker.HoldsScope(ctx, provisionedMintScope)
	exchanger := hh.authExchanger
	hh.mu.RUnlock()
	if !holds || !exchanger.IsConfiguredClient(caller) || exchanger.NamesClient(target) {
		return notProvisioned
	}

	claims, err := exchanger.ResolveSubjectClaimsLive(target)
	if err != nil {
		logf.FromContext(ctx).Error(err, "could not resolve a subject's provisioning",
			"client", caller, "subject", target)
		return provisionedUnknown
	}
	if provisionedBy, _ := claims[provisionedByClaim].(string); provisionedBy == caller {
		return provisionedByCaller
	}
	return notProvisioned
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

	doc := map[string]any{
		"keys": keys,
	}
	// Published so a client can choose a valid mint ttl without guessing
	// (host-manager#238). Absent when mint lifetimes are unbounded.
	if maxTTL := hh.authConfig.TokenManager.MaxTTL(); maxTTL > 0 {
		doc["max_ttl"] = maxTTL.String()
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(doc)
	if err != nil {
		log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// apitokenMintHandler mints a stateless API token. A caller holding
// apitokens:<self>:mint mints for itself; minting for another subject takes
// apitokens:<sub>:impersonate, or, for a configured client minting for a
// subject its Lookup attributes to it, provisionedMintScope (checkProvisioned).
func (hh *HostHandler) apitokenMintHandler(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	if r.Method != http.MethodPost {
		log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// With no authenticated subject there is no "self" to mint for, whatever
	// anonymousEntitlements grant -- the same two checks revoke makes.
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

	verb := "mint"
	if subject != requestingSub {
		verb = apitokenVerbImpersonate
	}
	requirement := kdexv1alpha1.SecurityRequirement{
		"bearer": []string{"apitokens:" + verb},
	}

	hh.mu.RLock()
	authorized, err := hh.authChecker.CheckAccess(
		r.Context(),
		"apitokens",
		subject,
		[]kdexv1alpha1.SecurityRequirement{requirement},
		verb,
	)
	hh.mu.RUnlock()

	// Only a denied impersonation consults the provisioned path. Its Lookup is
	// live network I/O, so it runs with hh.mu released: under the read lock a
	// pending host reconfiguration would stall every other reader.
	if err == nil && !authorized && verb == apitokenVerbImpersonate {
		switch hh.checkProvisioned(r.Context(), ac, requestingSub, subject) {
		case provisionedByCaller:
			authorized = true
			log.Info("minting an API token for a provisioned subject",
				"client", requestingSub, "subject", subject, "scope", provisionedMintScope)
		case provisionedUnknown:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "the subject's provisioning could not be checked", http.StatusServiceUnavailable)
			return
		case notProvisioned:
		}
	}

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if err != nil || !authorized {
		// V(1) for the policy denial (#181), Error for a checker failure --
		// see the same split in apitokenRevokeHandler above.
		if err != nil {
			log.Error(err, "mint authorization check failed",
				"subject", requestingSub, "target", subject, "verb", verb)
		} else {
			log.V(1).Info("mint denied",
				"subject", requestingSub, "target", subject, "verb", verb)
		}
		// Derived once, on the denial path only -- see the same shape in
		// apitokenRevokeHandler above.
		denial.Write(w, r, denial.Opts{
			Outcome: denial.Classify(
				r.Context(), hh.authChecker,
				hh.authChecker.GetParsedEntitlements(r.Context()),
				"apitokens", subject, verb),
			// Locked: hh.mu.RLock is held from above.
			Issuer: hh.issuerAddressLocked(),
		})
		return
	}

	if hh.authConfig.TokenManager == nil {
		log.Error(nil, "Token manager not configured")
		http.Error(w, "Token manager not configured", http.StatusNotImplemented)
		return
	}

	// A subject revoked on this host (revoke with all) cannot mint itself a
	// key with a credential that authenticated before the revocation: a live
	// session would otherwise outlast the cutoff and hand its keys to a
	// re-signup. Minting for another subject is that principal's own act and
	// is decided above. kdex-tech/host-manager#257.
	if subject == requestingSub {
		if refused, status := hh.mintFromRevokedCredential(r.Context(), ac, subject); refused {
			log.V(1).Info("mint refused: the subject was revoked after this credential authenticated", "subject", subject)
			http.Error(w, http.StatusText(status), status)
			return
		}
	}

	// An absent ttl defaults to 24h, capped at the host's maximum. A ttl that
	// is unreadable, non-positive, or above the maximum is refused rather than
	// replaced, so the caller never holds a token that expires sooner than it
	// asked for (host-manager#238).
	ttl := hh.authConfig.TokenManager.CapTTL(24 * time.Hour)
	if req.TTL != "" {
		if ttl, err = time.ParseDuration(req.TTL); err != nil || ttl <= 0 {
			log.V(1).Info("mint refused: unusable ttl", "subject", requestingSub, "ttl", req.TTL)
			http.Error(w, "ttl must be a positive Go duration such as 2160h", http.StatusBadRequest)
			return
		}
	}

	token, err := hh.authConfig.TokenManager.MintStatelessKey(audience, subject, req.Action, req.Scope, ttl)
	if errors.Is(err, apitoken.ErrTTLExceedsMax) {
		log.V(1).Info("mint refused: ttl above the host maximum", "subject", requestingSub, "target", subject, "error", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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

// mintFromRevokedCredential reports whether ac authenticated subject at or
// before subject's revocation, and the status to refuse with. A credential
// with no issue time counts as authenticated before it. A revocation store
// that cannot be read refuses with 503 rather than minting. Caller holds
// hh.mu.RLock.
func (hh *HostHandler) mintFromRevokedCredential(ctx context.Context, ac auth.AuthContext, subject string) (bool, int) {
	issuedAt := time.Time{}
	if iat, err := ac.GetIssuedAt(); err == nil && iat != nil {
		issuedAt = iat.Time
	}
	revoked, err := hh.authConfig.TokenManager.SubjectRevokedSince(ctx, subject, issuedAt)
	if err != nil {
		logf.FromContext(ctx).Error(err, "could not check the subject's revocation", "subject", subject)
		return true, http.StatusServiceUnavailable
	}
	if revoked {
		return true, http.StatusForbidden
	}
	return false, 0
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
											"max_ttl": &openapi.SchemaRef{Value: &openapi.Schema{
												Description: "The longest ttl /-/apitokens/mint accepts, as a Go duration. Absent when mint lifetimes are unbounded.",
												Type:        &openapi.Types{openapi.TypeString},
											}},
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
													"ttl": &openapi.SchemaRef{Value: &openapi.Schema{
														Description: "Token lifetime as a Go duration. Defaults to 24h, capped at the host's max_ttl (see /.well-known/pks.json). A ttl that is unparseable (Go has no day unit: send 2160h, not 90d), not positive, or above max_ttl is refused with 400.",
														Type:        &openapi.Types{openapi.TypeString},
													}},
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
							openapi.WithStatus(503, &openapi.ResponseRef{
								Value: &openapi.Response{
									Description: new("The Lookup that attributes a provisioned subject is unavailable; retry after Retry-After."),
								},
							}),
						),
						// Alternatives: mint for yourself, impersonate to mint
						// for another subject, or mint as a client for a
						// subject it provisioned.
						Security: &openapi.SecurityRequirements{
							openapi.SecurityRequirement{
								"bearer": {"apitokens:mint"},
							},
							openapi.SecurityRequirement{
								"bearer": {"apitokens:" + apitokenVerbImpersonate},
							},
							// A client minting for a subject its Lookup
							// attributes to it (provisioned_by). See #237.
							openapi.SecurityRequirement{
								"bearer": {provisionedMintScope},
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
													"act": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													revokeAllField: &openapi.SchemaRef{Value: &openapi.Schema{
														Description: "Revoke sub on this host as of now: every API token issued for it on any audience, whatever its act, including keys that were never recorded; a refresh token or session that authenticated before it can no longer mint or refresh. Takes sub only. A credential from a later authentication (a re-signup) is valid. Authorized like a metadata revoke: your own subject, or apitokens:<sub>:revoke-any. Enforced by host-manager v0.28.0 or later; a replica on an earlier version ignores it.",
														Type:        &openapi.Types{openapi.TypeBoolean},
													}},
													"aud":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"sub":   &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"token": &openapi.SchemaRef{Value: &openapi.Schema{Type: &openapi.Types{openapi.TypeString}}},
													"ttl": &openapi.SchemaRef{Value: &openapi.Schema{
														Description: revokeTTLDescription,
														Type:        &openapi.Types{openapi.TypeString},
													}},
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
						// Alternatives: revoke your own tokens, or
						// revoke-any for another subject's.
						Security: &openapi.SecurityRequirements{
							openapi.SecurityRequirement{
								"bearer": {"apitokens:revoke"},
							},
							openapi.SecurityRequirement{
								"bearer": {"apitokens:" + apitokenVerbRevokeAny},
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

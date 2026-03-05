package host

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	ko "github.com/kdex-tech/host-manager/internal/openapi"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
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
	if r.Method != http.MethodGet {
		hh.log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		hh.log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokenMintHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		hh.log.Error(nil, "Method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		hh.log.Error(err, "Failed to decode request body")
		http.Error(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	audience := req.Audience
	if audience == "" {
		hh.log.Error(nil, "aud is required")
		http.Error(w, "aud is required", http.StatusBadRequest)
		return
	}

	subject := req.Sub
	if subject == "" {
		hh.log.Error(nil, "sub is required")
		http.Error(w, "sub is required", http.StatusBadRequest)
		return
	}

	// TODO: entitlements should always URL encode the <resourceName> to protect from random colon ':' in the contents.
	urlEncodedSubject := url.PathEscape(subject)

	// 1. Check Entitlement
	requirement := kdexv1alpha1.SecurityRequirement{
		"bearer": []string{"apitokens:" + urlEncodedSubject + ":mint"},
	}

	authorized, err := hh.authChecker.CheckAccess(r.Context(), "tokens", "mint", []kdexv1alpha1.SecurityRequirement{requirement})
	if err != nil || !authorized {
		hh.log.Error(err, "Failed to check access")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	ttl, err := time.ParseDuration(req.TTL)
	if err != nil {
		ttl = 24 * time.Hour // Default
	}

	if hh.authConfig.TokenManager == nil {
		hh.log.Error(nil, "Token manager not configured")
		http.Error(w, "Token manager not configured", http.StatusNotImplemented)
		return
	}

	token, err := hh.authConfig.TokenManager.MintStatelessKey(audience, subject, req.Action, req.Scope, ttl)
	if err != nil {
		hh.log.Error(err, "Failed to mint token")
		http.Error(w, "Failed to mint token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(MintResponse{Token: token})
	if err != nil {
		hh.log.Error(err, "Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (hh *HostHandler) apitokenVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		hh.serveError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		hh.serveError(w, r, http.StatusBadRequest, "Invalid request body")
		return
	}

	if hh.authConfig.TokenManager == nil {
		hh.serveError(w, r, http.StatusNotImplemented, "Token manager not configured")
		return
	}

	tokenString := req.Token
	if after, ok := strings.CutPrefix(tokenString, "Bearer "); ok {
		tokenString = after
	}

	data, err := hh.authConfig.TokenManager.ValidateToken(tokenString)
	if err != nil {
		hh.log.Error(err, "Token verification failed")
		hh.serveError(w, r, http.StatusUnauthorized, "Invalid token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		hh.log.Error(err, "Failed to encode response")
		hh.serveError(w, r, http.StatusInternalServerError, "Failed to encode response")
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
				discoveryPath: {},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(mintPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: mintPath,
			Paths: map[string]ko.PathItem{
				mintPath: {},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)

	hh.registerPath(verifyPath, ko.PathInfo{
		API: ko.OpenAPI{
			BasePath: verifyPath,
			Paths: map[string]ko.PathItem{
				verifyPath: {},
			},
		},
		Type: ko.SystemPathType,
	}, registeredPaths)
}

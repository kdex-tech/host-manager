package host

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

const schemeHTTPS = "https"

type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

func (hh *HostHandler) registerHandler(mux *http.ServeMux, _ map[string]ko.PathInfo) {
	if hh.authConfig == nil || !hh.authConfig.DCR.Enabled || hh.authConfig.DCRStore == nil {
		return // DCR off: endpoint absent → 404, anti-enum preserved
	}
	mux.HandleFunc("POST /-/oauth/register", hh.oauthRegisterHandler)
}

func (hh *HostHandler) oauthRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !redirectAllowed(u, hh.authConfig.DCR.AllowedRedirectSchemes) {
			writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri scheme not allowed: "+u)
			return
		}
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	// maxClients soft cap: enforcement deferred — no atomic Incr primitive
	// exposed by cache.Cache; TTL bounds growth in the meantime.
	client, err := hh.authConfig.DCRStore.Register(r.Context(), dcr.Client{
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grants,
		ResponseTypes:           []string{"code"},
		Scope:                   req.Scope,
		ClientName:              req.ClientName,
		TokenEndpointAuthMethod: "none", // forced public
	})
	if err != nil {
		writeRegisterError(w, http.StatusInternalServerError, "server_error", "could not persist client")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(client)
}

func redirectAllowed(raw string, schemes []string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, s := range schemes {
		switch s {
		case schemeHTTPS:
			if u.Scheme == schemeHTTPS {
				return true
			}
		case "http-loopback":
			if u.Scheme == "http" {
				host := u.Hostname()
				if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
					return true
				}
			}
		}
	}
	return false
}

func writeRegisterError(w http.ResponseWriter, code int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": desc})
}

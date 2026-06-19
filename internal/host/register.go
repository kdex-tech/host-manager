package host

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
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
	// Construct the abuse-guardrail limiter exactly once per HostHandler.
	// registerHandler is invoked on every RebuildMux, so we must not reset
	// the token buckets on each call (that would defeat the global cap).
	hh.registerLimiterOnce.Do(func() {
		if hh.registerLimiter == nil {
			hh.registerLimiter = newRegisterLimiter(hh.authConfig.DCR.MaxClients)
		}
	})
	mux.HandleFunc("POST /-/oauth/register", hh.oauthRegisterHandler)
}

func (hh *HostHandler) oauthRegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Abuse guardrails (RFC 7591 open registration). The GLOBAL limiter is
	// the authoritative, non-spoofable guard; the per-IP limiter is
	// best-effort defense-in-depth (its key is derived from spoofable
	// headers — see clientIP / register_limiter.go).
	if rl := hh.registerLimiter; rl != nil {
		// Best-effort per-IP check first so an abusive single source is
		// throttled without consuming the shared global budget.
		if !rl.allowIP(clientIP(r)) {
			writeRegisterRateLimited(w, perIPRetryAfterSeconds)
			return
		}
		if !rl.allowGlobal() {
			writeRegisterRateLimited(w, globalRetryAfterSeconds)
			return
		}
	}

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
	// maxClients (DCR.MaxClients) is enforced as the GLOBAL limiter's burst
	// size (see newRegisterLimiter): it bounds registrations admitted per
	// burst window, NOT the count of simultaneously live clients. A true
	// live cap needs a cache SCAN/atomic-decrement primitive cache.Cache
	// does not provide; a create-only counter would overcount expiring
	// clients and could permanently wedge registration. The refilling token
	// bucket has no permanent-lockout path. TTL continues to bound growth.
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

// writeRegisterRateLimited emits an RFC 7591-shaped error with HTTP 429 and
// an advisory Retry-After header (seconds).
func writeRegisterRateLimited(w http.ResponseWriter, retryAfterSeconds int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	writeRegisterError(w, http.StatusTooManyRequests, "temporarily_unavailable",
		"registration rate limit exceeded; retry later")
}

func writeRegisterError(w http.ResponseWriter, code int, errCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": desc})
}

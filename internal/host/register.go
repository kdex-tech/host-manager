package host

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

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
	// Filter, don't fail. A native client (e.g. Cursor) registers several
	// redirect_uris at once — a loopback URI alongside a custom-scheme one —
	// expecting the AS to keep whichever it supports. RFC 7591 §3.2.1 lets the
	// server return an adjusted redirect_uris set, so keep the allowed subset
	// and pin only that; reject the whole request only when NONE is allowed,
	// rather than letting one unsupported scheme sink an otherwise-valid
	// registration.
	allowedRedirects := dcr.FilterRedirectURIs(req.RedirectURIs, hh.authConfig.DCR.AllowedRedirectSchemes)
	if len(allowedRedirects) == 0 {
		writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "no redirect_uri with an allowed scheme")
		return
	}
	// Dynamic Client Registration is UNAUTHENTICATED and forces
	// token_endpoint_auth_method="none" below, so everything it issues is a
	// credential-less PUBLIC client that any party can mint and freely re-mint
	// under a fresh client_id. The grant_types it hands out therefore cannot be
	// whatever the caller asked for.
	//
	// Honoring a client-supplied `password` produced an unauthenticated,
	// unattributable password-guessing surface: valid credentials were still
	// required, so this was never an auth bypass, but free client_id rotation
	// defeats per-client throttling and leaves no accountability. The password
	// grant is removed in OAuth 2.1 and discouraged by RFC 9700 §2.4.
	// client_credentials is excluded for a different reason: a forced-public
	// client holds no secret, so it has nothing to authenticate with.
	//
	// Restricting to the redirect-based pair costs the flow DCR exists for
	// nothing -- zero-touch MCP-client onboarding uses authorization_code
	// throughout. See GHSA-hm9g-w2cw-j7gg.
	//
	// Filter rather than fail, matching the redirect_uris handling above
	// (RFC 7591 §3.2.1 lets the server return adjusted metadata): a client
	// asking for a supported grant alongside an unsupported one still gets
	// registered for what it can actually use. Omitting grant_types gets the
	// default pair.
	grants := dcr.FilterGrantTypes(req.GrantTypes)
	if len(grants) == 0 {
		// Nothing survived. Registering it anyway would hand back a working
		// client for a grant the caller never asked for, so say no instead.
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata",
			"grant_types must include at least one of: "+strings.Join(dcr.SupportedGrantTypes, ", "))
		return
	}
	// maxClients (DCR.MaxClients) is enforced as the GLOBAL limiter's burst
	// size (see newRegisterLimiter): it bounds registrations admitted per
	// burst window, NOT the count of simultaneously live clients. A true
	// live cap needs a cache SCAN/atomic-decrement primitive cache.Cache
	// does not provide; a create-only counter would overcount expiring
	// clients and could permanently wedge registration. The refilling token
	// bucket has no permanent-lockout path. TTL continues to bound growth.
	client, err := hh.authConfig.DCRStore.Register(r.Context(), dcr.Client{
		RedirectURIs:            allowedRedirects,
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

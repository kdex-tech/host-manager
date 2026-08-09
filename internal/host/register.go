package host

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
)

const (
	schemeHTTP             = "http"
	schemeHTTPS            = "https"
	schemeConfigLoopback   = "http-loopback"
	schemeConfigPrivateUse = "private-use"
)

// dcrSupportedGrantTypes is the complete set a DYNAMICALLY REGISTERED client
// may hold. It is deliberately narrower than the authorization server's own
// grant_types_supported: those are available to statically configured clients,
// which an operator authored and can be held accountable for, whereas a DCR
// client is anonymous, credential-less and freely re-mintable.
//
// Keep this a redirect-based pair. Adding a grant that authenticates without a
// redirect (password, client_credentials) hands an unauthenticated caller a
// working credential-testing client. See GHSA-hm9g-w2cw-j7gg.
var dcrSupportedGrantTypes = []string{"authorization_code", "refresh_token"}

// filterDCRGrantTypes keeps only the requested grants a DCR client may hold,
// preserving the caller's order and dropping duplicates. Returns an empty slice
// when nothing requested is supported, which the caller treats as a rejection
// rather than silently substituting the default set.
func filterDCRGrantTypes(requested []string) []string {
	kept := make([]string, 0, len(requested))
	for _, g := range requested {
		if slices.Contains(dcrSupportedGrantTypes, g) && !slices.Contains(kept, g) {
			kept = append(kept, g)
		}
	}
	return kept
}

// dangerousSchemes are never honored as a freeform literal redirect scheme even
// when explicitly listed in allowedRedirectSchemes: they are code-execution /
// local-file / data-exfil vectors, not redirect targets.
var dangerousSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"file":       true,
	"vbscript":   true,
	"blob":       true,
}

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
	allowedRedirects := make([]string, 0, len(req.RedirectURIs))
	for _, u := range req.RedirectURIs {
		if redirectAllowed(u, hh.authConfig.DCR.AllowedRedirectSchemes) {
			allowedRedirects = append(allowedRedirects, u)
		}
	}
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
	grants := slices.Clone(dcrSupportedGrantTypes)
	if len(req.GrantTypes) > 0 {
		// Filter rather than fail, matching the redirect_uris handling above
		// (RFC 7591 §3.2.1 lets the server return adjusted metadata): a client
		// asking for a supported grant alongside an unsupported one still gets
		// registered for what it can actually use.
		grants = filterDCRGrantTypes(req.GrantTypes)
		if len(grants) == 0 {
			// Nothing survived. Registering it anyway would hand back a working
			// client for a grant the caller never asked for, so say no instead.
			writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata",
				"grant_types must include at least one of: authorization_code, refresh_token")
			return
		}
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

// redirectAllowed reports whether a redirect_uri is permitted by the host's
// allowedRedirectSchemes. Two entries are named POLICIES that constrain the
// URL's structure, not just its scheme; every other entry is a deterministic
// literal — the entry IS the URI scheme, so listing "cursor" permits cursor://…
// (Cursor's native callback), "vscode" permits vscode://…, and so on, with no
// per-scheme code.
//
//   - "http-loopback": scheme http, but only to a loopback host (RFC 8252 §7.3).
//   - "private-use":   any non-http(s) reverse-DNS/dotted scheme (RFC 8252 §7.1
//     SHOULD — reduces scheme-squatting; a bare single-label scheme is rejected
//     under this policy but can still be opted into as an explicit literal).
//   - anything else:   literal scheme match (u.Scheme == entry).
//
// Two guardrails apply to the literal path regardless of what is listed: a bare
// "http" literal is never honored (cleartext + non-loopback == open redirect;
// use "http-loopback"), and dangerousSchemes (javascript/data/file/…) are never
// honored. DCR clients are forced public + PKCE with an exact-matched
// redirect_uri at /authorize, so a permitted custom scheme cannot yield a
// usable intercepted code.
func redirectAllowed(raw string, schemes []string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for _, s := range schemes {
		switch s {
		case schemeConfigLoopback:
			if u.Scheme == schemeHTTP {
				host := u.Hostname()
				if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
					return true
				}
			}
		case schemeConfigPrivateUse:
			if u.Scheme != "" && u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS &&
				strings.Contains(u.Scheme, ".") {
				return true
			}
		default:
			// Deterministic literal: the config entry is the URI scheme.
			// Never honor an empty scheme, a bare "http" literal, or a
			// dangerous scheme even if explicitly listed.
			if s == "" || s == schemeHTTP || dangerousSchemes[s] {
				continue
			}
			if u.Scheme == s {
				return true
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

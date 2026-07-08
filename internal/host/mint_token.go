package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
)

// ctxKey namespaces context values set by the mint_token interception so
// they can't collide with other packages' context keys.
type ctxKey int

// mintTokenListDiscoveryURLKey marks a request context as carrying a tools/list
// call on a mint-token-enabled function, so ModifyResponse knows to splice the
// mint_token descriptor into the (already-forwarded) response body. Its value
// is the caller-facing /-/openapi discovery URL (possibly "" when the runtime
// address is unknown) resolved from the inbound request — the presence of the
// key, not the value, is the marker. See kdex-tech/host-manager#133.
const mintTokenListDiscoveryURLKey ctxKey = iota

// stringSliceFromClaim coerces an entitlements claim (which arrives as
// []any after JSON round-trips, or []string when set in-process) to []string.
func stringSliceFromClaim(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// MintTokenRequest is the argument shape of the mint_token MCP tool.
type MintTokenRequest struct {
	Entitlements []string `json:"entitlements"`
	TTLSeconds   int      `json:"ttl_seconds,omitempty"`
	Uses         int      `json:"uses,omitempty"`
}

// MintTokenResult is the mint_token success payload.
type MintTokenResult struct {
	Token         string   `json:"token"`
	ExpiresAt     int64    `json:"expires_at"`
	Entitlements  []string `json:"entitlements"`
	UsesRemaining int      `json:"uses_remaining"`
}

// hasDestructiveVerb reports whether any requested entitlement's verb is in the
// configured destructive set.
func hasDestructiveVerb(requested, destructive []string) bool {
	for _, e := range requested {
		parts := strings.Split(e, ":")
		verb := parts[len(parts)-1]
		// A wildcard/"all" verb encompasses every verb — including the
		// destructive ones — so it must trigger the destructive forcing too.
		if verb == "*" || verb == "all" {
			return true
		}
		for _, d := range destructive {
			if verb == d {
				return true
			}
		}
	}
	return false
}

// mintCapabilityToken verifies requested ⊆ held (directional attenuation),
// clamps ttl/uses to the host policy, and signs a short-lived HOST-AUDIENCE
// JWT whose entitlements claim is exactly the requested (attenuated) set. The
// caller (interception layer) supplies sub + held from the request auth context.
//
// Phase 1: the token is a stateless windowed JWT. `Uses` is clamped and
// reflected in UsesRemaining but no counter is provisioned yet (Phase 2 adds
// the jti-keyed Valkey counter and the middleware decrement). The
// auth.CapUsesClaim marker is always set so Phase 2 activates without
// re-minting semantics.
func (hh *HostHandler) mintCapabilityToken(ctx context.Context, sub string, held []string, req MintTokenRequest) (MintTokenResult, error) {
	cfg := hh.authConfig
	if cfg == nil || !cfg.MintTokenEnabled {
		return MintTokenResult{}, fmt.Errorf("mint_token is not enabled on this host")
	}
	if sub == "" {
		return MintTokenResult{}, fmt.Errorf("mint_token requires an authenticated caller")
	}
	if len(req.Entitlements) == 0 {
		return MintTokenResult{}, fmt.Errorf("mint_token requires at least one entitlement")
	}

	// Attenuation: every requested entitlement must be dominated by the held set.
	if offender, ok := entitlements.VerifyAttenuation(held, req.Entitlements); !ok {
		return MintTokenResult{}, fmt.Errorf("entitlement not held by caller: %s", offender)
	}

	// Clamp ttl.
	ttl := cfg.MintTokenTTLCap
	if req.TTLSeconds > 0 {
		reqTTL := time.Duration(req.TTLSeconds) * time.Second
		if reqTTL < ttl {
			ttl = reqTTL
		}
	}

	// Clamp uses; destructive verbs force single-use + shortest ttl.
	uses := req.Uses
	if uses <= 0 {
		uses = 1
	}
	if uses > cfg.MintTokenUsesCap {
		uses = cfg.MintTokenUsesCap
	}
	if hasDestructiveVerb(req.Entitlements, cfg.MintTokenDestructiveVerbs) {
		uses = 1
		if ttl > 10*time.Second {
			ttl = 10 * time.Second
		}
	}

	signer, err := sign.NewSigner(cfg.Audience, ttl, cfg.Issuer, &cfg.ActivePair.Private, cfg.ActivePair.KeyId, nil)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint signer: %w", err)
	}

	// signer.Project runs the claim allowlist (which passes "entitlements" and
	// "sub" but NOT auth.CapUsesClaim). Inject the capability marker into the
	// PROJECTED claims so it survives into the signed token — SignProjected
	// gives the projection the last word. (signer.Sign would drop auth.CapUsesClaim.)
	projected, err := signer.Project(jwt.MapClaims{
		"sub":          sub,
		"entitlements": req.Entitlements,
	})
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint project: %w", err)
	}
	projected[auth.CapUsesClaim] = true
	token, err := signer.SignProjected(projected)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint sign: %w", err)
	}

	// Provision the bounded-use counter keyed by the token's jti.
	if hh.cacheManager != nil {
		parsed, _, perr := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if perr == nil {
			if mc, ok := parsed.Claims.(jwt.MapClaims); ok {
				if jti, ok := mc["jti"].(string); ok && jti != "" {
					capCache := hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
					_ = capCache.Set(ctx, "uses:"+jti, strconv.Itoa(uses), cache.WithTTL(ttl))
				}
			}
		}
	}

	return MintTokenResult{
		Token:         token,
		ExpiresAt:     time.Now().Add(ttl).Unix(),
		Entitlements:  req.Entitlements,
		UsesRemaining: uses,
	}, nil
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// isMintTokenCall returns the request id, parsed arguments, and true when body
// is a single JSON-RPC tools/call for the mint_token tool. Batch (array) bodies
// and any other method/tool return matched=false (passthrough). MCP revision
// 2025-06-18 removed batching, so only the single-object shape is intercepted.
func isMintTokenCall(body []byte) (json.RawMessage, MintTokenRequest, bool) {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil, MintTokenRequest{}, false
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, MintTokenRequest{}, false
	}
	if req.Method != "tools/call" || req.Params.Name != "mint_token" {
		return nil, MintTokenRequest{}, false
	}
	var args MintTokenRequest
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return req.ID, MintTokenRequest{}, true // matched but bad args; handler emits error
		}
	}
	return req.ID, args, true
}

// mcpToolResult wraps a value as an MCP tools/call result (structuredContent +
// a text content block, per MCP tools/call response shape).
func mcpToolResult(v any) map[string]any {
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": mustJSON(v)}},
		"structuredContent": v,
		"isError":           false,
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// writeMintTokenRPC executes the mint and writes a JSON-RPC response. Attenuation
// / policy failures are returned as an MCP tool error result (isError=true) with
// HTTP 200, matching how MCP tools surface domain errors.
func (hh *HostHandler) writeMintTokenRPC(w http.ResponseWriter, id json.RawMessage, sub string, held []string, args MintTokenRequest) {
	w.Header().Set("Content-Type", "application/json")
	res, err := hh.mintCapabilityToken(context.Background(), sub, held, args)
	var payload jsonRPCResponse
	if err != nil {
		payload = jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		}}
	} else {
		payload = jsonRPCResponse{JSONRPC: "2.0", ID: id, Result: mcpToolResult(res)}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// mintTokenDescriptor is the MCP tools/list entry advertised for mint_token.
// When discoveryURL is non-empty it appends a note pointing at the runtime
// OpenAPI route catalog, so an agent can go mint -> read /-/openapi -> call the
// right route on the first try. An empty discoveryURL (unknown runtime address)
// falls back to the static description. See kdex-tech/host-manager#133.
func mintTokenDescriptor(discoveryURL string) map[string]any {
	description := "Mint a short-lived, attenuated capability token carrying a subset of your own entitlements, for off-context/credential-less use against the REST API. Returns { token, expires_at, entitlements, uses_remaining }; pass it as `Authorization: Bearer <token>`. Every entitlement you request must already be held by you — the mint attenuates, never escalates."
	if discoveryURL != "" {
		description += fmt.Sprintf(
			" To find the entitlements a call needs, open the OpenAPI spec at %s, locate the path + method you intend to call, and read its `security` block: each list entry is an alternative requirement (OR) — pick one scheme (e.g. bearer); the scope array inside that entry is the set of entitlements you must supply together (AND), so grant all of them. An entitlement's `<resourceName>` (middle) segment is interpreted by the target API and may require identity replacement — a wildcard or placeholder shown in the spec's scope must usually be resolved to the concrete resource the call targets before you request it (e.g. `functions:*:read` → `functions:/api/v1/files:read` for a specific route).",
			discoveryURL,
		)
	}
	return map[string]any{
		"name":        "mint_token",
		"description": description,
		"inputSchema": map[string]any{
			"type":     "object",
			"required": []string{"entitlements"},
			"properties": map[string]any{
				"entitlements": map[string]any{
					"type":        "array",
					"items":       map[string]any{"type": "string"},
					"description": "kdex-entitlements patterns (<resource>:<resourceName>:<verb>); each must be held by you.",
				},
				"ttl_seconds": map[string]any{"type": "integer", "description": "Requested lifetime; capped server-side."},
				"uses":        map[string]any{"type": "integer", "description": "Bounded use budget; capped server-side; destructive verbs force 1."},
			},
		},
	}
}

// isToolsListCall reports whether body is a single JSON-RPC tools/list request.
func isToolsListCall(body []byte) bool {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return req.Method == "tools/list"
}

// firstForwardedValue returns the first entry of a possibly comma-separated
// forwarded header value (e.g. "dev.knowdrive.ai, traefik.internal" -> the
// original caller's value), trimmed of surrounding whitespace.
func firstForwardedValue(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// fwdHost returns the caller-facing host, preferring X-Forwarded-Host (set by
// the GCE ingress / Traefik hop in front of host-manager) over the request's
// own Host, so the discovery URL names the external address rather than an
// internal :8090 one.
func fwdHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		return firstForwardedValue(xfh)
	}
	return r.Host
}

// fwdScheme returns the caller-facing scheme, preferring X-Forwarded-Proto,
// defaulting to https.
func fwdScheme(r *http.Request) string {
	if r != nil {
		if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
			return firstForwardedValue(xfp)
		}
	}
	return "https"
}

// openapiDiscoveryURL builds the caller-facing /-/openapi discovery URL from the
// forwarded request address, or "" when the host is unknown (defensive: callers
// fall back to the static mint_token description). See kdex-tech/host-manager#133.
func openapiDiscoveryURL(r *http.Request) string {
	host := fwdHost(r)
	if host == "" {
		return ""
	}
	return (&url.URL{Scheme: fwdScheme(r), Host: host, Path: "/-/openapi"}).String()
}

// spliceMintTokenDescriptor appends the mint_token descriptor to result.tools of
// a tools/list JSON-RPC response, embedding discoveryURL (the caller-facing
// /-/openapi endpoint, or "" for the static fallback) in its description.
// Returns (original, false) if the shape isn't a tools array (e.g. an SSE frame
// or an error response), so callers pass through.
func spliceMintTokenDescriptor(respBody []byte, discoveryURL string) ([]byte, bool) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return respBody, false
	}
	rawResult, ok := envelope["result"]
	if !ok {
		return respBody, false
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(rawResult, &result); err != nil {
		return respBody, false
	}
	rawTools, ok := result["tools"]
	if !ok {
		return respBody, false
	}
	var tools []json.RawMessage //nolint:prealloc // json.Unmarshal replaces the slice header wholesale; a preallocated cap is discarded
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return respBody, false
	}
	descBytes, err := json.Marshal(mintTokenDescriptor(discoveryURL))
	if err != nil {
		return respBody, false
	}
	tools = append(tools, descBytes)
	newTools, _ := json.Marshal(tools)
	result["tools"] = newTools
	newResult, _ := json.Marshal(result)
	envelope["result"] = newResult
	out, err := json.Marshal(envelope)
	if err != nil {
		return respBody, false
	}
	return out, true
}

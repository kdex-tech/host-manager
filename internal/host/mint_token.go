package host

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/sign"
)

// capUsesClaim marks a JWT as a bounded-use capability minted by mint_token.
// The inbound middleware decrements the jti-keyed use counter only for tokens
// carrying this claim; ordinary session/FAT tokens never carry it.
const capUsesClaim = "kdx_cap"

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
// the jti-keyed Valkey counter and the middleware decrement). The capUsesClaim
// marker is always set so Phase 2 activates without re-minting semantics.
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
	// "sub" but NOT capUsesClaim). Inject the capability marker into the
	// PROJECTED claims so it survives into the signed token — SignProjected
	// gives the projection the last word. (signer.Sign would drop capUsesClaim.)
	projected, err := signer.Project(jwt.MapClaims{
		"sub":          sub,
		"entitlements": req.Entitlements,
	})
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint project: %w", err)
	}
	projected[capUsesClaim] = true
	token, err := signer.SignProjected(projected)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint sign: %w", err)
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

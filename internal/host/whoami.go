package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
)

// WhoamiResult is the whoami success payload.
//
// It describes the authority the PRESENTED CREDENTIAL carries — not the person
// behind it. That distinction is the whole safety argument for exposing this
// tool: a minted capability token is attenuated on purpose, and re-resolving
// the subject's full entitlements here would disclose the shape of an authority
// the token was deliberately not granted.
//
// Every profile field is omitempty because they are genuinely optional on the
// wire: name, given_name, family_name and email are scope-controlled claim
// families (see Signer.confineByScope), so an OAuth2 caller whose token lacks
// `profile`/`email` does not carry them at all. Absent means "this credential
// does not carry it", which is information; an empty string would not be.
//
// Entitlements is NOT omitempty: an authenticated caller holding nothing must
// serialize as `[]` rather than being dropped, so a client can iterate without
// a nil check.
type WhoamiResult struct {
	Identity          string   `json:"identity,omitempty"`
	Name              string   `json:"name,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	FamilyName        string   `json:"family_name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Entitlements      []string `json:"entitlements"`
}

// whoamiFromAuthContext projects an auth context into the tool's result.
//
// Identity is the email claim. It falls back to `sub` when the credential
// carries no email — scope-gating means a perfectly valid caller may have
// none, and reporting the subject is more useful than reporting no identity at
// all. In this deployment the two are usually the same value.
func whoamiFromAuthContext(ac auth.AuthContext) (WhoamiResult, error) {
	sub, _ := ac["sub"].(string)
	if sub == "" {
		// Mirrors mintCapabilityToken: an anonymous caller gets an error rather
		// than an empty record that reads like a successful answer about nobody.
		return WhoamiResult{}, fmt.Errorf("whoami requires an authenticated caller")
	}

	identity, _ := ac["email"].(string)
	if identity == "" {
		identity = sub
	}

	ents := stringSliceFromClaim(ac["entitlements"])
	if ents == nil {
		ents = []string{}
	}

	name, _ := ac["name"].(string)
	givenName, _ := ac["given_name"].(string)
	familyName, _ := ac["family_name"].(string)
	preferredUsername, _ := ac["preferred_username"].(string)

	return WhoamiResult{
		Identity:          identity,
		Name:              name,
		GivenName:         givenName,
		FamilyName:        familyName,
		PreferredUsername: preferredUsername,
		Entitlements:      ents,
	}, nil
}

// isWhoamiCall returns the request id and true when body is a single JSON-RPC
// tools/call for whoami. Batch (array) bodies and any other method/tool return
// matched=false (passthrough), matching isMintTokenCall — MCP revision
// 2025-06-18 removed batching, so only the single-object shape is intercepted.
func isWhoamiCall(body []byte) (json.RawMessage, bool) {
	trimmed := strings.TrimLeft(string(body), " \t\r\n")
	if !strings.HasPrefix(trimmed, "{") {
		return nil, false
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, false
	}
	if req.Method != "tools/call" || req.Params.Name != "whoami" {
		return nil, false
	}
	return req.ID, true
}

// mergeResolvedClaims folds a subject's resolved backend claims onto the
// caller's auth context WITHOUT overwriting anything already there.
//
// The direction matters: a claim the presented credential actually carries is
// authoritative and must win, so the lookup only ever fills gaps. This mirrors
// the PAT bridge's own merge (#138).
func mergeResolvedClaims(ac auth.AuthContext, resolved jwt.MapClaims) auth.AuthContext {
	if len(resolved) == 0 {
		return ac
	}
	if ac == nil {
		ac = auth.AuthContext{}
	}
	for k, v := range resolved {
		if _, exists := ac[k]; !exists {
			ac[k] = v
		}
	}
	return ac
}

// writeWhoamiRPC answers the call locally and never forwards it upstream. An
// unauthenticated caller surfaces as an MCP tool error (isError=true) with HTTP
// 200, matching how writeMintTokenRPC surfaces domain errors.
//
// Profile fields are fleshed out from the NON-LOGIN Lookup before projecting:
// name/given_name/family_name/email are scope-controlled claim families, so a
// caller whose token lacks profile/email carries none of them and whoami would
// otherwise report a bare subject. Exchanger.ResolveSubjectClaims is the
// password-less resolution path for exactly this, and it sits behind the 60s
// subject-resolve cache, so repeated calls do not hit the backend.
//
// Entitlements are NOT re-resolved. They stay whatever the presented credential
// carries, which is what keeps an attenuated capability token reporting its
// reduced authority rather than the full authority of the user who minted it.
func (hh *HostHandler) writeWhoamiRPC(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")

	ac, _ := auth.GetAuthContext(r.Context())
	if sub, _ := ac["sub"].(string); sub != "" && hh.authExchanger != nil {
		ac = mergeResolvedClaims(ac, hh.authExchanger.ResolveSubjectClaims(sub))
	}
	res, err := whoamiFromAuthContext(ac)

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

// whoamiDescriptor is the MCP tools/list entry advertised for whoami. It takes
// no arguments: the answer is entirely a function of the presented credential,
// so there is nothing for a caller to pass.
func whoamiDescriptor() map[string]any {
	return map[string]any{
		"name": "whoami",
		"description": "Report who the server thinks you are and what your current credential lets " +
			"you do. Returns { identity, entitlements } plus whichever of name, given_name, " +
			"family_name and preferred_username are known for you. `identity` is your email, " +
			"falling back to the token subject. Profile fields are resolved from the identity " +
			"backend, so they are reported even when your token was not granted the profile/email " +
			"scopes. `entitlements` is what THIS credential holds, not what you hold generally — an " +
			"attenuated capability token reports its own reduced set, not the full authority of the " +
			"user who minted it. Takes no arguments. Use it to answer \"who am I and what may I do?\" " +
			"before a call fails, or to find out why one did.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}
}

package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
)

// toolNameWhoami is the MCP tool name the AS answers locally, kept in one
// place so the matcher and the advertised descriptor cannot drift apart.
const toolNameWhoami = "whoami"

// WhoamiResult is the whoami success payload.
//
// It describes what the USER can do. whoami is a reporting tool and hands out
// no authority by answering, so it reports effective entitlements rather than
// whatever the credential in hand happens to carry — see
// applyEffectiveEntitlements.
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

	// EntitlementsWithheld reports that the credential currently presented
	// carries FEWER entitlements than the user effectively holds, so some of
	// the entitlements listed here cannot be exercised with it. Set whenever
	// the two differ — including for a deliberately attenuated capability
	// token, where it is expected rather than a misconfiguration.
	EntitlementsWithheld bool `json:"entitlements_withheld,omitempty"`

	// Hint is a short actionable explanation, present only when something is
	// actionable.
	Hint string `json:"hint,omitempty"`
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

// applyEffectiveEntitlements reports the UNION of what the credential carries
// and what the user's role bindings resolve to, and flags the gap between them.
//
// whoami is a REPORTING tool. It grants nothing, so the question it answers is
// "what can I do", about the USER — not "what can this token do". Those come
// apart constantly and by design:
//
//   - A PASETO PAT bakes in no entitlements at all; it carries a single narrow
//     `scp` and the proxy bridge resolves the wide set at request time.
//   - A JWT whose client never requested scope=entitlements carries none,
//     because confineByScope deletes the claim at signing time.
//   - A minted capability token deliberately carries a subset.
//
// The attenuated case is NOT an exception. An attenuated token cannot EXERCISE
// the wider set, but narrowing the report would answer a question nobody asked
// and would make whoami useless for the caller most likely to need it.
//
// UNION, not replacement. The two inputs are different sets and NEITHER is a
// superset of the other:
//
//   - carried is the auth context, already through EnrichAuthContext on the
//     proxy path (proxy.go:547, ahead of this interception), so it includes
//     anything the host's claimMappings folded in — on the knowdrive dev host
//     that is `self.vs_entitlements`, the per-vector-store grants. mint_token
//     reads exactly this set as `held`.
//   - resolved is ResolveInternalRolesAndEntitlements: KDexRoleBinding grants
//     only, which never include those.
//
// Replacing carried with resolved dropped precisely the per-vector-store
// entitlements an agent needs and reported LESS than mint_token would accept.
//
// EntitlementsWithheld flags only resolved-minus-carried. A grant the
// credential carries but the role set does not is exercisable right now, so
// nothing is being withheld and warning about it would be noise.
//
// An empty resolved set is a resolution failure (no bindings, or a provider
// without the capability), never an answer: it leaves the carried set alone.
func applyEffectiveEntitlements(res WhoamiResult, resolved []string) WhoamiResult {
	if len(resolved) == 0 {
		return res
	}

	carried := make(map[string]struct{}, len(res.Entitlements))
	for _, e := range res.Entitlements {
		carried[e] = struct{}{}
	}

	// Carried first so the report leads with what is exercisable right now.
	effective := make([]string, 0, len(res.Entitlements)+len(resolved))
	effective = append(effective, res.Entitlements...)
	for _, e := range resolved {
		if _, ok := carried[e]; !ok {
			res.EntitlementsWithheld = true
			effective = append(effective, e)
		}
	}

	res.Entitlements = effective
	if res.EntitlementsWithheld {
		res.Hint = "These are the entitlements YOUR ACCOUNT holds. The credential you are " +
			"currently presenting carries fewer of them, so calls beyond what it carries will " +
			"be denied. For an OAuth2 client, request `scope=entitlements` when authorizing; " +
			"for a minted capability token, this is expected — it was attenuated on purpose."
	}
	return res
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
	if req.Method != "tools/call" || req.Params.Name != toolNameWhoami {
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
// Entitlements ARE resolved and unioned with what the credential carries — see
// applyEffectiveEntitlements for why the report is about the USER rather than
// about the token in hand, and why an attenuated capability token is not an
// exception to that.
func (hh *HostHandler) writeWhoamiRPC(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")

	ac, _ := auth.GetAuthContext(r.Context())
	if sub, _ := ac["sub"].(string); sub != "" && hh.authExchanger != nil {
		ac = mergeResolvedClaims(ac, hh.authExchanger.ResolveSubjectClaims(sub))
	}
	res, err := whoamiFromAuthContext(ac)
	if err == nil && hh.authExchanger != nil {
		// In-memory only: role bindings and the roles->entitlements table are
		// preloaded, so this is a map lookup plus a regex scan, not a backend
		// call. It is the same resolution the PAT bridge already performs per
		// request.
		sub, _ := ac["sub"].(string)
		_, effective, rerr := hh.authExchanger.ResolveInternalRolesAndEntitlements(sub)
		if rerr == nil {
			res = applyEffectiveEntitlements(res, effective)
		}
	}

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
		"name": toolNameWhoami,
		"description": "Report who you are and WHAT YOU ARE ENTITLED TO DO. Takes no " +
			"arguments. Returns { identity, entitlements } plus whichever of name, given_name, " +
			"family_name and preferred_username are known for you. `identity` is your email, " +
			"falling back to the token subject.\n\n" +
			"`entitlements` is what YOUR ACCOUNT holds — not what the credential you happen to be " +
			"presenting carries. Call this FIRST: without it there is no way to discover what you " +
			"may do, and the only alternative is to guess an entitlement set, pass it to " +
			"mint_token, and find out from the failure. Use it to plan a call, to pick the " +
			"entitlements to request from mint_token (every one must already be held by you), or " +
			"to explain why a call was denied.\n\n" +
			"If `entitlements_withheld` is true, the credential you are currently presenting " +
			"carries fewer entitlements than are listed, so some of these calls will be denied " +
			"with it; `hint` says what to do about that.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}
}

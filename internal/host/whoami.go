package host

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
// Identity and Entitlements are MANDATORY: whatever the scope, a caller must
// always learn who the server thinks they are and what they may do — that is
// the entire purpose of the tool. Identity falls back to the subject, which
// every credential carries, and an empty entitlement set serializes as `[]`
// rather than being dropped so a client can iterate without a nil check.
//
// The profile fields ARE omitempty, and that is the privacy contract: they are
// scope-controlled claim families (see Signer.confineByScope), so absent means
// "this credential was not granted it" — which is information an empty string
// would not convey.
type WhoamiResult struct {
	Identity          string   `json:"identity"`
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

// writeWhoamiRPC answers the call locally and never forwards it upstream. An
// unauthenticated caller surfaces as an MCP tool error (isError=true) with HTTP
// 200, matching how writeMintTokenRPC surfaces domain errors.
//
// Profile fields are reported ONLY as the presented credential carries them.
// name/given_name/family_name/email are scope-controlled claim families that
// confineByScope deletes at signing time when the client was not granted
// profile/email, so resolving them back from the identity backend would hand a
// third-party client personal data the user deliberately withheld when
// authorizing it — routing around the consent mechanism instead of honouring
// it.
//
// This costs PAT callers nothing: the proxy PAT bridge already merges
// ResolveSubjectClaims into the context it builds (proxy.go), so their profile
// arrives populated by the time this runs. Only a scope-limited OAuth2
// delegation is narrowed, which is the point.
//
// The exchanger is passed IN rather than read off the handler: hh.authExchanger
// is written under hh.mu by SetHost and read under RLock everywhere else, and
// this runs on the request goroutine. proxy.go already snapshots it under RLock
// in the closure that calls this, so taking it as a parameter removes an
// unguarded read that raced every host reconcile -- the torn-interface hazard
// #88 documents.
//
// Entitlements are DELIBERATELY exempt from that rule: they are the caller's own
// authority rather than personal data, and reporting them fully is the whole
// point of the tool. See applyEffectiveEntitlements.
func (hh *HostHandler) writeWhoamiRPC(w http.ResponseWriter, r *http.Request, id json.RawMessage, exchanger *auth.Exchanger) {
	w.Header().Set("Content-Type", "application/json")

	ac, _ := auth.GetAuthContext(r.Context())
	res, err := whoamiFromAuthContext(ac)
	if err == nil && exchanger != nil {
		// In-memory only: role bindings and the roles->entitlements table are
		// preloaded, so this is a map lookup plus a regex scan, not a backend
		// call. It is the same resolution the PAT bridge already performs per
		// request.
		sub, _ := ac["sub"].(string)
		_, effective, rerr := exchanger.ResolveInternalRolesAndEntitlements(sub)
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
			"arguments. Always returns { identity, entitlements }, plus whichever of name, " +
			"given_name, family_name and preferred_username the credential you are presenting " +
			"actually carries — a client authorized without the profile/email scopes will not " +
			"see those, by design. `identity` is your email, falling back to the token " +
			"subject.\n\n" +
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

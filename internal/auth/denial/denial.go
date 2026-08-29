// Package denial implements host-manager's single denial contract.
//
// One question — "may this caller have this?" — gets one answer shape:
//
//	no credential presented            -> 401 + WWW-Authenticate
//	credential, fails the identity gate -> 403, no challenge
//	credential, fails the requirement   -> 403 + insufficient_scope,
//	                                       when oauth2-protected
//
// The qualifier on the third row is load-bearing: Write emits the
// insufficient_scope challenge only when Opts.ResourceMetadata is set,
// because RFC 6750 is an OAuth 2.0 bearer-token spec and there is no
// resource metadata to point a client at otherwise. A non-oauth2 resource
// gets the bare 403 of the second row.
//
// No status is ever chosen to conceal that a resource exists. The
// anti-enumeration 404 this replaces concealed nothing: /-/openapi serves
// every Ready function's paths to anonymous callers with no entitlement
// check (internal/host/openapi.go), so enumeration was already cheaper by
// GET than by probing. If /-/openapi is ever gated or caller-filtered, that
// trade reverses and this package is what should be revisited.
//
// That condition is ENFORCED, not merely written down:
// TestOpenAPIPublishesGatedFunctionPathsToAnonymousCallers
// (internal/host/openapi_test.go) asserts a gated function path is present in
// the document built for a caller who presented no credential. Gating or
// caller-filtering /-/openapi turns that test red, which is the signal to
// come back here.
//
// This package owns statuses and challenges, never bodies and never
// redirects. Presentation belongs to the mux-wide unwrap layer
// (internal/host/feedback.go), which re-renders every >= 400 per Accept.
// Redirects belong to the page gate, because a redirect is an alternative
// to writing a status rather than a kind of status.
//
// Design: docs/superpowers/specs/2026-08-28-denial-contract-design.md
package denial

import (
	"context"
	"net/http"
	"strings"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Outcome is which of the three contract rows a denial fell into.
type Outcome int

const (
	// Unauthenticated: no credential was presented at all.
	Unauthenticated Outcome = iota
	// NoIdentity: a credential was presented but cannot address the
	// resource at all -- it fails the <resource>:<resourceName>:read
	// identity gate.
	NoIdentity
	// InsufficientScope: a credential was presented and clears the
	// identity gate, but does not satisfy the declared requirement.
	InsufficientScope
)

func (o Outcome) String() string {
	switch o {
	case Unauthenticated:
		return "unauthenticated"
	case NoIdentity:
		return "no-identity"
	case InsufficientScope:
		return "insufficient-scope"
	}
	return "unknown"
}

// Checker is the subset of the host's authorization checker that Classify
// needs. Declared here (rather than imported) so the package depends on
// behaviour, not on the HostHandler.
//
// GetParsedEntitlements is deliberately NOT in this set: Classify takes the
// caller's already-parsed entitlements instead of re-deriving them. See
// Classify.
type Checker interface {
	ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements
	VerifyResourceParsedEntitlements(
		string, string,
		entitlements.ParsedEntitlements, entitlements.ParsedRequirements,
		...string,
	) (bool, error)
}

// Opts carries everything Write needs to render a denial.
type Opts struct {
	Outcome Outcome
	// Issuer is the host's issuer address, used as the realm when the
	// resource is not oauth2-protected.
	Issuer string
	// ResourceMetadata is the full RFC 9728 metadata URL
	// (<issuer>/.well-known/oauth-protected-resource<basePath>).
	// Empty when the resource is not oauth2-protected.
	ResourceMetadata string
	// Scopes are the requirement's declared scopes, named in an
	// insufficient_scope challenge so a client can step up.
	Scopes []string
}

// Classify decides which contract row a denial falls into. It runs ONLY
// after a gate has already denied, so the extra identity probe below is
// never on the happy path.
//
// `held` is the caller's parsed entitlements, which every gate has ALREADY
// computed to make the decision that failed. Classify takes it rather than
// calling GetParsedEntitlements again: a second derivation costs another
// map+slice allocation, another claim re-parse, and another RLock on the
// per-host pattern cache that every concurrent request shares -- all to
// recompute a value the caller is holding.
//
// Anonymity is tested against the auth context rather than by inspecting
// entitlements: anonymous entitlements live inside the AuthorizationChecker
// itself, not as a synthetic auth context, so an absent context really does
// mean "no credential presented".
//
// A context with an EMPTY subject counts as anonymous too. That is the
// definition every other gate in host-manager already uses --
// hasEvaluatedSubject (internal/host/feedback.go), apitokenRevokeHandler
// (internal/host/apitoken.go) and capabilityMintHandler
// (internal/host/capabilities.go) all require a non-empty sub -- and a
// credential that names nobody cannot clear an identity gate keyed on who
// the caller is, so NoIdentity would be a 403 the caller can never fix.
//
// The identity/requirement split needs no library change. An EMPTY
// requirement set reduces VerifyResourceParsedEntitlements to exactly the
// identity check -- the same reduction /-/check relies on and documents
// (internal/host/check.go).
func Classify(
	ctx context.Context,
	c Checker,
	held entitlements.ParsedEntitlements,
	resource, name string,
	verbs ...string,
) Outcome {
	ac, authenticated := auth.GetAuthContext(ctx)
	if !authenticated {
		return Unauthenticated
	}
	if sub, _ := ac.GetSubject(); sub == "" {
		return Unauthenticated
	}
	if c == nil {
		return NoIdentity
	}
	hasIdentity, err := c.VerifyResourceParsedEntitlements(
		resource, name,
		held,
		c.ParseRequirements(nil),
		verbs...,
	)
	if err != nil || !hasIdentity {
		return NoIdentity
	}
	return InsufficientScope
}

// Write sets the status and, where the contract calls for one, the
// WWW-Authenticate header. It uses http.Error so the status text becomes
// unwrap's statusMsg; it never renders HTML itself.
func Write(w http.ResponseWriter, r *http.Request, o Opts) {
	// Symmetry with the page gate's discovery redirect, which carries
	// no-store for the reason that applies verbatim here: a cached denial
	// follows the user past the grant change that fixed it. Not a live
	// defect -- 401 and 403 are not heuristically cacheable (RFC 9111 4.2.2)
	// -- but an intermediary or a service worker instructed to cache them
	// would outlive the grant, and the whole point of insufficient_scope is
	// that the caller is expected to come back with more.
	w.Header().Set("Cache-Control", "no-store")

	// meta is o.ResourceMetadata once it has earned its place in a header;
	// "" when the resource is not oauth2-protected OR when the value could
	// not be validated. o.ResourceMetadata itself stays the "is this resource
	// oauth2-protected" signal, so an unsafe URL costs the challenge its
	// pointer, never the challenge itself.
	//
	// auth.CheckedResourceMetadata, not a copy of the rule: the same predicate
	// guards auth.bearerChallenge, which emits this parameter on the far more
	// reachable invalid/expired-token path. It lives in internal/auth because
	// this package imports internal/auth and the dependency cannot run back.
	meta := auth.CheckedResourceMetadata(r.Context(), o.ResourceMetadata)

	switch o.Outcome {
	case Unauthenticated:
		// RFC 7235: a 401 MUST carry a challenge. RFC 6750 3.1: the error
		// parameter is omitted when no credentials were sent -- claiming
		// invalid_token would be a lie about a token never presented.
		switch {
		case meta != "":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+meta+`"`)
		case o.Issuer != "":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+o.Issuer+`"`)
		default:
			// A host with no routing domain yet has no issuer to name.
			// RFC 7235 permits a bare scheme, and a bare Bearer is a valid
			// challenge -- realm="" would be worse than none.
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

	case InsufficientScope:
		// RFC 6750 3.1 defines insufficient_scope as a 403 that still
		// carries a challenge, which is what gives a client a step-up path
		// instead of a dead end.
		if o.ResourceMetadata != "" {
			c := `Bearer error="insufficient_scope"`
			if scope := safeScope(o.Scopes); scope != "" {
				c += `, scope="` + scope + `"`
			}
			if meta != "" {
				c += `, resource_metadata="` + meta + `"`
			}
			w.Header().Set("WWW-Authenticate", c)
		}
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)

	default: // NoIdentity
		// No challenge: the caller cannot address the resource at all, so
		// naming a scope would imply a scope would fix it.
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

// safeScope joins scopes RFC 6749 style (space-delimited), dropping any
// value that is not a well-formed scope-token. Scopes are operator-authored
// CR data, not caller-supplied -- but the same discipline the invalid_token
// challenge follows applies: nothing unvalidated reaches a header.
//
// ALLOW-list, not deny-list. The deny-list this replaces
// (strings.ContainsAny(s, "\"\\ \t\r\n,")) named the characters someone
// thought of and let NUL, VT, FF, DEL and every non-ASCII byte through.
func safeScope(scopes []string) string {
	safe := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if isScopeToken(s) {
			safe = append(safe, s)
		}
	}
	return strings.Join(safe, " ")
}

// isScopeToken reports whether s matches RFC 6749 3.3's scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ) -- printable ASCII minus SP, `"` and `\`.
// Byte-wise by construction: the production is defined over bytes, so a
// multi-byte rune is out of range regardless of how it is decoded.
func isScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}

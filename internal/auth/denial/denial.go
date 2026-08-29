// Package denial implements host-manager's single denial contract.
//
// One question — "may this caller have this?" — gets one answer shape:
//
//	no credential presented            -> 401 + WWW-Authenticate
//	credential, fails the identity gate -> 403, no challenge
//	credential, fails the requirement   -> 403 + insufficient_scope
//
// No status is ever chosen to conceal that a resource exists. The
// anti-enumeration 404 this replaces concealed nothing: /-/openapi serves
// every Ready function's paths to anonymous callers with no entitlement
// check (internal/host/openapi.go), so enumeration was already cheaper by
// GET than by probing. If /-/openapi is ever gated or caller-filtered, that
// trade reverses and this package is what should be revisited.
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
type Checker interface {
	GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements
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
// Anonymity is tested with auth.GetAuthContext rather than by inspecting
// entitlements: anonymous entitlements live inside the AuthorizationChecker
// itself, not as a synthetic auth context, so !ok really does mean "no
// credential presented".
//
// The identity/requirement split needs no library change. An EMPTY
// requirement set reduces VerifyResourceParsedEntitlements to exactly the
// identity check -- the same reduction /-/check relies on and documents
// (internal/host/check.go).
func Classify(ctx context.Context, c Checker, resource, name string, verbs ...string) Outcome {
	if _, authenticated := auth.GetAuthContext(ctx); !authenticated {
		return Unauthenticated
	}
	if c == nil {
		return NoIdentity
	}
	hasIdentity, err := c.VerifyResourceParsedEntitlements(
		resource, name,
		c.GetParsedEntitlements(ctx),
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
	switch o.Outcome {
	case Unauthenticated:
		// RFC 7235: a 401 MUST carry a challenge. RFC 6750 3.1: the error
		// parameter is omitted when no credentials were sent -- claiming
		// invalid_token would be a lie about a token never presented.
		switch {
		case o.ResourceMetadata != "":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+o.ResourceMetadata+`"`)
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
			c += `, resource_metadata="` + o.ResourceMetadata + `"`
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
// value that cannot sit in an HTTP quoted-string or would break the
// delimiter. Scopes are operator-authored CR data, not caller-supplied --
// but the same discipline the invalid_token challenge follows applies:
// nothing unvalidated reaches a header.
func safeScope(scopes []string) string {
	safe := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "" || strings.ContainsAny(s, "\"\\ \t\r\n,") {
			continue
		}
		safe = append(safe, s)
	}
	return strings.Join(safe, " ")
}

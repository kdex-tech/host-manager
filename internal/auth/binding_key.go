package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// bindingKeyLog is a dedicated logger for role-binding-key resolution decisions,
// filterable via --named-log-level=role-binding=2. It exists because the OIDC
// login / refresh / auth-code binding path resolves the key silently: the
// existing lookup=2 lines ("login lookup resolved" / "subject claims resolved")
// fire only for credential-backend resolution, never here, so an email-keyed
// KDexRoleBinding that never matches (kdex-tech/host-manager#215) leaves no
// trace of WHY. Mirrors roles.go's lookupLog so it needs no ctx.
var bindingKeyLog = logf.Log.WithName("role-binding")

// The role-resolution sites, as the role-binding line names them. Every site
// that resolves KDexRoleBinding roles passes one in its BindingSubject.
const (
	SiteLocalLogin          = "local login"
	SiteOIDCLogin           = "oidc login"
	SiteAuthCode            = "auth-code redeem"
	SiteRefresh             = "refresh"
	SiteSessionGrantRefresh = "session-grant refresh"
	SiteClientCredentials   = "client_credentials"
	SiteTokenExchange       = "token exchange"
	SiteHostPAT             = "host pat"
	SiteProxyPAT            = "proxy pat"
	SiteWhoami              = "whoami"
)

// bindingLogLevel is the role-binding verbosity of a site's resolution line:
// V(3) for the sites that resolve on every request, V(2) for the issue-time
// ones, as the signer splits V(2)/V(3). See kdex-tech/host-manager#255.
func bindingLogLevel(site string) int {
	switch site {
	case SiteHostPAT, SiteProxyPAT, SiteWhoami, SiteSessionGrantRefresh:
		return 3
	default:
		return 2
	}
}

// BindingSubject is what one role resolution matches KDexRoleBindings
// against. Key is the binding key: the sub, or under RoleBindingClaim another
// claim such as an email, so it is NEVER logged (#215). Kind is the subject's
// kind, which a binding's subjectKinds may restrict; the caller supplies it,
// because it cannot be inferred from a key that may not be the sub. Site
// names the resolution site (the Site* constants). Carrying the three in one
// named value keeps them from being swapped the way positional strings can.
// See kdex-tech/host-manager#255.
type BindingSubject struct {
	Key  string
	Kind kdexv1alpha1.SubjectKind
	Site string
}

// BindingNames collects, for one resolution, the names of the bindings that
// contributed roles and of those whose subject matched but whose subjectKinds
// excluded the caller's kind. The matcher fills it only when one is passed.
type BindingNames struct {
	Contributed, SkippedForKind []string
}

// resolveBindings runs one role resolution for bs and writes its role-binding
// line. It is the one place every resolution site's line comes from: the
// Exchanger's entry point (ResolveInternalRolesAndEntitlements) and local
// password login, which resolves inside the provider.
//
//   - An empty kind is logged at V(0): it matches only the bindings without
//     subjectKinds, a subset of the correct answer, so it marks a site that
//     lost track of its subject's kind.
//   - A non-empty kind this release does not know, such as a ServiceAccount a
//     newer release recorded on a credential, matches the same bindings, but
//     it is the credential's kind carried correctly, not a site's bug. It is
//     written on the site's own line, at the site's level.
//   - Binding names are collected only when the site's level is enabled, so
//     with the logger off resolution allocates nothing for them.
//   - The line names the site, the kind and the bindings, never bs.Key.
func resolveBindings(sp InternalIdentityProvider, bs BindingSubject) ([]string, []string, error) {
	if bs.Kind == "" {
		bindingKeyLog.Info("resolving roles without a subject kind; only bindings without subjectKinds can match",
			"site", bs.Site)
	}
	log := bindingKeyLog.V(bindingLogLevel(bs.Site))
	if !log.Enabled() {
		return sp.FindInternalRolesAndEntitlements(bs, nil)
	}
	var names BindingNames
	roles, entitlements, err := sp.FindInternalRolesAndEntitlements(bs, &names)
	if err == nil {
		log.Info("role bindings resolved",
			"site", bs.Site,
			"kind", string(bs.Kind),
			"contributed", names.Contributed,
			"skipped_for_kind", names.SkippedForKind)
	}
	return roles, entitlements, err
}

// resolveBindingKey returns the value KDexRoleBinding.Subject is matched against
// for a login, given the login's claims and the identity subject `sub`. It
// implements the RoleBindingClaim feature: identity stays `sub`, but binding
// matching may key on a configurable, human-authorable claim (e.g. email).
//
//   - roleBindingClaim "" or "sub": always returns sub (historical behavior).
//   - the named claim absent or not a non-empty string: returns sub, so non-OIDC
//     logins (local/PAT) that lack the claim keep matching on sub.
//   - roleBindingClaim == "email" && requireEmailVerified && email_verified not
//     truthy: returns sub, so an unverified address cannot inherit email-keyed roles.
func resolveBindingKey(claims jwt.MapClaims, sub, roleBindingClaim string, requireEmailVerified bool) string {
	if roleBindingClaim == "" || roleBindingClaim == "sub" {
		return sub
	}
	v, ok := claims[roleBindingClaim].(string)
	if !ok || v == "" {
		return sub
	}
	if roleBindingClaim == "email" && requireEmailVerified && !emailVerifiedTruthy(claims) {
		return sub
	}
	return v
}

// bindingKeyLogKV renders a resolveBindingKey decision as V(2) diagnostic
// key/values. It logs the OUTCOME and the discriminating inputs -- never the
// claim VALUE itself (an email is PII) -- so a login can be diagnosed without
// writing an address to the logs. `resolved_to_sub` distinguishes the two
// silent-fallback causes the #215 investigation could not tell apart:
//   - claim_present=false: the claims carried no usable (non-empty string)
//     value for roleBindingClaim (e.g. the id_token had no `email`), or
//   - email_verified_truthy=false: the value was present but unverified.
//
// `role_binding_claim` / `require_email_verified` echo the config actually in
// effect at resolution time, closing the last remaining hypothesis (a runtime
// config that is not what the CR shows).
func bindingKeyLogKV(claims jwt.MapClaims, sub, bindingKey, roleBindingClaim string, requireEmailVerified bool) []any {
	v, isString := claims[roleBindingClaim].(string)
	return []any{
		"role_binding_claim", roleBindingClaim,
		"require_email_verified", requireEmailVerified,
		"claim_present", isString && v != "",
		"email_verified_truthy", emailVerifiedTruthy(claims),
		"resolved_to_sub", bindingKey == sub,
	}
}

// emailVerifiedTruthy reports whether the `email_verified` claim asserts a
// verified address. OIDC defines it as a boolean, but some IdPs emit the string
// "true"; both are accepted, everything else (absent, false, "false", other
// types) is treated as unverified.
func emailVerifiedTruthy(claims jwt.MapClaims) bool {
	switch ev := claims["email_verified"].(type) {
	case bool:
		return ev
	case string:
		return strings.EqualFold(ev, "true")
	default:
		return false
	}
}

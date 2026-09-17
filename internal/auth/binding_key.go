package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
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

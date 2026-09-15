package auth

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

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

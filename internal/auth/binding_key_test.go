package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestResolveBindingKey(t *testing.T) {
	const sub = "104187opaque"
	cases := []struct {
		name             string
		claims           jwt.MapClaims
		roleBindingClaim string
		requireVerified  bool
		want             string
	}{
		{"default empty -> sub", jwt.MapClaims{"email": "a@x.io"}, "", true, sub},
		{"explicit sub -> sub", jwt.MapClaims{"email": "a@x.io"}, "sub", true, sub},
		{"email present verified bool", jwt.MapClaims{"email": "a@x.io", "email_verified": true}, "email", true, "a@x.io"},
		{"email present verified string", jwt.MapClaims{"email": "a@x.io", "email_verified": "true"}, "email", true, "a@x.io"},
		{"email unverified bool -> sub", jwt.MapClaims{"email": "a@x.io", "email_verified": false}, "email", true, sub},
		{"email unverified string -> sub", jwt.MapClaims{"email": "a@x.io", "email_verified": "false"}, "email", true, sub},
		{"email verified absent -> sub", jwt.MapClaims{"email": "a@x.io"}, "email", true, sub},
		{"email require off, unverified -> email", jwt.MapClaims{"email": "a@x.io", "email_verified": false}, "email", false, "a@x.io"},
		{"claim absent -> sub", jwt.MapClaims{}, "email", true, sub},
		{"claim empty string -> sub", jwt.MapClaims{"email": ""}, "email", true, sub},
		{"claim non-string -> sub", jwt.MapClaims{"email": 42}, "email", false, sub},
		{"custom claim present", jwt.MapClaims{"upn": "a@x.io"}, "upn", true, "a@x.io"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveBindingKey(tc.claims, sub, tc.roleBindingClaim, tc.requireVerified)
			assert.Equal(t, tc.want, got)
		})
	}
}

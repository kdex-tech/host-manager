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

// kv turns the flat key/value slice bindingKeyLogKV returns into a map for
// assertion. It also asserts the slice is well-formed (even length).
func kv(t *testing.T, pairs []any) map[string]any {
	t.Helper()
	assert.Equal(t, 0, len(pairs)%2, "log KV slice must be even-length")
	m := make(map[string]any, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		k, ok := pairs[i].(string)
		assert.True(t, ok, "log KV key at %d must be a string", i)
		m[k] = pairs[i+1]
	}
	return m
}

func TestBindingKeyLogKV(t *testing.T) {
	const sub = "104187opaque"
	const email = "a@x.io" // PII: must never appear in the emitted values.

	t.Run("email present and verified -> resolved to email, not sub", func(t *testing.T) {
		claims := jwt.MapClaims{"email": email, "email_verified": true}
		bindingKey := resolveBindingKey(claims, sub, "email", true)
		m := kv(t, bindingKeyLogKV(claims, sub, bindingKey, "email", true))
		assert.Equal(t, "email", m["role_binding_claim"])
		assert.Equal(t, true, m["require_email_verified"])
		assert.Equal(t, true, m["claim_present"])
		assert.Equal(t, true, m["email_verified_truthy"])
		assert.Equal(t, false, m["resolved_to_sub"])
	})

	// The two silent-fallback causes the #215 investigation could not tell apart.
	t.Run("claim absent -> fell back to sub, claim_present false", func(t *testing.T) {
		claims := jwt.MapClaims{}
		bindingKey := resolveBindingKey(claims, sub, "email", true)
		m := kv(t, bindingKeyLogKV(claims, sub, bindingKey, "email", true))
		assert.Equal(t, false, m["claim_present"])
		assert.Equal(t, false, m["email_verified_truthy"])
		assert.Equal(t, true, m["resolved_to_sub"])
	})

	t.Run("email present but unverified -> fell back to sub, claim_present true", func(t *testing.T) {
		claims := jwt.MapClaims{"email": email, "email_verified": false}
		bindingKey := resolveBindingKey(claims, sub, "email", true)
		m := kv(t, bindingKeyLogKV(claims, sub, bindingKey, "email", true))
		assert.Equal(t, true, m["claim_present"])
		assert.Equal(t, false, m["email_verified_truthy"])
		assert.Equal(t, true, m["resolved_to_sub"])
	})

	t.Run("never logs the claim value (PII)", func(t *testing.T) {
		claims := jwt.MapClaims{"email": email, "email_verified": true}
		bindingKey := resolveBindingKey(claims, sub, "email", true)
		for _, v := range bindingKeyLogKV(claims, sub, bindingKey, "email", true) {
			assert.NotEqual(t, email, v, "email value must not be logged")
		}
	})
}

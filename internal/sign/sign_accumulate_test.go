package sign_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// asStrings flattens a []string / []any claim for comparison.
func asStrings(t *testing.T, v any) []string {
	t.Helper()
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, len(l))
		for i, e := range l {
			s, ok := e.(string)
			require.Truef(t, ok, "non-string element %T", e)
			out[i] = s
		}
		return out
	}
	t.Fatalf("unexpected claim type %T", v)
	return nil
}

// TestSigner_Project_ClaimMappingsAccumulate pins kdex-tech/host-manager#229
// through the real signer: a claimMappings rule that does not restate
// self.entitlements must not strip the static grants from the token. The
// source claim (extra_grants) is an arbitrary example — no claim is special-cased.
func TestSigner_Project_ClaimMappingsAccumulate(t *testing.T) {
	ctx := jwt.MapClaims{
		"sub":          "alice",
		"entitlements": []any{"pages:home:read"},
		"extra_grants": []any{"functions:/api/x:read"},
	}
	tests := []struct {
		name  string
		rules []dmapper.MappingRule
	}{
		{"A: rule omits self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"B: rule restates self.entitlements", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements + self.extra_grants", TargetPropPath: "entitlements"},
		}},
		{"C: identity rule then omitting rule", []dmapper.MappingRule{
			{SourceExpression: "self.entitlements", TargetPropPath: "entitlements"},
			{SourceExpression: "self.extra_grants", TargetPropPath: "entitlements"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := testSignerWithMapper(t, tt.rules).Project(ctx)
			require.NoError(t, err)
			assert.Equal(t, []string{"pages:home:read", "functions:/api/x:read"}, asStrings(t, p["entitlements"]))
		})
	}
}

// TestSigner_EnrichThenProjectNoGrowth pins that the production double run —
// EnrichAuthContext over the auth context, then Project over the enriched
// context with the SAME mapper — neither duplicates nor grows a list claim.
// roles is used because entitlements.Compact would mask duplicates in
// entitlements.
func TestSigner_EnrichThenProjectNoGrowth(t *testing.T) {
	rules := []dmapper.MappingRule{{SourceExpression: "self.extra_roles", TargetPropPath: "roles"}}
	m, err := dmapper.NewMapper(rules)
	require.NoError(t, err)

	ac := auth.AuthContext{"sub": "alice", "roles": []any{"admin"}, "extra_roles": []any{"auditor"}}
	auth.EnrichAuthContext(ac, m)
	assert.Equal(t, []string{"admin", "auditor"}, asStrings(t, ac["roles"]))

	p, err := testSignerWithMapper(t, rules).Project(jwt.MapClaims(ac))
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "auditor"}, asStrings(t, p["roles"]))
}

// TestSigner_Project_ClaimMappingsReplaceNarrows pins the opt-out through the
// signer: merge: Replace lets a filtering rule narrow a list claim.
func TestSigner_Project_ClaimMappingsReplaceNarrows(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{{
		SourceExpression: "dyn(self.roles).filter(r, r != 'guest')",
		TargetPropPath:   "roles",
		Merge:            dmapper.MergeReplace,
	}})
	p, err := s.Project(jwt.MapClaims{"sub": "alice", "roles": []any{"admin", "guest"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, asStrings(t, p["roles"]))
}

// TestSigner_Project_MapperSeesOutboundAudience pins that a claimMappings rule
// targeting aud builds on the audience THIS token carries, never the inbound
// context's. On the FAT path the signing context is the caller's host session
// (aud = the host); under list accumulation a rule writing aud would otherwise
// union the host audience into the FAT, letting it be replayed against the
// host. Project already treats sub/iss/aud as authoritative; the mapper must
// see those outbound values. See kdex-tech/host-manager#229 final review.
func TestSigner_Project_MapperSeesOutboundAudience(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{{
		SourceExpression: "['https://peer']",
		TargetPropPath:   "aud",
	}})
	p, err := s.Project(jwt.MapClaims{
		"sub": "alice",
		"iss": "https://host",
		"aud": []any{"https://host"},
	})
	require.NoError(t, err)
	aud := asStrings(t, p["aud"])
	assert.NotContains(t, aud, "https://host", "the inbound host audience must never reach a projected token")
	assert.Equal(t, []string{"aud-test", "https://peer"}, aud)
}

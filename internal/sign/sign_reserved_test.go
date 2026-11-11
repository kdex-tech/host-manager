package sign_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// The claims a claimMappings rule may never set. A host or KDexFunction author
// writes those rules; on the FAT path a rule that wrote `aud` would make the
// token minted for a function replayable against the host by that function's
// backend, and one that wrote `sub` would rename the caller. The list is
// kdex-crds' ReservedClaimTargets, the one the admission rules are pinned to,
// so admission refuses exactly what the mint drops.
func TestReservedClaims_AreTheAdmissionRulesTargets(t *testing.T) {
	assert.ElementsMatch(t, kdexv1alpha1.ReservedClaimTargets(), sign.ReservedClaims())
	for _, c := range sign.MintDecidedClaims() {
		assert.Contains(t, sign.ReservedClaims(), c, "every mint-decided claim is reserved")
	}
}

// kdex-tech/host-manager#211: a rule targeting a reserved claim, top-level or
// beneath it, is dropped; the token carries what the mint decided.
func TestSigner_Project_ClaimMappingCannotSetReservedClaims(t *testing.T) {
	inbound := jwt.MapClaims{
		"sub": "alice", "iss": "https://host", "aud": []any{"https://host"},
		"scope": "openid", "act": map[string]any{"sub": "svc"},
	}
	for _, claim := range sign.ReservedClaims() {
		for _, target := range []string{claim, claim + ".nested"} {
			t.Run(target, func(t *testing.T) {
				s := testSignerWithMapper(t, []dmapper.MappingRule{{
					SourceExpression: `"forged"`, TargetPropPath: target,
				}})
				want, err := testSigner(t).Project(inbound)
				require.NoError(t, err)

				got, err := s.Project(inbound)
				require.NoError(t, err)
				assert.Equal(t, want[claim], got[claim], "a rule must not set %s", target)
			})
		}
	}
}

// The filter is exactly the reserved set: an ordinary claim, and one whose
// name merely starts with a reserved one, still map.
func TestSigner_Project_ClaimMappingStillSetsOrdinaryClaims(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{
		{SourceExpression: `["pages:a:read"]`, TargetPropPath: "entitlements"},
		{SourceExpression: `"x"`, TargetPropPath: "subscription"},
	})
	got, err := s.Project(jwt.MapClaims{"sub": "alice"})
	require.NoError(t, err)
	assert.Equal(t, []string{"pages:a:read"}, got["entitlements"])
	assert.Equal(t, "x", got["subscription"])
}

// A rule writing exp used to be the one way to lose the signer's default
// expiry (#227); with the target dropped the token keeps it.
func TestSigner_Sign_ClaimMappingCannotZeroExp(t *testing.T) {
	s := testSignerWithMapper(t, []dmapper.MappingRule{{SourceExpression: "0", TargetPropPath: "exp"}})
	tok, err := s.Sign(jwt.MapClaims{"sub": "user-42"})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(tok, claims)
	require.NoError(t, err)
	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, exp, "the signer's default exp survives the rule")
}

// ReservedTargets names the rules the signer will drop, so the reconcile that
// builds a mapper can say so once instead of every mint dropping them silently.
func TestReservedTargets(t *testing.T) {
	got := sign.ReservedTargets([]dmapper.MappingRule{
		{SourceExpression: `"x"`, TargetPropPath: "entitlements"},
		{SourceExpression: `"x"`, TargetPropPath: "aud"},
		{SourceExpression: `"x"`, TargetPropPath: "act.sub"},
		{SourceExpression: `"x"`, TargetPropPath: "subscription"},
	})
	assert.Equal(t, []string{"aud", "act.sub"}, got)
	assert.Empty(t, sign.ReservedTargets(nil))
}

// kdex-tech/host-manager#295: client_id names the client a token was issued
// to. It is mint-decided, so Project carries it from the signing context into
// every FAT, and reserved, so a claimMappings rule can neither override it
// nor add one to a token issued to no client.
func TestSigner_Project_ClientIDIsMintDecided(t *testing.T) {
	assert.Contains(t, sign.MintDecidedClaims(), sign.ClaimClientID)
	assert.Contains(t, kdexv1alpha1.ReservedClaimTargets(), sign.ClaimClientID)

	forger := testSignerWithMapper(t, []dmapper.MappingRule{{
		SourceExpression: `"forged-client"`, TargetPropPath: sign.ClaimClientID,
	}})
	for name, s := range map[string]*sign.Signer{"without a mapper": testSigner(t), "with a forging rule": forger} {
		got, err := s.Project(jwt.MapClaims{"sub": "alice", sign.ClaimClientID: "dcr_abc"})
		require.NoError(t, err, name)
		assert.Equal(t, "dcr_abc", got[sign.ClaimClientID], name)
	}

	got, err := forger.Project(jwt.MapClaims{"sub": "alice"})
	require.NoError(t, err)
	assert.NotContains(t, got, sign.ClaimClientID, "a rule cannot add one")

	assert.Equal(t, []string{sign.ClaimClientID}, sign.ReservedTargets([]dmapper.MappingRule{
		{SourceExpression: `"x"`, TargetPropPath: sign.ClaimClientID},
	}), "the reconcile reports the rule it will drop")
}

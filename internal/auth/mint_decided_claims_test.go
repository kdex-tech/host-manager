package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMintDecidedClaims_SingleSourced (quad 2026-10-28, D): every claim the
// mint decides (sign.MintDecidedClaims) is reserved from backend claims, and
// survives the signer's projection, with a claimMappings mapper and without,
// so a claim added to that one list is mint-decided everywhere.
func TestMintDecidedClaims_SingleSourced(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	// The mapper rewrites every mint-decided claim; the mint's value must win.
	var rules []dmapper.MappingRule
	for _, claim := range sign.MintDecidedClaims() {
		rules = append(rules, dmapper.MappingRule{SourceExpression: `"mapped"`, TargetPropPath: claim})
	}
	mapper, err := dmapper.NewMapper(rules)
	require.NoError(t, err)
	withMapper, err := sign.NewSigner("aud", time.Minute, "iss", &cs, "kid", mapper)
	require.NoError(t, err)
	withoutMapper, err := sign.NewSigner("aud", time.Minute, "iss", &cs, "kid", nil)
	require.NoError(t, err)

	require.NotEmpty(t, sign.MintDecidedClaims())
	for _, claim := range sign.MintDecidedClaims() {
		t.Run(claim, func(t *testing.T) {
			assert.Contains(t, reservedMintClaims, claim, "not reserved from backend claims")
			for name, s := range map[string]*sign.Signer{"with a mapper": withMapper, "without a mapper": withoutMapper} {
				p, err := s.Project(jwt.MapClaims{"sub": "alice", claim: "minted"})
				require.NoError(t, err, name)
				assert.Equal(t, "minted", p[claim], "%s: the claim did not survive Project", name)
			}
		})
	}
}

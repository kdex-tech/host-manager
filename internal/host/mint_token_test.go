package host

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
)

func testAuthConfigForMint(t *testing.T) *auth.Config {
	t.Helper()
	kp := keys.GenerateECDSAKeyPair() // ECDSA P-256 dev pair
	return &auth.Config{
		Audience:                  "https://dev.example",
		Issuer:                    "https://dev.example",
		ActivePair:                kp.ActiveKey(),
		MintTokenEnabled:          true,
		MintTokenTTLCap:           60 * time.Second,
		MintTokenUsesCap:          32,
		MintTokenDestructiveVerbs: []string{"delete", "own"},
	}
}

func TestMintCapabilityToken_AttenuatesAndSignsHostAudience(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write", "functions:/api/v1/files:read"}

	res, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:write"},
		TTLSeconds:   30,
	})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Entitlements).To(Equal([]string{"functions:/api/v1/files:write"}))

	// Parse back with the active public key; assert host audience + claim.
	var claims jwt.MapClaims
	_, perr := jwt.ParseWithClaims(res.Token, &claims, func(*jwt.Token) (any, error) {
		return hh.authConfig.ActivePair.Private.Public(), nil
	}, jwt.WithAudience("https://dev.example"), jwt.WithIssuer("https://dev.example"))
	g.Expect(perr).ToNot(HaveOccurred())
	g.Expect(claims["sub"]).To(Equal("alice"))
	g.Expect(claims["entitlements"]).To(ContainElement("functions:/api/v1/files:write"))
	g.Expect(claims[capUsesClaim]).To(BeTrue())
}

func TestMintCapabilityToken_RejectsOverBroad(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	held := []string{"functions:/api/v1/files:write"}

	_, err := hh.mintCapabilityToken(context.Background(), "alice", held, MintTokenRequest{
		Entitlements: []string{"functions:/api/v1/files:*"},
	})
	g.Expect(err).To(MatchError(ContainSubstring("functions:/api/v1/files:*")))
}

func TestMintCapabilityToken_ClampsTTL(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"pages:/:read"}, MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 99999})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(61*time.Second).Unix()))
}

func TestMintCapabilityToken_DestructiveVerbForcing(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: testAuthConfigForMint(t)}

	// Explicit destructive verb: forced to uses=1 and ttl<=10s even though
	// the caller asked for uses=5 and a 60s ttl.
	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"vector_stores:X:delete"},
		MintTokenRequest{Entitlements: []string{"vector_stores:X:delete"}, Uses: 5, TTLSeconds: 60})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.UsesRemaining).To(Equal(1))
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(11*time.Second).Unix()))

	// Wildcard verb encompasses destructive verbs -> same forcing.
	res2, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"vector_stores:X:all"},
		MintTokenRequest{Entitlements: []string{"vector_stores:X:all"}, Uses: 5, TTLSeconds: 60})
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res2.UsesRemaining).To(Equal(1))
	g.Expect(res2.ExpiresAt).To(BeNumerically("<=", time.Now().Add(11*time.Second).Unix()))
}

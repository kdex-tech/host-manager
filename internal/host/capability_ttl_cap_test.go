package host

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
)

// twoCapConfig builds a mint-enabled config whose REST capability ceiling
// differs from the MCP mint_token ceiling, so a test can tell which surface's
// cap actually clamped a request.
func twoCapConfig(t *testing.T, mcpCap, capCap time.Duration) *auth.Config {
	t.Helper()
	kp := keys.GenerateECDSAKeyPair()
	return &auth.Config{
		Audience:                  "https://dev.example",
		Issuer:                    "https://dev.example",
		ActivePair:                kp.ActiveKey(),
		MintTokenEnabled:          true,
		MintTokenTTLCap:           mcpCap,
		MintTokenCapabilityTTLCap: capCap,
		MintTokenUsesCap:          32,
		MintTokenDestructiveVerbs: []string{"delete", "own"},
	}
}

// The REST /-/capabilities/mint surface must honor the capability ceiling, not
// the (shorter) MCP mint_token ceiling: a 300s request under a 60s MCP cap but
// a 600s REST cap survives at ~300s. If the REST surface wrongly reused the MCP
// cap, this would clamp to 60s.
func TestCapabilityMintHandler_UsesCapabilityTTLCap(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: twoCapConfig(t, 60*time.Second, 600*time.Second)}

	rw := postMint(hh, "alice", []string{"pages:/:read"},
		mintReq(t, MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 300}))

	g.Expect(rw.Code).To(Equal(http.StatusOK))
	var res MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &res)).To(Succeed())
	g.Expect(res.ExpiresAt).To(BeNumerically(">", time.Now().Add(120*time.Second).Unix()),
		"a 300s request must not be clamped to the 60s MCP cap on the REST surface")
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(301*time.Second).Unix()))
}

// The REST capability ceiling still clamps: a request above it is capped AT the
// capability ceiling (600s), not left at the requested value and not dropped to
// the MCP ceiling.
func TestCapabilityMintHandler_CapabilityCapClampsAboveIt(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: twoCapConfig(t, 60*time.Second, 600*time.Second)}

	rw := postMint(hh, "alice", []string{"pages:/:read"},
		mintReq(t, MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 99999}))

	g.Expect(rw.Code).To(Equal(http.StatusOK))
	var res MintTokenResult
	g.Expect(json.Unmarshal(rw.Body.Bytes(), &res)).To(Succeed())
	g.Expect(res.ExpiresAt).To(BeNumerically(">", time.Now().Add(120*time.Second).Unix()))
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(601*time.Second).Unix()))
}

// The MCP mint_token surface must IGNORE the capability ceiling: even with a
// large capability cap configured, the MCP wrapper clamps to the MCP ttl cap.
// This is the whole point of the split — the capability cap must not leak back
// onto the MCP tool.
func TestMintCapabilityToken_MCPSurfaceIgnoresCapabilityCap(t *testing.T) {
	g := NewWithT(t)
	hh := &HostHandler{authConfig: twoCapConfig(t, 60*time.Second, 600*time.Second)}

	res, err := hh.mintCapabilityToken(context.Background(), "alice",
		[]string{"pages:/:read"},
		MintTokenRequest{Entitlements: []string{"pages:/:read"}, TTLSeconds: 300}, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.ExpiresAt).To(BeNumerically("<=", time.Now().Add(61*time.Second).Unix()),
		"the MCP mint_token surface must stay clamped to its own 60s cap")
}

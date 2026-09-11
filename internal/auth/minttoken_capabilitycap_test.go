package auth

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// An explicit capabilityTtlCapSeconds is resolved independently of the MCP
// ttlCapSeconds — the two surfaces get two ceilings.
func TestApplyMintTokenPolicy_CapabilityTTLCap_Explicit(t *testing.T) {
	g := NewWithT(t)
	cfg := &Config{}
	applyMintTokenPolicy(cfg, &kdexv1alpha1.MintToken{
		Enabled: true, TTLCapSeconds: 60, CapabilityTTLCapSeconds: 600,
	})
	g.Expect(cfg.MintTokenTTLCap).To(Equal(60 * time.Second))
	g.Expect(cfg.MintTokenCapabilityTTLCap).To(Equal(600 * time.Second))
}

// Unset capabilityTtlCapSeconds inherits the resolved ttlCapSeconds, so a host
// that never sets it behaves exactly as before this field existed.
func TestApplyMintTokenPolicy_CapabilityTTLCap_FallsBackToTTLCap(t *testing.T) {
	g := NewWithT(t)
	cfg := &Config{}
	applyMintTokenPolicy(cfg, &kdexv1alpha1.MintToken{Enabled: true, TTLCapSeconds: 120})
	g.Expect(cfg.MintTokenCapabilityTTLCap).To(Equal(120*time.Second),
		"unset capabilityTtlCapSeconds must inherit ttlCapSeconds")
}

// With both unset, the capability cap inherits ttlCapSeconds' own default (60).
func TestApplyMintTokenPolicy_CapabilityTTLCap_InheritsDefaultTTLCap(t *testing.T) {
	g := NewWithT(t)
	cfg := &Config{}
	applyMintTokenPolicy(cfg, &kdexv1alpha1.MintToken{Enabled: true})
	g.Expect(cfg.MintTokenCapabilityTTLCap).To(Equal(60 * time.Second))
}

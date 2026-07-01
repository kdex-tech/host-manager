package host

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/sign"
)

// capUsesClaim marks a JWT as a bounded-use capability minted by mint_token.
// The inbound middleware decrements the jti-keyed use counter only for tokens
// carrying this claim; ordinary session/FAT tokens never carry it.
const capUsesClaim = "kdx_cap"

// MintTokenRequest is the argument shape of the mint_token MCP tool.
type MintTokenRequest struct {
	Entitlements []string `json:"entitlements"`
	TTLSeconds   int      `json:"ttl_seconds,omitempty"`
	Uses         int      `json:"uses,omitempty"`
}

// MintTokenResult is the mint_token success payload.
type MintTokenResult struct {
	Token         string   `json:"token"`
	ExpiresAt     int64    `json:"expires_at"`
	Entitlements  []string `json:"entitlements"`
	UsesRemaining int      `json:"uses_remaining"`
}

// hasDestructiveVerb reports whether any requested entitlement's verb is in the
// configured destructive set.
func hasDestructiveVerb(requested, destructive []string) bool {
	for _, e := range requested {
		parts := strings.Split(e, ":")
		verb := parts[len(parts)-1]
		for _, d := range destructive {
			if verb == d {
				return true
			}
		}
	}
	return false
}

// mintCapabilityToken verifies requested ⊆ held (directional attenuation),
// clamps ttl/uses to the host policy, and signs a short-lived HOST-AUDIENCE
// JWT whose entitlements claim is exactly the requested (attenuated) set. The
// caller (interception layer) supplies sub + held from the request auth context.
//
// Phase 1: the token is a stateless windowed JWT. `Uses` is clamped and
// reflected in UsesRemaining but no counter is provisioned yet (Phase 2 adds
// the jti-keyed Valkey counter and the middleware decrement). The capUsesClaim
// marker is always set so Phase 2 activates without re-minting semantics.
func (hh *HostHandler) mintCapabilityToken(ctx context.Context, sub string, held []string, req MintTokenRequest) (MintTokenResult, error) {
	cfg := hh.authConfig
	if cfg == nil || !cfg.MintTokenEnabled {
		return MintTokenResult{}, fmt.Errorf("mint_token is not enabled on this host")
	}
	if sub == "" {
		return MintTokenResult{}, fmt.Errorf("mint_token requires an authenticated caller")
	}
	if len(req.Entitlements) == 0 {
		return MintTokenResult{}, fmt.Errorf("mint_token requires at least one entitlement")
	}

	// Attenuation: every requested entitlement must be dominated by the held set.
	if offender, ok := entitlements.VerifyAttenuation(held, req.Entitlements); !ok {
		return MintTokenResult{}, fmt.Errorf("entitlement not held by caller: %s", offender)
	}

	// Clamp ttl.
	ttl := cfg.MintTokenTTLCap
	if req.TTLSeconds > 0 {
		reqTTL := time.Duration(req.TTLSeconds) * time.Second
		if reqTTL < ttl {
			ttl = reqTTL
		}
	}

	// Clamp uses; destructive verbs force single-use + shortest ttl.
	uses := req.Uses
	if uses <= 0 {
		uses = 1
	}
	if uses > cfg.MintTokenUsesCap {
		uses = cfg.MintTokenUsesCap
	}
	if hasDestructiveVerb(req.Entitlements, cfg.MintTokenDestructiveVerbs) {
		uses = 1
		if ttl > 10*time.Second {
			ttl = 10 * time.Second
		}
	}

	signer, err := sign.NewSigner(cfg.Audience, ttl, cfg.Issuer, &cfg.ActivePair.Private, cfg.ActivePair.KeyId, nil)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint signer: %w", err)
	}

	// signer.Project runs the claim allowlist (which passes "entitlements" and
	// "sub" but NOT capUsesClaim). Inject the capability marker into the
	// PROJECTED claims so it survives into the signed token — SignProjected
	// gives the projection the last word. (signer.Sign would drop capUsesClaim.)
	projected, err := signer.Project(jwt.MapClaims{
		"sub":          sub,
		"entitlements": req.Entitlements,
	})
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint project: %w", err)
	}
	projected[capUsesClaim] = true
	token, err := signer.SignProjected(projected)
	if err != nil {
		return MintTokenResult{}, fmt.Errorf("mint sign: %w", err)
	}

	return MintTokenResult{
		Token:         token,
		ExpiresAt:     time.Now().Add(ttl).Unix(),
		Entitlements:  req.Entitlements,
		UsesRemaining: uses,
	}, nil
}

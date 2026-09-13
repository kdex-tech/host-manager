/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	. "github.com/onsi/gomega"
	"kdex.dev/crds/api/v1alpha1"
)

// jitGrant is the per-subject entitlement a login hook "provisions" during its
// gate; the fix (#206) must surface it in the FIRST minted token.
const jitGrant = "vector_stores:vs_alice:all"

// gateJITMapping is the guarded host claim-mapping that folds a backend Lookup's
// custom `vs_entitlements` claim into `entitlements` -- the documented delivery
// path for data-driven grants. The `has()` guards make it a no-op before any
// dynamic data exists, so it is safe on a login with no provisioned grants.
func gateJITMapping() []dmapper.MappingRule {
	return []dmapper.MappingRule{{
		SourceExpression: "(has(self.entitlements) ? self.entitlements : []) + " +
			"(has(self.vs_entitlements) ? self.vs_entitlements : [])",
		TargetPropPath: "entitlements",
	}}
}

// provisioningProvider models a downstream service that JIT-provisions a subject
// during an enforcing login gate. `provisioned` flips (via the hook) to model the
// grant coming into existence mid-login; ResolveClaims then delivers it as the
// backend `vs_entitlements` custom claim. resolveCalls counts live resolves so a
// test can prove the post-gate enrichment is skipped on the hot path.
type provisioningProvider struct {
	provisioned  atomic.Bool
	resolveCalls atomic.Int64
}

func (p *provisioningProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	if subject != "alice" {
		return nil, ErrGrantFailure
	}
	return jwt.MapClaims{"sub": subject}, nil
}

func (p *provisioningProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func (p *provisioningProvider) ResolveClaimsWithError(string) (jwt.MapClaims, error) {
	p.resolveCalls.Add(1)
	grants := []string{}
	if p.provisioned.Load() {
		grants = []string{jitGrant}
	}
	return jwt.MapClaims{"vs_entitlements": grants}, nil
}

func (p *provisioningProvider) ResolveClaims(subject string) jwt.MapClaims {
	claims, _ := p.ResolveClaimsWithError(subject)
	return claims
}

// newGateEnrichExchanger builds a LoginLocal-capable Exchanger whose signer folds
// the backend `vs_entitlements` into `entitlements`, plus the given dispatcher and
// provisioning provider. Mirrors newLoginTestExchanger with a claim-mapping added.
func newGateEnrichExchanger(t *testing.T, d *EventDispatcher, p InternalIdentityProvider) *Exchanger {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cs := crypto.Signer(priv)
	mapper, err := dmapper.NewMapper(gateJITMapping())
	if err != nil {
		t.Fatalf("new mapper: %v", err)
	}
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", mapper)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	cfg := Config{
		Issuer:          "test-iss",
		Audience:        "test-aud",
		Signer:          *signer,
		ActivePair:      &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		RefreshTokenTTL: time.Hour,
		MaxSessionAge:   time.Hour,
		Clients:         map[string]AuthClient{"client": {ClientID: "client"}},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "gate-enrich-test", nil)
	if err != nil {
		t.Fatalf("new cache manager: %v", err)
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, p, d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// entitlementsOf decodes the (unverified) entitlements claim of a minted token.
func entitlementsOf(t *testing.T, tokenStr string) []string {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	raw, _ := claims["entitlements"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// provisioningHook returns an enforcing/advisory login hook whose server flips
// the provider to "provisioned" when called -- the downstream JIT provisioner.
func provisioningHook(t *testing.T, p *provisioningProvider, mode string) *EventDispatcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		p.provisioned.Store(true)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "login", mode, nil),
	}, logr.Discard())
}

// TestHasEnforcingLogin pins the predicate that gates the post-gate enrichment
// (#206): enrichment must run only when an enforcing *login* hook is configured,
// so a deployment with no hooks -- or only advisory / non-login enforcing hooks
// -- keeps the pre-#206 mint path unchanged (no extra backend resolve).
func TestHasEnforcingLogin(t *testing.T) {
	g := NewWithT(t)

	var nild *EventDispatcher
	g.Expect(nild.HasEnforcingLogin()).To(BeFalse(), "nil dispatcher enforces no login")

	g.Expect(NewEventDispatcher("h", nil, logr.Discard()).HasEnforcingLogin()).
		To(BeFalse(), "no hooks means no enforcing login")

	advisory := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", "http://unused", "login", "advisory", nil),
	}, logr.Discard())
	g.Expect(advisory.HasEnforcingLogin()).
		To(BeFalse(), "an advisory login hook does not provision-gate a login")

	logout := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", "http://unused", "logout", "enforcing", nil),
	}, logr.Discard())
	g.Expect(logout.HasEnforcingLogin()).
		To(BeFalse(), "an enforcing logout hook is not an enforcing login")

	enforcing := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", "http://unused", "login", "enforcing", nil),
	}, logr.Discard())
	g.Expect(enforcing.HasEnforcingLogin()).
		To(BeTrue(), "an enforcing login hook must trigger post-gate enrichment")
}

// TestEnrichAfterGate_MergesOnlyWhenEnforcingLogin pins the helper: with an
// enforcing login hook it re-resolves and merges the backend claim; with an
// advisory-only hook it does nothing and issues no backend resolve.
func TestEnrichAfterGate_MergesOnlyWhenEnforcingLogin(t *testing.T) {
	g := NewWithT(t)

	pEnf := &provisioningProvider{}
	pEnf.provisioned.Store(true)
	exEnf := newGateEnrichExchanger(t, provisioningHook(t, pEnf, "enforcing"), pEnf)
	sc := jwt.MapClaims{"sub": "alice"}
	exEnf.enrichAfterGate(sc, "alice")
	g.Expect(sc).To(HaveKey("vs_entitlements"), "enforcing login must merge the backend claim")

	pAdv := &provisioningProvider{}
	pAdv.provisioned.Store(true)
	exAdv := newGateEnrichExchanger(t, provisioningHook(t, pAdv, "advisory"), pAdv)
	sc2 := jwt.MapClaims{"sub": "alice"}
	exAdv.enrichAfterGate(sc2, "alice")
	g.Expect(sc2).ToNot(HaveKey("vs_entitlements"), "advisory login must not enrich")
	g.Expect(pAdv.resolveCalls.Load()).To(BeZero(), "advisory login must not resolve")
}

// TestLoginLocal_EnforcingGateProvisioningReflectedInFirstToken is the #206
// behaviour: a subject provisioned by the enforcing login gate is reflected in
// the FIRST minted token, not only after a later refresh.
func TestLoginLocal_EnforcingGateProvisioningReflectedInFirstToken(t *testing.T) {
	g := NewWithT(t)
	p := &provisioningProvider{}
	ex := newGateEnrichExchanger(t, provisioningHook(t, p, "enforcing"), p)

	ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entitlementsOf(t, ts.AccessToken)).To(ContainElement(jitGrant),
		"the gate provisioned the grant; the first token must carry it (#206)")
}

// TestLoginLocal_NoEnforcingHook_NoEnrichment pins the hot path: with no
// enforcing login hook, LoginLocal issues no post-gate resolve and mints exactly
// as before -- even when backing data already exists.
func TestLoginLocal_NoEnforcingHook_NoEnrichment(t *testing.T) {
	g := NewWithT(t)
	p := &provisioningProvider{}
	p.provisioned.Store(true) // data exists, but no gate to trigger a re-resolve
	ex := newGateEnrichExchanger(t, nil, p)

	ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(p.resolveCalls.Load()).To(BeZero(), "no enforcing login hook => no post-gate resolve")
	g.Expect(entitlementsOf(t, ts.AccessToken)).ToNot(ContainElement(jitGrant))
}

// TestLoginLocal_AdvisoryHook_NoEnrichment pins that an advisory login hook does
// NOT trigger enrichment (only an enforcing gate can provision).
func TestLoginLocal_AdvisoryHook_NoEnrichment(t *testing.T) {
	g := NewWithT(t)
	p := &provisioningProvider{}
	ex := newGateEnrichExchanger(t, provisioningHook(t, p, "advisory"), p)

	ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(p.resolveCalls.Load()).To(BeZero(), "advisory login hook must not trigger enrichment")
	g.Expect(entitlementsOf(t, ts.AccessToken)).ToNot(ContainElement(jitGrant))
}

// newOIDCGateEnrichExchanger mirrors newOIDCTestExchanger but injects a
// claim-mapping (folding vs_entitlements into entitlements) and a custom
// provider, so the OIDC callback path can be exercised end-to-end for #206.
func newOIDCGateEnrichExchanger(t *testing.T, d *EventDispatcher, p InternalIdentityProvider) *Exchanger {
	t.Helper()
	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	t.Cleanup(server.Close)

	cm, err := cache.NewCacheManager("", "oidc-gate-enrich-test", nil)
	if err != nil {
		t.Fatalf("new cache manager: %v", err)
	}

	cfg, err := NewConfigBuilder().WithAuthClientLoader(
		func() (map[string]AuthClient, error) { return map[string]AuthClient{}, nil },
	).WithKeyLoader(
		func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil },
	).WithOIDCClientConfigLoader(
		func() (*OIDCClientConfig, error) {
			return &OIDCClientConfig{ClientID: "foo", ClientSecret: "bar"}, nil
		},
	).WithAudience("foo").WithIssuer(server.URL).WithDevMode(true).WithCacheManager(
		cm,
	).Build(&v1alpha1.Auth{
		OIDCProvider:  &v1alpha1.OIDCProvider{OIDCProviderURL: server.URL},
		ClaimMappings: gateJITMapping(),
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	ih.Handler = MockOIDCProvider(*cfg)

	ex, err := NewExchanger(ctx, *cfg, cm, p, d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// TestExchangeToken_EnforcingGateProvisioningReflectedInFirstToken is #206 on the
// OIDC callback path: ExchangeToken never called ResolveSubjectClaims, so a
// gate-time provisioned grant could not appear until a refresh. After the fix the
// first token carries it.
func TestExchangeToken_EnforcingGateProvisioningReflectedInFirstToken(t *testing.T) {
	g := NewWithT(t)
	p := &provisioningProvider{}
	ex := newOIDCGateEnrichExchanger(t, provisioningHook(t, p, "enforcing"), p)

	oidcTokens, err := ex.ExchangeCode(context.Background(), "alice")
	g.Expect(err).ToNot(HaveOccurred())

	ts, err := ex.ExchangeToken(context.Background(), oidcTokens)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(entitlementsOf(t, ts.AccessToken)).To(ContainElement(jitGrant),
		"the OIDC callback's first token must reflect gate-time provisioning (#206)")
}

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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	. "github.com/onsi/gomega"
)

// refreshEventsStubProvider vouches for every subject, mirroring
// subjectAuditStubProvider (exchange_failure_subject_test.go). The
// refresh-token grant never calls FindInternal directly, but
// mintTokensFromSubject re-resolves roles/entitlements through
// FindInternalRolesAndEntitlements on every redemption.
type refreshEventsStubProvider struct{}

func (refreshEventsStubProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"sub": subject}, nil
}

func (refreshEventsStubProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// newRefreshEventsExchanger wires an Exchanger with the same Config/Signer
// setup as newSubjectAuditExchanger (exchange_failure_subject_test.go), plus
// the given dispatcher.
func newRefreshEventsExchanger(t *testing.T, d *EventDispatcher) *Exchanger {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
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
		Clients: map[string]AuthClient{
			"app": {ClientID: "app"},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "refresh-events-test", nil)
	if err != nil {
		t.Fatalf("new cache manager: %v", err)
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, refreshEventsStubProvider{}, d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// seedRefreshToken stores a valid, redeemable refresh-token record directly
// in the cache -- the same approach TestRedeemRefreshToken_RejectionsCarrySubject
// (exchange_failure_subject_test.go) uses, since createRefreshToken stamps
// IssuedAt/ExpiresAt itself and a raw write is the only way to control them.
func seedRefreshToken(t *testing.T, ex *Exchanger, tokenID string, claims RefreshTokenClaims) {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	if err := ex.refreshTokenCache.Set(context.Background(), tokenID, string(payload)); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
}

// TestRedeemRefreshToken_FiresSessionRefresh pins the success-emission
// insertion for the refresh_token grant: a successful redemption/rotation
// must fire the async session-refresh hook, carrying the redeemed claims'
// Subject/ClientID/Scope/AuthMethod and the newly-rotated refresh token id
// as SessionID.
func TestRedeemRefreshToken_FiresSessionRefresh(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Int32
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "session-refresh", "advisory", nil),
	}, logr.Discard())

	ex := newRefreshEventsExchanger(t, d)
	claims := RefreshTokenClaims{
		ClientID: "app", Subject: "alice", AuthMethod: AuthMethodLocal, Scope: "openid profile",
		ExpiresAt:        time.Now().Add(time.Hour).Unix(),
		OriginalIssuedAt: time.Now().Unix(),
	}
	seedRefreshToken(t, ex, "test-refresh-token", claims)

	ts, err := ex.RedeemRefreshToken(context.Background(), "test-refresh-token", "app")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ts.RefreshToken).ToNot(BeEmpty(), "a successful redemption must rotate in a new refresh token")

	g.Eventually(done, "2s").Should(Receive())
	g.Expect(hit.Load()).To(Equal(int32(1)))
}

// TestRedeemRefreshToken_RejectionDoesNotFireSessionRefresh pins the other
// half of the success-only placement: a rejected redemption (here, an
// expired token) must not fire session-refresh.
func TestRedeemRefreshToken_RejectionDoesNotFireSessionRefresh(t *testing.T) {
	g := NewWithT(t)
	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "session-refresh", "advisory", nil),
	}, logr.Discard())

	ex := newRefreshEventsExchanger(t, d)
	claims := RefreshTokenClaims{
		ClientID: "app", Subject: "alice", AuthMethod: AuthMethodLocal, Scope: "openid",
		ExpiresAt:        time.Now().Add(-time.Minute).Unix(),
		OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
	}
	seedRefreshToken(t, ex, "expired-refresh-token", claims)

	_, err := ex.RedeemRefreshToken(context.Background(), "expired-refresh-token", "app")
	g.Expect(err).To(HaveOccurred())

	g.Consistently(func() int32 { return hit.Load() }, "200ms").Should(Equal(int32(0)))
}

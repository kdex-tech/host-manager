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

// logoutEventsStubProvider mirrors the other event-hook test fixtures --
// EmitLogout never consults the identity provider, but NewExchanger requires
// one.
type logoutEventsStubProvider struct{}

func (logoutEventsStubProvider) FindInternal(subject string, _ string) (jwt.MapClaims, error) {
	return jwt.MapClaims{"sub": subject}, nil
}

func (logoutEventsStubProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// newLogoutTestExchanger wires an Exchanger with the same Config/Signer shape
// as newLoginTestExchanger (exchange_login_events_test.go) and
// newRevokeTestExchanger (exchange_revoke_test.go), plus the given
// dispatcher, so both EmitLogout's cache read and RevokeRefreshToken's are
// exercised against a real refresh-token cache.
func newLogoutTestExchanger(t *testing.T, d *EventDispatcher) *Exchanger {
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
		Clients: map[string]AuthClient{
			"app": {ClientID: "app"},
		},
	}

	cm, err := cache.NewCacheManager("", "logout-events-test", nil)
	if err != nil {
		t.Fatalf("new cache manager: %v", err)
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, logoutEventsStubProvider{}, d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// decodeJSON is a small test helper mirroring the brief's Step 1.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// TestEmitLogout_FiresLogoutEvent pins the no-refresh-token case: EmitLogout
// must still dispatch EventLogout, with an empty Subject, when there is
// nothing to decode. Logout must never be silently skipped just because the
// caller has no refresh cookie to hand it.
func TestEmitLogout_FiresLogoutEvent(t *testing.T) {
	g := NewWithT(t)
	var got atomic.Value
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p EventPayload
		_ = decodeJSON(r, &p)
		got.Store(p)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "logout", "advisory", nil),
	}, logr.Discard())

	ex := newLogoutTestExchanger(t, d)
	ex.EmitLogout(context.Background(), "", "") // no token -> subject "" still fires
	g.Eventually(done, "2s").Should(Receive())

	p, ok := got.Load().(EventPayload)
	g.Expect(ok).To(BeTrue())
	g.Expect(p.Event).To(Equal(EventLogout))
	g.Expect(p.Subject).To(BeEmpty())
}

// TestEmitLogout_DecodesRefreshTokenClaims pins the identity-recovery path:
// when refreshTokenID names a cached refresh token, EmitLogout must decode
// it and populate Subject/ClientID/Scope/AuthMethod/SessionID on the
// dispatched payload -- and must NOT consume the record (RevokeRefreshToken
// still needs it afterwards; that ordering is exercised separately by
// TestEmitLogout_DoesNotConsumeRefreshToken below).
func TestEmitLogout_DecodesRefreshTokenClaims(t *testing.T) {
	g := NewWithT(t)
	var got atomic.Value
	done := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p EventPayload
		_ = decodeJSON(r, &p)
		got.Store(p)
		_, _ = w.Write([]byte(`{"ok":true}`))
		done <- struct{}{}
	}))
	defer srv.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", srv.URL, "logout", "advisory", nil),
	}, logr.Discard())

	ex := newLogoutTestExchanger(t, d)
	ctx := context.Background()
	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid profile",
	})
	g.Expect(err).ToNot(HaveOccurred())

	ex.EmitLogout(ctx, tokenID, "")
	g.Eventually(done, "2s").Should(Receive())

	p, ok := got.Load().(EventPayload)
	g.Expect(ok).To(BeTrue())
	g.Expect(p.Event).To(Equal(EventLogout))
	g.Expect(p.Subject).To(Equal("alice"))
	g.Expect(p.ClientID).To(Equal("app"))
	g.Expect(p.Scope).To(Equal("openid profile"))
	g.Expect(p.AuthMethod).To(Equal(string(AuthMethodLocal)))
	g.Expect(p.SessionID).To(Equal(tokenID))
}

// TestEmitLogout_DoesNotConsumeRefreshToken pins the ordering LogoutPost
// depends on: EmitLogout reads the refresh-token record without deleting it,
// so a subsequent RevokeRefreshToken call (the caller's own responsibility,
// unchanged by this task) still finds -- and revokes -- it.
func TestEmitLogout_DoesNotConsumeRefreshToken(t *testing.T) {
	g := NewWithT(t)
	ex := newLogoutTestExchanger(t, nil) // nil dispatcher: EmitLogout is nil-safe on it
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	g.Expect(err).ToNot(HaveOccurred())

	ex.EmitLogout(ctx, tokenID, "")

	g.Expect(ex.RevokeRefreshToken(ctx, tokenID)).To(Succeed(),
		"RevokeRefreshToken must still find the record after EmitLogout read it")
}

// TestEmitLogout_NilExchangerIsNoOp pins the package-wide nil-safety
// invariant: a host without auth enabled has no *Exchanger, and logout must
// not panic just because there is nothing to notify.
func TestEmitLogout_NilExchangerIsNoOp(t *testing.T) {
	var ex *Exchanger
	ex.EmitLogout(context.Background(), "anything", "anything") // must not panic
}

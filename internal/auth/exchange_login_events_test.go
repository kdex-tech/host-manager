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
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	. "github.com/onsi/gomega"
)

// loginEventsStubProvider vouches for "alice" only, mirroring the fixtures
// used by the other LoginLocal tests (exchange_failure_subject_test.go).
type loginEventsStubProvider struct{}

func (loginEventsStubProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	if subject != "alice" {
		return nil, ErrGrantFailure
	}
	return jwt.MapClaims{"sub": subject}, nil
}

func (loginEventsStubProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

// newLoginTestExchanger wires an Exchanger with the same Config/Signer setup
// as newSubjectAuditExchanger (exchange_failure_subject_test.go), plus the
// given dispatcher, and a stub identity provider that vouches for "alice".
func newLoginTestExchanger(t *testing.T, d *EventDispatcher) *Exchanger {
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
			"client": {ClientID: "client"},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "login-events-test", nil)
	if err != nil {
		t.Fatalf("new cache manager: %v", err)
	}

	ex, err := NewExchanger(context.Background(), cfg, cm, loginEventsStubProvider{}, d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// TestLoginLocal_EnforcingDenyBlocksLogin pins the gate insertion: an
// enforcing login hook that denies must block LoginLocal, the returned error
// must carry the hook's reason, and no token may be minted.
func TestLoginLocal_EnforcingDenyBlocksLogin(t *testing.T) {
	g := NewWithT(t)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"risk"}`))
	}))
	defer deny.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", deny.URL, "login", "enforcing", nil),
	}, logr.Discard())

	ex := newLoginTestExchanger(t, d)
	ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).To(MatchError(ContainSubstring("risk")))
	g.Expect(ts.AccessToken).To(BeEmpty(), "a denied login must not mint a token")
}

// TestLoginLocal_AdvisoryFiresSuccess pins the success-emission insertion: a
// successful local login must fire the advisory login hook.
func TestLoginLocal_AdvisoryFiresSuccess(t *testing.T) {
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
		hookTo(t, "a", srv.URL, "login", "advisory", nil),
	}, logr.Discard())

	ex := newLoginTestExchanger(t, d)
	ts, err := ex.LoginLocal(context.Background(), "alice", "pw", "", "client", AuthMethodLocal)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ts.AccessToken).ToNot(BeEmpty())
	g.Eventually(done, "2s").Should(Receive())
	g.Expect(hit.Load()).To(Equal(int32(1)))
}

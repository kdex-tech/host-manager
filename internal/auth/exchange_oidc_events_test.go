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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	. "github.com/onsi/gomega"
	"kdex.dev/crds/api/v1alpha1"
)

// newOIDCTestExchanger mirrors newOIDCFixture (oidc_refresh_test.go) but
// plumbs a dispatcher through to NewExchanger -- newOIDCFixture always passes
// nil, which is the wiring these tests are pinning.
func newOIDCTestExchanger(t *testing.T, d *EventDispatcher) *Exchanger {
	t.Helper()

	ctx := context.Background()
	ih := &IH{}
	server := MockRunningServer(ih)
	t.Cleanup(server.Close)

	cacheManager, err := cache.NewCacheManager("", "oidc-events-test", nil)
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
		cacheManager,
	).Build(&v1alpha1.Auth{
		OIDCProvider: &v1alpha1.OIDCProvider{
			OIDCProviderURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("build config: %v", err)
	}

	ih.Handler = MockOIDCProvider(*cfg)

	ex, err := NewExchanger(ctx, *cfg, cacheManager, scopeProviderForOIDC(), d)
	if err != nil {
		t.Fatalf("new exchanger: %v", err)
	}
	return ex
}

// sampleOIDCExchange exchanges the mock IdP's "alice" authorization code for
// an OIDCExchange the way ExchangeCode's other callers in this package do
// (see newOIDCFixture's tests in oidc_refresh_test.go).
func sampleOIDCExchange(t *testing.T, ex *Exchanger) OIDCExchange {
	t.Helper()
	oidcTokens, err := ex.ExchangeCode(context.Background(), "alice")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	return oidcTokens
}

// TestExchangeToken_EnforcingDenyBlocksOIDCLogin pins the gate insertion in
// the OIDC path: an enforcing login hook that denies must block
// ExchangeToken, the returned error must carry the hook's reason, and no
// local token may be minted.
func TestExchangeToken_EnforcingDenyBlocksOIDCLogin(t *testing.T) {
	g := NewWithT(t)
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"reason":"oidc-risk"}`))
	}))
	defer deny.Close()
	d := NewEventDispatcher("h", []*httpEventHook{
		hookTo(t, "a", deny.URL, "login", "enforcing", nil),
	}, logr.Discard())

	ex := newOIDCTestExchanger(t, d)
	oidcTokens := sampleOIDCExchange(t, ex)

	ts, err := ex.ExchangeToken(context.Background(), oidcTokens)
	g.Expect(err).To(MatchError(ContainSubstring("oidc-risk")))
	g.Expect(ts.AccessToken).To(BeEmpty(), "a denied OIDC login must not mint a local token")
}

// TestExchangeToken_AdvisoryFiresSuccess pins the success-emission insertion:
// a successful OIDC exchange must fire the advisory login hook.
func TestExchangeToken_AdvisoryFiresSuccess(t *testing.T) {
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

	ex := newOIDCTestExchanger(t, d)
	oidcTokens := sampleOIDCExchange(t, ex)

	ts, err := ex.ExchangeToken(context.Background(), oidcTokens)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(ts.AccessToken).ToNot(BeEmpty())
	g.Eventually(done, "2s").Should(Receive())
	g.Expect(hit.Load()).To(Equal(int32(1)))
}

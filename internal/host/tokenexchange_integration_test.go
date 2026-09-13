/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	texE2EDomain  = "dev.knowdrive.ai"
	texE2EIssuer  = "https://" + texE2EDomain
	texE2ESubject = "alice"
	texE2EKeyID   = "tex-e2e-kid"
)

// texStubIdentityProvider grants texE2ESubject exactly one entitlement:
// functions:/v1/internal:read. It is what proves the token-exchange handler
// RE-RESOLVES the subject's entitlements at exchange time (via the real
// HostHandler -> auth.Exchanger wiring) rather than trusting whatever the
// inbound FAT happened to carry.
type texStubIdentityProvider struct{}

func (texStubIdentityProvider) FindInternal(string, string) (jwt.MapClaims, error) {
	return jwt.MapClaims{}, nil
}

func (texStubIdentityProvider) FindInternalRolesAndEntitlements(subject string) ([]string, []string, error) {
	if subject != texE2ESubject {
		return nil, nil, nil
	}
	return []string{"internal-reader"}, []string{"functions:/v1/internal:read"}, nil
}

// newTokenExchangeE2EMux builds a REAL HostHandler (mirroring
// mcp_oauth2_e2e_test.go's newE2EHarness) with two Ready functions -- a public
// function A at /v1/public and a spec.Internal function B at /v1/internal --
// and returns the mux the host itself wires /-/token onto via hh.tokenHandler.
// This drives the actual exchangeTargetAudiences() snapshot (Task 1) and the
// 3 ResourceAudiences/ExchangeTargets wiring sites in handlers.go, not a
// hand-built auth.OAuth2{ExchangeTargets: ...}.
//
// It returns the mux, the functions (for their Status.URL), and a signer that
// mints FATs with the SAME key/issuer the HostHandler's auth.Exchanger
// verifies subject_token against.
func newTokenExchangeE2EMux(t *testing.T) (mux http.Handler, functionA, functionB kdexv1alpha1.KDexFunction, fatSigner *sign.Signer, verifyKey crypto.Signer) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	ttl := time.Hour

	functionA = kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-a"},
		Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: "/v1/public"}},
		Status: kdexv1alpha1.KDexFunctionStatus{
			State: kdexv1alpha1.KDexFunctionStateReady,
			URL:   "https://fn-a.ns.svc.cluster.local",
		},
	}
	functionB = kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-b"},
		Spec:       kdexv1alpha1.KDexFunctionSpec{Internal: true, API: kdexv1alpha1.API{BasePath: "/v1/internal"}},
		Status: kdexv1alpha1.KDexFunctionStatus{
			State: kdexv1alpha1.KDexFunctionStateReady,
			URL:   "https://fn-b.ns.svc.cluster.local",
		},
	}

	// The Exchanger's OWN config is what ExchangeSubjectToken verifies the
	// inbound subject_token (FAT) against (issuer + ActivePair.Private), and
	// what it signs the exchanged token's iss with. It must match the FAT
	// signer below and equal the host issuer so the "iss == host issuer"
	// assertion holds.
	exCfg := auth.Config{
		Issuer:   texE2EIssuer,
		Audience: texE2EIssuer, // a real host sets Audience (= issuer); the FAT gate requires it
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     texE2EKeyID,
			Private:   signerKey,
		},
		TokenTTL: ttl,
	}
	ex, err := auth.NewExchanger(t.Context(), exCfg, nil, texStubIdentityProvider{}, nil)
	require.NoError(t, err)

	// authConfig drives the HTTP endpoints: ActivePair gates IsAuthEnabled
	// (so tokenHandler registers /-/token at all).
	authConfig := &auth.Config{
		ActivePair: &keys.KeyPair{
			ActiveKey: true,
			KeyId:     texE2EKeyID,
			Private:   signerKey,
		},
		TokenTTL: ttl,
	}

	hh := &HostHandler{
		log:    logr.Discard(),
		scheme: "https",
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{texE2EDomain}},
		},
		functions:     []kdexv1alpha1.KDexFunction{functionA, functionB},
		authConfig:    authConfig,
		authExchanger: ex,
	}

	m := http.NewServeMux()
	registeredPaths := map[string]ko.PathInfo{}
	hh.tokenHandler(m, registeredPaths)

	signer, err := sign.NewSigner(functionA.Status.URL, ttl, texE2EIssuer, &signerKey, texE2EKeyID, nil)
	require.NoError(t, err)

	return m, functionA, functionB, signer, signerKey
}

// TestTokenExchange_EndToEnd_InternalTarget drives the real /-/token mux: mint a
// FAT for function A, POST an RFC 8693 exchange for an INTERNAL function B's
// basePath, and assert the returned JWT is addressed to B's fatAudienceFor and
// carries the subject's re-resolved entitlements. This exercises the full
// wiring chain -- HostHandler.exchangeTargetAudiences() -> the
// ResourceAudiences:/ExchangeTargets: wiring site in tokenHandler ->
// auth.OAuth2.handleTokenExchange -> Exchanger.ExchangeSubjectToken -- rather
// than a test-only auth.OAuth2{ExchangeTargets: ...} built by hand, so it
// catches drift the isolated per-task tests cannot.
func TestTokenExchange_EndToEnd_InternalTarget(t *testing.T) {
	mux, functionA, functionB, fatSigner, verifyKey := newTokenExchangeE2EMux(t)

	// 1. Mint a FAT: aud = function A (the calling function), sub = alice.
	fat, err := fatSigner.Sign(jwt.MapClaims{"sub": texE2ESubject})
	require.NoError(t, err)

	// 2. POST /-/token through the REAL mux the HostHandler built.
	form := url.Values{
		"grant_type":         {auth.GRANT_TYPE_TOKEN_EXCHANGE},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {functionB.Spec.API.BasePath}, // "/v1/internal"
	}
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "token body=%s", rec.Body.String())

	var resp struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", resp.IssuedTokenType)
	require.NotEmpty(t, resp.AccessToken)

	// 3. Decode the exchanged access_token and verify aud/iss/entitlements.
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(resp.AccessToken, claims, func(*jwt.Token) (any, error) {
		return verifyKey.Public(), nil
	})
	require.NoError(t, err)
	require.True(t, tok.Valid)

	// aud must be fatAudienceFor(functionB) -- the SAME source of truth the
	// proxy's own FAT mint uses -- proving no drift between the two mint paths.
	assert.Equal(t, []any{fatAudienceFor(&functionB)}, claims["aud"])
	assert.Equal(t, functionB.Status.URL, fatAudienceFor(&functionB))

	assert.Equal(t, texE2EIssuer, claims["iss"])
	assert.Equal(t, texE2ESubject, claims["sub"])

	// entitlements were RE-RESOLVED for this exchange (Task 2), not copied off
	// the inbound FAT (which carried none).
	assert.Contains(t, claims["entitlements"], "functions:/v1/internal:read")

	// act records the calling function (the FAT's audience = function A).
	act, _ := claims["act"].(map[string]any)
	assert.Equal(t, functionA.Status.URL, act["sub"])

	// 4. Negative: an unknown resource is rejected as invalid_target.
	negForm := url.Values{
		"grant_type":         {auth.GRANT_TYPE_TOKEN_EXCHANGE},
		"subject_token":      {fat},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {"/v1/nope"},
	}
	negReq := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(negForm.Encode()))
	negReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	negRec := httptest.NewRecorder()
	mux.ServeHTTP(negRec, negReq)

	require.Equal(t, http.StatusBadRequest, negRec.Code, "body=%s", negRec.Body.String())
	var negBody struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(negRec.Body.Bytes(), &negBody))
	assert.Equal(t, "invalid_target", negBody.Error)
}

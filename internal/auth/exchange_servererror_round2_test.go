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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers kdex-tech/host-manager#168 review round 2's second
// finding: several infrastructure failures inside mintTokensFromCode,
// LoginLocal, LoginClient and RedeemRefreshToken's config check were
// reported as 400 invalid_grant instead of 500 server_error, telling a
// client its credential is dead when the actual cause was OUR outage.
// Round 1's tests (exchange_servererror_test.go) pin the seven original
// ErrServerError sites; these pin the newly-marked ones, PLUS the one site
// the review flagged that this fix deliberately does NOT mark (see below).

// TestRedeemAuthorizationCode_SignFailureIsServerError reaches
// mintTokensFromCode's access-token sign call: the code decrypts and
// validates cleanly (subject known, grant genuinely good), and only the
// signer itself is broken. It uses a REAL crypto.Signer of a key type
// sign.Signer's SignProjected does not handle (only RSA/ECDSA; Ed25519
// falls through to its `default: unsupported signer type` branch) rather
// than a mock, matching this file's existing style.
func TestRedeemAuthorizationCode_SignFailureIsServerError(t *testing.T) {
	ex := newSubjectAuditExchanger(t)
	ctx := context.Background()

	code, err := ex.CreateAuthorizationCode(ctx, AuthorizationCodeClaims{
		ClientID:    "app",
		RedirectURI: "https://app.example.com/cb",
		Subject:     "alice",
		Scope:       "openid",
		Exp:         time.Now().Add(time.Minute).Unix(),
	})
	require.NoError(t, err)

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	badCS := crypto.Signer(edPriv)
	badSigner, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &badCS, "bad-kid", nil)
	require.NoError(t, err)
	ex.config.Signer = *badSigner

	_, err = ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a signer that cannot produce a token is our infrastructure, not the client's grant")
	assert.Contains(t, err.Error(), "failed to sign access token")
}

// TestLoginClient_M2MNotConfiguredIsServerError and
// TestRedeemRefreshToken_StorageNotConfiguredIsServerError are cheap,
// direct pins on two of round 2's other newly-marked sites: both are pure
// deployment/config facts, not anything a client presented.

func TestLoginClient_M2MNotConfiguredIsServerError(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)
	// ActivePair deliberately left nil: IsM2MEnabled() requires it, so this
	// is the "M2M auth not configured" branch specifically, not
	// GetClient's "invalid client_id" a moment later.
	cfg := Config{Issuer: "test-iss", Audience: "test-aud", Signer: *signer}
	ex, err := NewExchanger(context.Background(), cfg, nil, rotationStubIdentityProvider{})
	require.NoError(t, err)
	require.False(t, ex.config.IsM2MEnabled())

	_, err = ex.LoginClient(context.Background(), "app", "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"M2M auth being unconfigured is our deployment fact, not the client's grant")
}

func TestRedeemRefreshToken_StorageNotConfiguredIsServerError(t *testing.T) {
	// IsRefreshTokenEnabled() gates on refreshTokenCache != nil, which
	// NewExchanger only sets when given a non-nil cache.CacheManager --
	// independent of RefreshTokenTTL. Passing nil is what actually leaves
	// refresh-token storage unconfigured (a host that never wired a cache
	// backend for it), reaching RedeemRefreshToken's very first check.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)
	cfg := Config{
		Issuer:          "test-iss",
		Audience:        "test-aud",
		Signer:          *signer,
		ActivePair:      &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
		RefreshTokenTTL: time.Hour,
		Clients:         map[string]AuthClient{"app": {ClientID: "app"}},
	}
	ex, err := NewExchanger(context.Background(), cfg, nil, rotationStubIdentityProvider{})
	require.NoError(t, err)
	require.False(t, ex.IsRefreshTokenEnabled())

	_, err = ex.RedeemRefreshToken(context.Background(), "whatever", "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"refresh tokens never having been configured is our deployment fact, not the client's grant")
}

// TestMintTokensFromSubject_MarksItsOwnInfrastructureFailures closes
// quad-findings item 8. The branch marked the three structurally identical
// infrastructure sites in mintTokensFromCode and left the three in
// mintTokensFromSubject bare, safe only because its single caller re-wrapped
// with ErrServerError -- two near-twin functions with opposite conventions,
// in the branch that introduces the convention. The classification now
// belongs to the function that knows what failed, so a second caller cannot
// silently report an outage as invalid_grant.
//
// This calls mintTokensFromSubject DIRECTLY, standing in for that future
// second caller: against the unfixed code the error carries no sentinel and
// this fails.
func TestMintTokensFromSubject_MarksItsOwnInfrastructureFailures(t *testing.T) {
	ex := newRotationTestExchanger(t)

	// Same idiom as TestRedeemAuthorizationCode_SignFailureIsServerError:
	// a real signer of a key type SignScoped does not handle.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	badCS := crypto.Signer(edPriv)
	badSigner, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &badCS, "bad-kid", nil)
	require.NoError(t, err)
	ex.config.Signer = *badSigner

	ts, err := ex.mintTokensFromSubject("alice", "app", "openid", AuthMethodLocal)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"mintTokensFromSubject must mark its own infrastructure failures (quad-findings item 8), "+
			"not rely on one caller re-wrapping them")
	assert.Equal(t, "alice", ts.Subject,
		"#158 subject attribution on the failure path is unchanged")
}

// httpLookupIdentityAdapter adapts the internal Lookup interface (the same
// one lookup_http_test.go exercises directly) to the InternalIdentityProvider
// shape Exchanger.sp expects, reproducing exactly what
// scopeProvider.FindInternal (roles.go) does for a single configured
// lookup: propagate the lookup's error as-is, with no wrapping of its own.
type httpLookupIdentityAdapter struct {
	lookup Lookup
}

func (a httpLookupIdentityAdapter) FindInternal(subject, password string) (jwt.MapClaims, error) {
	_, claims, err := a.lookup.FindInternal(subject, password)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (httpLookupIdentityAdapter) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newLoginLocalExchanger(t *testing.T, sp InternalIdentityProvider) *Exchanger {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cs := crypto.Signer(priv)
	signer, err := sign.NewSigner("test-aud", time.Hour, "test-iss", &cs, "test-kid", nil)
	require.NoError(t, err)
	cfg := Config{
		Issuer:     "test-iss",
		Audience:   "test-aud",
		Signer:     *signer,
		ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: cs},
	}
	ex, err := NewExchanger(context.Background(), cfg, nil, sp)
	require.NoError(t, err)
	return ex
}

// TestLoginLocal_IdentityLookupFailureDefaultsClosedNotServerError is the
// "highest-value path" #168 round 2 asked to be covered -- but it pins the
// OPPOSITE of errors.Is(err, ErrServerError): a deliberate decision not to
// mark this site, documented on the call site in exchange.go and repeated
// here. httpLookup.FindInternal (lookup_http.go) folds a transport failure
// (dial/timeout/decode) and an ordinary "backend says this password is
// wrong" rejection into the IDENTICAL `error` return -- there is no
// sentinel or type distinguishing them at this call site. Marking it
// ErrServerError would turn every routine bad-password ROPC attempt into
// 500 server_error, which is a worse regression than the one #168 round 2
// is fixing. Both subtests below confirm the actually-safe outcome
// instead: round 1's default-closed classifier (neither sentinel -> 400
// invalid_grant, fixed generic description, cause logged only) already
// prevents the disclosure the review was concerned about, without that
// misclassification cost.
func TestLoginLocal_IdentityLookupFailureDefaultsClosedNotServerError(t *testing.T) {
	t.Run("transport failure (the httpLookup dial case the review cited)", func(t *testing.T) {
		lookup, err := NewHTTPLookup(makeHTTPLookupSecret(t,
			"http://127.0.0.1:1/", // port 1 is reserved and closed -- a real dial failure
			"500",
			make([]byte, 32),
		))
		require.NoError(t, err)
		ex := newLoginLocalExchanger(t, httpLookupIdentityAdapter{lookup: lookup})

		_, err = ex.LoginLocal(context.Background(), "alice", "whatever", "", "app", AuthMethodLocal)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"deliberately unmarked -- see the comment on this call site in exchange.go")
		assert.False(t, errors.Is(err, ErrGrantFailure))

		status, code, desc := oauthErrorForRedemption(err)
		assert.Equal(t, http.StatusBadRequest, status)
		assert.Equal(t, "invalid_grant", code)
		assert.Equal(t, genericGrantFailureDescription, desc,
			"the safe default must apply: fixed description, not the dial error's own text")
		assert.NotContains(t, desc, "127.0.0.1",
			"the dial failure's target address must never reach the client")
	})

	t.Run("backend-rejected credentials (an ordinary wrong password)", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok": false, "reason": "invalid_credentials"}`))
		}))
		defer srv.Close()

		lookup, err := NewHTTPLookup(makeHTTPLookupSecret(t, srv.URL, "2000", make([]byte, 32)))
		require.NoError(t, err)
		ex := newLoginLocalExchanger(t, httpLookupIdentityAdapter{lookup: lookup})

		_, err = ex.LoginLocal(context.Background(), "alice", "wrong", "", "app", AuthMethodLocal)
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"an ordinary wrong-password rejection must never become 500 server_error -- "+
				"this is the exact regression blanket-marking this call site would cause")
	})
}

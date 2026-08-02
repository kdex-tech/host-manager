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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// subjectAuditStubProvider vouches for every username except "nobody", so
// LoginLocal's post-vouch failure paths can be reached.
type subjectAuditStubProvider struct{}

func (subjectAuditStubProvider) FindInternal(subject, _ string) (jwt.MapClaims, error) {
	if subject == "nobody" {
		return nil, assert.AnError
	}
	return jwt.MapClaims{"sub": subject}, nil
}

func (subjectAuditStubProvider) FindInternalRolesAndEntitlements(string) ([]string, []string, error) {
	return nil, nil, nil
}

func newSubjectAuditExchanger(t *testing.T) *Exchanger {
	t.Helper()

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
		MaxSessionAge:   time.Hour,
		Clients: map[string]AuthClient{
			"app":   {ClientID: "app", RedirectURIs: []string{"https://app.example.com/cb"}},
			"other": {ClientID: "other"},
			"pkce": {
				ClientID:     "pkce",
				RedirectURIs: []string{"https://app.example.com/cb"},
				RequirePKCE:  true,
			},
			"m2m": {
				ClientID:      "m2m",
				ClientSecret:  "s3cret",
				AllowedScopes: []string{"openid"},
			},
		},
	}
	cfg.OIDC.BlockKey = "0123456789abcdef0123456789abcdef"

	cm, err := cache.NewCacheManager("", "subject-audit-test", nil)
	require.NoError(t, err)

	ex, err := NewExchanger(context.Background(), cfg, cm, subjectAuditStubProvider{})
	require.NoError(t, err)
	return ex
}

// TestRedeemAuthorizationCode_RejectionsCarrySubject pins #158 for the
// authorization_code grant.
//
// The code is a JWE we minted ourselves, so once it decrypts the subject is
// known AND server-vouched — a caller cannot assert it. Every rejection after
// that point used to return a bare TokenSet{}, so the token endpoint logged
// `"subject": ""` for the entire class. The replay case matters most: an
// already-consumed code is a security-relevant event (RFC 6749 §10.5) and was
// logged without any idea whose code was replayed.
func TestRedeemAuthorizationCode_RejectionsCarrySubject(t *testing.T) {
	ctx := context.Background()

	newCode := func(t *testing.T, ex *Exchanger, mutate func(*AuthorizationCodeClaims)) string {
		t.Helper()
		claims := AuthorizationCodeClaims{
			ClientID:    "app",
			RedirectURI: "https://app.example.com/cb",
			Subject:     "alice",
			Scope:       "openid",
			Exp:         time.Now().Add(time.Minute).Unix(),
		}
		if mutate != nil {
			mutate(&claims)
		}
		code, err := ex.CreateAuthorizationCode(ctx, claims)
		require.NoError(t, err)
		return code
	}

	challengeFor := func(verifier string) string {
		h := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(h[:])
	}

	for _, tc := range []struct {
		name     string
		redeem   func(t *testing.T, ex *Exchanger) (TokenSet, error)
		wantErrs []string
	}{
		{
			name: "expired code",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, func(c *AuthorizationCodeClaims) {
					c.Exp = time.Now().Add(-time.Minute).Unix()
				})
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
			},
			wantErrs: []string{"expired"},
		},
		{
			name: "client_id mismatch",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, nil)
				return ex.RedeemAuthorizationCode(ctx, code, "other", "https://app.example.com/cb", "")
			},
			wantErrs: []string{"client_id mismatch"},
		},
		{
			name: "redirect_uri mismatch",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, nil)
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://evil.example.com/cb", "")
			},
			wantErrs: []string{"redirect_uri mismatch"},
		},
		{
			name: "PKCE required but absent",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, func(c *AuthorizationCodeClaims) { c.ClientID = "pkce" })
				return ex.RedeemAuthorizationCode(ctx, code, "pkce", "https://app.example.com/cb", "")
			},
			wantErrs: []string{"PKCE"},
		},
		{
			name: "code_verifier missing",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, func(c *AuthorizationCodeClaims) {
					c.CodeChallenge = challengeFor("the-verifier")
					c.CodeChallengeMethod = PKCE_METHOD_S256
				})
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
			},
			wantErrs: []string{"code_verifier"},
		},
		{
			name: "invalid code_verifier",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, func(c *AuthorizationCodeClaims) {
					c.CodeChallenge = challengeFor("the-verifier")
					c.CodeChallengeMethod = PKCE_METHOD_S256
				})
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "wrong-verifier")
			},
			wantErrs: []string{"code_verifier"},
		},
		{
			name: "downgraded code_challenge_method",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, func(c *AuthorizationCodeClaims) {
					c.CodeChallenge = "plain-challenge"
					c.CodeChallengeMethod = "plain"
				})
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "plain-challenge")
			},
			wantErrs: []string{"code_challenge_method"},
		},
		{
			name: "replayed code",
			redeem: func(t *testing.T, ex *Exchanger) (TokenSet, error) {
				code := newCode(t, ex, nil)
				_, err := ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
				require.NoError(t, err, "first redemption must succeed")
				return ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
			},
			wantErrs: []string{"consumed"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newSubjectAuditExchanger(t)
			ts, err := tc.redeem(t, ex)

			require.Error(t, err, "this case must be a rejection")
			for _, want := range tc.wantErrs {
				assert.Contains(t, err.Error(), want)
			}
			assert.Equal(t, "alice", ts.Subject,
				"rejection must still report the subject so the token endpoint can attribute it (#158)")

			// A populated Subject must never be mistaken for success.
			assert.Empty(t, ts.AccessToken, "a rejection must not return an access token")
			assert.Empty(t, ts.IDToken, "a rejection must not return an id token")
			assert.Empty(t, ts.RefreshToken, "a rejection must not return a refresh token")
		})
	}
}

// TestRedeemRefreshToken_RejectionsCarrySubject pins #158 for the
// refresh_token grant, for the rejections that happen after the stored record
// has been read (so the subject is known).
func TestRedeemRefreshToken_RejectionsCarrySubject(t *testing.T) {
	ctx := context.Background()

	// Seed the cache directly: createRefreshToken stamps IssuedAt/ExpiresAt
	// itself, so crafting expired / long-lived records needs a raw write.
	seed := func(t *testing.T, ex *Exchanger, claims RefreshTokenClaims) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		require.NoError(t, err)
		tokenID := "test-refresh-token"
		require.NoError(t, ex.refreshTokenCache.Set(ctx, tokenID, string(payload)))
		return tokenID
	}

	for _, tc := range []struct {
		name     string
		claims   RefreshTokenClaims
		redeemAs string
		wantErr  string
	}{
		{
			name: "expired refresh token",
			claims: RefreshTokenClaims{
				ClientID: "app", Subject: "alice", AuthMethod: AuthMethodLocal,
				ExpiresAt:        time.Now().Add(-time.Minute).Unix(),
				OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
			},
			redeemAs: "app",
			wantErr:  "expired",
		},
		{
			name: "absolute session timeout",
			claims: RefreshTokenClaims{
				ClientID: "app", Subject: "alice", AuthMethod: AuthMethodLocal,
				ExpiresAt:        time.Now().Add(time.Hour).Unix(),
				OriginalIssuedAt: time.Now().Add(-48 * time.Hour).Unix(),
			},
			redeemAs: "app",
			wantErr:  "absolute timeout",
		},
		{
			name: "issued to a different client",
			claims: RefreshTokenClaims{
				ClientID: "app", Subject: "alice", AuthMethod: AuthMethodLocal,
				ExpiresAt:        time.Now().Add(time.Hour).Unix(),
				OriginalIssuedAt: time.Now().Unix(),
			},
			redeemAs: "other",
			wantErr:  "not issued to this client",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newSubjectAuditExchanger(t)
			tokenID := seed(t, ex, tc.claims)

			ts, err := ex.RedeemRefreshToken(ctx, tokenID, tc.redeemAs)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.Equal(t, "alice", ts.Subject,
				"rejection must still report the subject (#158)")
			assert.Empty(t, ts.AccessToken, "a rejection must not return an access token")
		})
	}
}

// TestRedeemRefreshToken_UnknownTokenHasNoSubject pins the documented limit of
// #158, and is the case in the original report
// (`refresh token not found or expired`).
//
// Refresh tokens are opaque — `rand.Text()` keyed against a cache record — so
// a miss leaves nothing to attribute. This is asserted rather than left
// implicit so that anyone who later makes it attributable (consumption
// tombstones, a structured token) has to come here and change a test that
// states why it was empty.
func TestRedeemRefreshToken_UnknownTokenHasNoSubject(t *testing.T) {
	ex := newSubjectAuditExchanger(t)

	ts, err := ex.RedeemRefreshToken(context.Background(), "never-issued", "app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found or expired")
	assert.Empty(t, ts.Subject,
		"an unknown refresh token carries no recoverable subject; see #158 for the options")
}

// TestLoginClient_SubjectOnlyAfterClientAuthenticates pins the deliberate
// asymmetry in #158: client_credentials' subject IS the client, so it is
// reported once the client has authenticated — but NOT before. An
// unauthenticated caller can assert any client_id, and an audit log that
// cannot distinguish an asserted identity from a verified one is worse than
// one that stays silent.
func TestLoginClient_SubjectOnlyAfterClientAuthenticates(t *testing.T) {
	ctx := context.Background()

	t.Run("post-authentication failure carries the client as subject", func(t *testing.T) {
		ex := newSubjectAuditExchanger(t)
		// Authenticates cleanly, then trips the client's AllowedScopes.
		ts, err := ex.LoginClient(ctx, "m2m", "s3cret", "openid forbidden-scope")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not allowed")
		assert.Equal(t, "m2m", ts.Subject,
			"an authenticated client is a vouched subject (#158)")
	})

	t.Run("bad secret reports no subject", func(t *testing.T) {
		ex := newSubjectAuditExchanger(t)
		ts, err := ex.LoginClient(ctx, "m2m", "wrong-secret", "openid")
		require.Error(t, err)
		assert.Empty(t, ts.Subject,
			"a caller that failed authentication must not have its asserted client_id logged as a subject (#158)")
	})

	t.Run("unknown client reports no subject", func(t *testing.T) {
		ex := newSubjectAuditExchanger(t)
		ts, err := ex.LoginClient(ctx, "does-not-exist", "whatever", "openid")
		require.Error(t, err)
		assert.Empty(t, ts.Subject,
			"an unregistered client_id is caller-asserted and must not be logged as a subject (#158)")
	})
}

// TestLoginLocal_SubjectOnlyAfterCredentialsVouch covers the password grant:
// once the credential store has vouched, later failures report the subject;
// a credential rejection does not (the handler logs `username` separately,
// which is the only identity handle that exists at that point).
func TestLoginLocal_SubjectOnlyAfterCredentialsVouch(t *testing.T) {
	ctx := context.Background()

	t.Run("post-vouch failure carries the subject", func(t *testing.T) {
		ex := newSubjectAuditExchanger(t)
		// Credentials vouch, then the unsupported auth method trips.
		ts, err := ex.LoginLocal(ctx, "alice", "pw", "openid", "app", AuthMethod("bogus"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported local login auth method")
		assert.Equal(t, "alice", ts.Subject,
			"the credential store vouched for this identity before the failure (#158)")
	})

	t.Run("credential rejection reports no subject", func(t *testing.T) {
		ex := newSubjectAuditExchanger(t)
		ts, err := ex.LoginLocal(ctx, "nobody", "pw", "openid", "app", AuthMethodOAuth2)
		require.Error(t, err)
		assert.Empty(t, ts.Subject,
			"nothing vouched for this identity, so there is no subject to report (#158)")
	})
}

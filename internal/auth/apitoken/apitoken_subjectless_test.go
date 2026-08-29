/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package apitoken

import (
	"context"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func subjectlessTokenManager(t *testing.T) *TokenManager {
	t.Helper()
	cm, err := cache.NewCacheManager("", "apitoken-subjectless-test", nil)
	require.NoError(t, err)
	tm, err := NewTokenManager("test-issuer", GenerateDevmodeKeyPair(),
		cm.GetCache("revocation", cache.CacheOptions{}))
	require.NoError(t, err)
	return tm
}

// The PASETO half of "a subject-less credential is not a supported
// configuration". A PAT is a credential, and every consumer of one turns
// ValidateToken's success into an identity (hostPATIdentity, the proxy's PAT
// bridge) or into an answer about one (/-/apitokens/verify), so a token that
// names nobody must not exist and must not be honoured if it does.
func TestMintStatelessKeyRefusesASubjectlessCredential(t *testing.T) {
	tm := subjectlessTokenManager(t)

	token, err := tm.MintStatelessKey("https://a.example", "", "read", "scope", time.Hour)

	require.Error(t, err)
	assert.ErrorIs(t, err, sign.ErrSubjectlessCredential)
	assert.Empty(t, token, "no PAT may be minted for a credential that names nobody")
}

// The validation end. paseto.Token.GetSubject already rejects a MISSING `sub`
// -- what it cannot see is a PRESENT-but-empty one, which is exactly the shape
// MintStatelessKey produced before the guard above existed. Such tokens are
// still on the wire until they expire, so the refusal has to be at both ends.
//
// The token below is minted around MintStatelessKey, directly against the
// manager's own signing key, so it is a genuinely valid PASETO for this host
// in every respect except the subject.
func TestValidateTokenRefusesAnEmptySubject(t *testing.T) {
	tm := subjectlessTokenManager(t)

	now := time.Now()
	tok := paseto.NewToken()
	tok.SetAudience("https://a.example")
	tok.SetExpiration(now.Add(time.Hour))
	tok.SetIssuedAt(now)
	tok.SetIssuer("test-issuer")
	tok.SetJti(GenerateJTI("https://a.example", "", "read"))
	tok.SetNotBefore(now)
	tok.SetSubject("")
	tok.SetString("act", "read")
	tok.SetString("scp", "scope")
	tok.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))
	legacy := tm.wrap(tok.V4Sign(*tm.activeKey.SecretKey, nil))

	data, err := tm.ValidateToken(context.Background(), legacy, "https://a.example")

	require.Error(t, err, "a legacy PAT that names nobody must not validate")
	assert.ErrorIs(t, err, sign.ErrSubjectlessCredential)
	assert.Nil(t, data)
}

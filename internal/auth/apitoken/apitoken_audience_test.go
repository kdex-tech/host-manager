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
	"strings"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateToken_EnforcesAudience pins the fix for
// kdex-tech/host-manager#69. Pre-fix ValidateToken added IssuedBy,
// NotExpired, and ValidAt rules but no ForAudience — a token minted
// for service A validated as legitimate when presented to service B,
// because nothing compared the token's aud against an expected
// audience. Consumers of ValidateToken (e.g. the /-/apitokens/verify
// handler) implicitly trusted the success signal.
//
// Post-fix, ValidateToken takes an expectedAudience parameter:
// non-empty enforces, empty preserves the legitimate "extract claims
// without authenticating" path used by the revocation handler.
func TestValidateToken_EnforcesAudience(t *testing.T) {
	ctx := context.Background()
	cm, err := cache.NewCacheManager("", "test-host", nil)
	require.NoError(t, err)
	tm, err := NewTokenManager("test-issuer", GenerateDevmodeKeyPair(), cm.GetCache("revocation", cache.CacheOptions{}))
	require.NoError(t, err)

	signed, err := tm.MintStatelessKey("https://a.example", "alice", "read", "scope", time.Hour)
	require.NoError(t, err)

	t.Run("wrong expected audience is rejected", func(t *testing.T) {
		_, err := tm.ValidateToken(ctx, signed, "https://b.example")
		require.Error(t, err, "token minted for aud=A must NOT validate for aud=B (#69)")
		msg := strings.ToLower(err.Error())
		assert.True(t,
			strings.Contains(msg, "audience") ||
				strings.Contains(msg, "intended for") ||
				strings.Contains(msg, "aud "),
			"rejection error should mention audience mismatch; got: %q", err.Error())
	})

	t.Run("matching expected audience succeeds", func(t *testing.T) {
		data, err := tm.ValidateToken(ctx, signed, "https://a.example")
		require.NoError(t, err, "token minted for aud=A must validate for aud=A")
		assert.Equal(t, "alice", data.Subject)
	})

	t.Run("empty expected audience skips check (revocation flow)", func(t *testing.T) {
		// Revocation handlers extract a token's subject regardless of
		// audience — that token is being INSPECTED, not used for
		// authentication on the current request. Empty expectedAudience
		// preserves that legitimate use case.
		data, err := tm.ValidateToken(ctx, signed, "")
		require.NoError(t, err, "empty expectedAudience must skip audience check")
		assert.Equal(t, "alice", data.Subject)
	})
}

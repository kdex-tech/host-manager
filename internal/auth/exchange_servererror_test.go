package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRedeemRefreshToken_GrantFailuresAreNotServerErrors pins the #168
// classification boundary. A dead or mismatched grant is the CLIENT's
// problem and maps to 400 invalid_grant; it must never be reported as
// ErrServerError, or a client would be told to retry rather than
// re-authorize.
func TestRedeemRefreshToken_GrantFailuresAreNotServerErrors(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	t.Run("unknown token", func(t *testing.T) {
		_, err := ex.RedeemRefreshToken(ctx, "never-issued", "app")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"an unknown refresh token is a grant failure (400 invalid_grant), not a server error")
	})

	t.Run("client mismatch", func(t *testing.T) {
		tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
			AuthMethod: AuthMethodLocal,
			ClientID:   "app",
			Subject:    "alice",
			Scope:      "openid",
		})
		require.NoError(t, err)

		_, err = ex.RedeemRefreshToken(ctx, tokenID, "some-other-client")
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrServerError),
			"a client-id mismatch is a grant failure (400 invalid_grant), not a server error")
	})
}

// TestErrServerError_IsDetectable pins that the sentinel survives wrapping,
// which is the whole mechanism Task 4's handler depends on.
func TestErrServerError_IsDetectable(t *testing.T) {
	wrapped := errors.Join(ErrServerError, errors.New("cache unreachable"))
	assert.True(t, errors.Is(wrapped, ErrServerError))
	assert.False(t, errors.Is(errors.New("refresh token not found or expired"), ErrServerError))
}

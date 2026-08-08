package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/kdex-tech/host-manager/internal/cache"
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

// failingCache decorates a real cache.Cache, forcing exactly the named
// operation(s) to fail while delegating every other method to the embedded
// cache unchanged. It exists so tests can reach the infrastructure-failure
// branches inside RedeemRefreshToken / RedeemAuthorizationCode -- a real
// cache read/write failure, not just a miss -- without reimplementing the
// whole cache.Cache interface.
type failingCache struct {
	cache.Cache
	failGetAndDelete bool
	failSet          bool
}

var errCacheBackendDown = errors.New("cache backend unreachable")

func (f failingCache) GetAndDelete(ctx context.Context, key string) (string, bool, bool, error) {
	if f.failGetAndDelete {
		return "", false, false, errCacheBackendDown
	}
	return f.Cache.GetAndDelete(ctx, key)
}

func (f failingCache) Set(ctx context.Context, key, value string, opts ...cache.SetOption) error {
	if f.failSet {
		return errCacheBackendDown
	}
	return f.Cache.Set(ctx, key, value, opts...)
}

// TestRedeemRefreshToken_CacheReadFailureIsServerError reaches the wrap
// site at the top of RedeemRefreshToken directly: a GetAndDelete that
// fails (not merely misses) is OUR cache being unreachable, not a bad
// grant. This is the exact scenario ErrServerError exists to distinguish
// from "refresh token not found or expired" -- and it would fail if that
// wrap site regressed from `%w` to `%v` on ErrServerError.
func TestRedeemRefreshToken_CacheReadFailureIsServerError(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ex.refreshTokenCache = failingCache{Cache: ex.refreshTokenCache, failGetAndDelete: true}

	_, err := ex.RedeemRefreshToken(context.Background(), "whatever-token-id", "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a cache read failure is OUR infrastructure, not a bad grant")
	assert.Contains(t, err.Error(), "failed to read refresh token")
}

// TestRedeemRefreshToken_MalformedStoredRecordIsServerError reaches the
// json.Unmarshal wrap site: a stored record WE wrote failing to parse is
// our bug, not the client's presented token.
func TestRedeemRefreshToken_MalformedStoredRecordIsServerError(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()
	tokenID := "corrupt-record"
	require.NoError(t, ex.refreshTokenCache.Set(ctx, tokenID, "not-json"))

	_, err := ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a stored record WE wrote failing to parse is our bug, not the client's")
	assert.Contains(t, err.Error(), "failed to parse refresh token")
}

// TestRedeemRefreshToken_RotateFailureIsServerError reaches the rotate wrap
// site: the read/parse/mint steps all succeed against a real cache and a
// real signer (proven end-to-end by
// TestRedeemRefreshToken_ConcurrentRedemptionsHaveSingleWinner in
// exchange_rotation_race_test.go), and only the final persistence write is
// forced to fail.
func TestRedeemRefreshToken_RotateFailureIsServerError(t *testing.T) {
	ex := newRotationTestExchanger(t)
	ctx := context.Background()

	tokenID, err := ex.createRefreshToken(ctx, RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	// GetAndDelete still hits the real backing cache -- only the rotate
	// write is forced to fail -- so the seeded token above is consumed
	// normally and mintTokensFromSubject succeeds before rotation trips.
	ex.refreshTokenCache = failingCache{Cache: ex.refreshTokenCache, failSet: true}

	_, err = ex.RedeemRefreshToken(ctx, tokenID, "app")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"failing to persist the rotated refresh token is our infrastructure, not the client's grant")
	assert.Contains(t, err.Error(), "failed to rotate refresh token")
}

// TestRedeemAuthorizationCode_NilExchangerIsServerError reaches the `e ==
// nil` guard: an unconfigured Exchanger is OUR misconfiguration, not a bad
// grant, so it must classify as ErrServerError.
func TestRedeemAuthorizationCode_NilExchangerIsServerError(t *testing.T) {
	var ex *Exchanger
	_, err := ex.RedeemAuthorizationCode(context.Background(), "any-code", "app", "https://app.example.com/cb", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"a nil Exchanger means auth isn't configured at all -- that is OUR misconfiguration, not a bad grant")
}

// TestRedeemAuthorizationCode_MalformedDecryptedClaimsIsServerError reaches
// the claims-unmarshal wrap site by hand-crafting a JWE that decrypts
// cleanly with the Exchanger's own block key -- proving it is a record WE
// minted -- but whose plaintext is not valid JSON. This mirrors the
// encrypt half of CreateAuthorizationCode without ever producing valid
// claims, deliberately excluding the "failed to parse auth code" and
// "failed to decrypt auth code" sites just above it, which describe the
// CLIENT's presented code failing and are correctly left unwrapped.
func TestRedeemAuthorizationCode_MalformedDecryptedClaimsIsServerError(t *testing.T) {
	ex := newSubjectAuditExchanger(t)

	key := sha256.Sum256([]byte(ex.config.OIDC.BlockKey))
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key[:]}, nil)
	require.NoError(t, err)
	object, err := encrypter.Encrypt([]byte("not-json"))
	require.NoError(t, err)
	code, err := object.CompactSerialize()
	require.NoError(t, err)

	_, err = ex.RedeemAuthorizationCode(context.Background(), code, "app", "https://app.example.com/cb", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"the code decrypted with our own key, so malformed claims are our bug, not the client's")
	assert.Contains(t, err.Error(), "failed to unmarshal auth code claims")
}

// TestRedeemAuthorizationCode_ConsumptionCheckFailureIsServerError reaches
// the single-use consumption-check wrap site: the code was minted normally
// (writing its JTI through the real backing cache), and only the
// redemption-time consumption lookup is forced to fail.
func TestRedeemAuthorizationCode_ConsumptionCheckFailureIsServerError(t *testing.T) {
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

	ex.authCodeCache = failingCache{Cache: ex.authCodeCache, failGetAndDelete: true}

	_, err = ex.RedeemAuthorizationCode(ctx, code, "app", "https://app.example.com/cb", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"failing to check whether a code was already consumed is our infrastructure, not the client's grant")
	assert.Contains(t, err.Error(), "failed to check auth code consumption")
}

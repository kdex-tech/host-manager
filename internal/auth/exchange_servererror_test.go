package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/sign"
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

// ---------------------------------------------------------------------------
// Merged from exchange_servererror_round2_test.go (#174). That file was named
// after a REVIEW ITERATION rather than a behaviour, so a future maintainer had
// no way to know which file new server-error tests belonged in. These cover the
// same property as the tests above: which failures are classified as OURS.
// ---------------------------------------------------------------------------

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

	ts, err := ex.mintTokensFromSubject("alice", "app", "openid", AuthMethodLocal, nil)
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

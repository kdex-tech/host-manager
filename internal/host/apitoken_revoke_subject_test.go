package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// POST /-/apitokens/revoke {sub, all: true} revokes the subject on this host
// as of now: every API token for it on any audience, including keys the
// caller never recorded, and no credential that authenticated before it can
// mint another. It is authorized exactly like a metadata revoke. See
// kdex-tech/host-manager#257.

func TestApitokenRevoke_AllRevokesEveryTokenForTheSubject(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	recorded, err := tm.MintStatelessKey("aud", "alice", "key-1", "", time.Hour)
	require.NoError(t, err)
	unrecorded, err := tm.MintStatelessKey("other-aud", "alice", "minted-directly", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "purger", []any{"apitokens:alice:revoke-any"}, RevokeRequest{Sub: "alice", All: true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	_, err = tm.ValidateToken(t.Context(), recorded, "aud")
	assert.Error(t, err, "recorded")
	_, err = tm.ValidateToken(t.Context(), unrecorded, "other-aud")
	assert.Error(t, err, "unrecorded, on another audience")
}

func TestApitokenRevoke_AllForYourselfNeedsOnlyTheSelfServiceGrant(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	token, err := tm.MintStatelessKey("aud", "alice", "key-1", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Sub: "alice", All: true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	_, err = tm.ValidateToken(t.Context(), token, "aud")
	assert.Error(t, err)
}

func TestApitokenRevoke_AllForAnotherSubjectNeedsRevokeAny(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	token, err := tm.MintStatelessKey("aud", "admin", "key-1", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Sub: "admin", All: true})
	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())

	_, err = tm.ValidateToken(t.Context(), token, "aud")
	assert.NoError(t, err, "a denied revoke-all revokes nothing")
}

// all names a subject on every audience: a request that also names an aud,
// an act or a token reads as something narrower, so it is refused.
func TestApitokenRevoke_AllRefusesNarrowerRequests(t *testing.T) {
	hh, _ := crossSubjectHost(t)
	for name, req := range map[string]RevokeRequest{
		"without sub": {All: true},
		"with aud":    {Audience: "aud", Sub: "alice", All: true},
		"with act":    {Sub: "alice", Action: "key-1", All: true},
		"with token":  {Sub: "alice", Token: "v4.public.x", All: true},
	} {
		rr := revokeAs(t, hh, "alice", selfServiceGrant, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code, name)
	}
}

// A session that authenticated before the subject was revoked cannot mint
// the subject a fresh key; one that authenticated afterwards (a re-signup)
// can.
func TestApitokenMint_RefusedForACredentialFromBeforeTheSubjectWasRevoked(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	mintWithIAT := func(iat time.Time) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		body, err := json.Marshal(MintRequest{Audience: "aud", Sub: "alice", Action: "key-2", TTL: "1h"})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewReader(body))
		// iat as a parsed JWT carries it: seconds, as a float64.
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
			"sub": "alice", "entitlements": selfServiceGrant, "iat": float64(iat.Unix()),
		}))
		hh.apitokenMintHandler(rr, req)
		return rr
	}
	stale := time.Now().Add(-time.Minute)
	require.NoError(t, tm.RevokeSubject(t.Context(), "alice", 0))

	assert.Equal(t, http.StatusForbidden, mintWithIAT(stale).Code)
	assert.Equal(t, http.StatusOK, mintWithIAT(time.Now().Add(2*time.Second)).Code)

	// A credential with no issue time is not taken as one from after the
	// revocation.
	rr := httptest.NewRecorder()
	body, err := json.Marshal(MintRequest{Audience: "aud", Sub: "alice", Action: "key-3", TTL: "1h"})
	require.NoError(t, err)
	hh.apitokenMintHandler(rr, callerCtx(httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewReader(body)), "alice", selfServiceGrant))
	assert.Equal(t, http.StatusForbidden, rr.Code)

	// Minting for another subject is that principal's own act.
	rr = mintAs(t, hh, "ops", []any{"apitokens:alice:impersonate"}, "alice")
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

// A capability carries the caller's subject and a fresh iat, so minting one
// from a credential that predates the subject's revocation would launder the
// credential past the cutoff: the REST and MCP surfaces both refuse it.
func TestCapabilityMint_RefusedForACredentialFromBeforeTheSubjectWasRevoked(t *testing.T) {
	hh := urlMintHandler(t)
	_, tm := crossSubjectHost(t)
	hh.authConfig.TokenManager = tm
	require.NoError(t, tm.RevokeSubject(t.Context(), "alice", 0))
	held := []string{"functions:/api/v1/files:read"}
	withIAT := func(r *http.Request, iat time.Time) *http.Request {
		return r.WithContext(auth.SetAuthContext(r.Context(), auth.AuthContext{
			"sub": "alice", "entitlements": held, "iat": float64(iat.Unix()),
		}))
	}

	for name, tc := range map[string]struct {
		iat  time.Time
		want int
	}{
		"stale": {time.Now().Add(-time.Minute), http.StatusForbidden},
		"fresh": {time.Now().Add(2 * time.Second), http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodPost, capabilitiesMintPath, mintReq(t, MintTokenRequest{Entitlements: held}))
		rw := httptest.NewRecorder()
		hh.capabilityMintHandler(rw, withIAT(r, tc.iat))
		assert.Equal(t, tc.want, rw.Code, "REST %s: %s", name, rw.Body.String())
	}

	rw := httptest.NewRecorder()
	r := withIAT(httptest.NewRequest(http.MethodPost, "/mcp", nil), time.Now().Add(-time.Minute))
	hh.writeMintTokenRPC(rw, r, json.RawMessage(`1`), "alice", held, MintTokenRequest{Entitlements: held})
	assert.Contains(t, rw.Body.String(), `"isError":true`, "MCP stale")
	assert.Contains(t, rw.Body.String(), "revoked")
}

// contextRecordingChecker keeps the auth context that reaches the gate.
type contextRecordingChecker struct {
	mockAuthChecker
	seen auth.AuthContext
}

func (c *contextRecordingChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	if ac, ok := auth.GetAuthContext(ctx); ok {
		c.seen = ac
	}
	return c.mockAuthChecker.GetParsedEntitlements(ctx)
}

// The proxy's API-token identity carries the token's iat, like the host's, so
// a key minted after a subject revocation (a re-signup's MCP client) is not
// taken for a credential from before it by mint_token.
func TestProxy_APITokenIdentityCarriesIssuedAt(t *testing.T) {
	fn := apiKeySecuredFunction("/v1/api", true)
	idp := stubInternalIdentityProvider{roles: []string{"api-role"}, ents: []string{"functions:read"}}
	rec := &contextRecordingChecker{}
	handler, tm, _, _ := apitokenBridgeFixture(t, fn, idp, rec)

	// A revocation of api-bob well before the key below is minted.
	cm, err := cache.NewCacheManager("", "proxy-iat-test", nil)
	require.NoError(t, err)
	store, _ := apitoken.RevocationCaches(cm)
	cutoffTM, err := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), store)
	require.NoError(t, err)
	require.NoError(t, cutoffTM.RevokeSubject(t.Context(), "api-bob", 0))
	time.Sleep(1100 * time.Millisecond) // iat is whole seconds

	token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, "api-bob", "act", "scope:abc", time.Hour)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/v1/api", nil)
	req.AddCookie(&http.Cookie{Name: "X-API-TOKEN", Value: token})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, rec.seen)
	data, err := tm.ValidateToken(t.Context(), token, apitokenBridgeHostAudience)
	require.NoError(t, err)
	assert.Equal(t, float64(data.IssuedAt), rec.seen[auth.ClaimIssuedAt])

	predates, err := (&auth.Config{TokenManager: cutoffTM}).CredentialPredatesRevocation(t.Context(), rec.seen)
	require.NoError(t, err)
	assert.False(t, predates, "a key minted after the revocation is not refused")
}

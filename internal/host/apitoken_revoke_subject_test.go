package host

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// POST /-/apitokens/revoke {aud, sub, all: true} revokes every token for the
// subject issued up to now, including keys the caller never recorded. It is
// authorized exactly like a metadata revoke. See kdex-tech/host-manager#257.

func TestApitokenRevoke_AllRevokesEveryTokenForTheSubject(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	recorded, err := tm.MintStatelessKey("aud", "alice", "key-1", "", time.Hour)
	require.NoError(t, err)
	unrecorded, err := tm.MintStatelessKey("aud", "alice", "minted-directly", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "purger", []any{"apitokens:alice:revoke-any"},
		RevokeRequest{Audience: "aud", Sub: "alice", All: true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	for name, token := range map[string]string{"recorded": recorded, "unrecorded": unrecorded} {
		_, err := tm.ValidateToken(t.Context(), token, "aud")
		assert.Error(t, err, name)
	}
}

func TestApitokenRevoke_AllForYourselfNeedsOnlyTheSelfServiceGrant(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	token, err := tm.MintStatelessKey("aud", "alice", "key-1", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Audience: "aud", Sub: "alice", All: true})
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	_, err = tm.ValidateToken(t.Context(), token, "aud")
	assert.Error(t, err)
}

func TestApitokenRevoke_AllForAnotherSubjectNeedsRevokeAny(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	token, err := tm.MintStatelessKey("aud", "admin", "key-1", "", time.Hour)
	require.NoError(t, err)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Audience: "aud", Sub: "admin", All: true})
	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())

	_, err = tm.ValidateToken(t.Context(), token, "aud")
	assert.NoError(t, err, "a denied revoke-all revokes nothing")
}

// all names a subject, not a token: a request that also names an act or a
// token is ambiguous about what it revokes, so it is refused, not guessed.
func TestApitokenRevoke_AllRefusesAmbiguousRequests(t *testing.T) {
	hh, _ := crossSubjectHost(t)
	for name, req := range map[string]RevokeRequest{
		"without aud": {Sub: "alice", All: true},
		"without sub": {Audience: "aud", All: true},
		"with act":    {Audience: "aud", Sub: "alice", Action: "key-1", All: true},
		"with token":  {Audience: "aud", Sub: "alice", Token: "v4.public.x", All: true},
	} {
		rr := revokeAs(t, hh, "alice", selfServiceGrant, req)
		assert.Equal(t, http.StatusBadRequest, rr.Code, name)
	}
}

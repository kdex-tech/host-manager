package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubLookup is a Lookup whose verdict the test dictates, so scopeProvider's
// chain semantics can be driven without a real backend.
type stubLookup struct {
	name    string
	ok      bool
	claims  jwt.MapClaims
	err     error
	called  *[]string
	subject string
}

func (s stubLookup) FindInternal(subject, _ string) (bool, jwt.MapClaims, error) {
	*s.called = append(*s.called, s.name)
	return s.ok, s.claims, s.err
}
func (s stubLookup) ResolveClaims(string) (jwt.MapClaims, error) { return nil, nil }
func (s stubLookup) Type() string                                { return "stub" }

// --- httpLookup: which failures are "the backend is unreachable" -------------

// TestHTTPLookup_InfrastructureFailuresAreUnavailable pins the distinction
// kdex-tech/host-manager#171 exists for. Every one of these is OUR backend
// misbehaving, not a verdict about the presented credential. Marking them lets
// the token endpoint answer 500 server_error instead of telling a client its
// credential is dead during an identity-provider outage — which makes clients
// discard working refresh tokens and forces users to log in again.
func TestHTTPLookup_InfrastructureFailuresAreUnavailable(t *testing.T) {
	t.Run("transport failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close() // nothing is listening now

		lookup, _ := NewHTTPLookup(makeHTTPLookupSecret(t, url, "2000", make([]byte, 32)))
		_, _, err := lookup.FindInternal("alice", "x")

		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLookupUnavailable),
			"an unreachable credential backend must be marked unavailable, not reported as a bad credential")
	})

	t.Run("non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()

		lookup, _ := NewHTTPLookup(makeHTTPLookupSecret(t, srv.URL, "2000", make([]byte, 32)))
		_, _, err := lookup.FindInternal("alice", "x")

		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLookupUnavailable),
			"a 5xx from the credential backend is not a credential verdict")
	})

	t.Run("undecodable response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		}))
		defer srv.Close()

		lookup, _ := NewHTTPLookup(makeHTTPLookupSecret(t, srv.URL, "2000", make([]byte, 32)))
		_, _, err := lookup.FindInternal("alice", "x")

		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrLookupUnavailable),
			"a response we cannot parse tells us nothing about the credential")
	})
}

// TestHTTPLookup_RejectedCredentialIsNotUnavailable is the other side: an
// `ok:false` body IS the backend's authoritative verdict on the credential and
// must stay a plain rejection, or every wrong password becomes a 500.
func TestHTTPLookup_RejectedCredentialIsNotUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok": false, "reason": "invalid_credentials"}`))
	}))
	defer srv.Close()

	lookup, _ := NewHTTPLookup(makeHTTPLookupSecret(t, srv.URL, "2000", make([]byte, 32)))
	_, _, err := lookup.FindInternal("alice", "wrong")

	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrLookupUnavailable),
		"a wrong password is a verdict, not an outage; marking it unavailable would 500 every failed login")
}

// --- scopeProvider: the chain ruling -----------------------------------------

// TestScopeProvider_RejectionStopsTheChain pins the owner's ruling: one
// identity may not live in two lookups, so a lookup that FOUND the subject and
// rejected the password is authoritative. The chain stops there.
//
// Falling through would let a subject present in two backends authenticate
// against whichever one accepts the password — an account in backend A could be
// unlocked by a stale duplicate in backend B.
func TestScopeProvider_RejectionStopsTheChain(t *testing.T) {
	var called []string
	rp := &scopeProvider{lookups: []Lookup{
		stubLookup{name: "first", err: errors.New("invalid password for subject 'alice'"), called: &called},
		stubLookup{name: "second", ok: true, claims: jwt.MapClaims{"sub": "alice"}, called: &called},
	}}

	_, err := rp.FindInternal("alice", "wrong")

	require.Error(t, err)
	assert.Equal(t, []string{"first"}, called,
		"a rejection is authoritative: the second lookup must NOT be consulted")
	assert.False(t, errors.Is(err, ErrServerError),
		"a rejected credential is about the grant, not our infrastructure")
}

// TestScopeProvider_UnavailableLookupIsServerError is the classification this
// issue blocks: an identity-backend outage must reach the token endpoint marked
// as OUR failure, so it answers 500 rather than invalid_grant.
func TestScopeProvider_UnavailableLookupIsServerError(t *testing.T) {
	var called []string
	rp := &scopeProvider{lookups: []Lookup{
		stubLookup{name: "first", err: ErrLookupUnavailable, called: &called},
		stubLookup{name: "second", ok: true, claims: jwt.MapClaims{"sub": "alice"}, called: &called},
	}}

	_, err := rp.FindInternal("alice", "hunter2")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerError),
		"an unreachable lookup must be marked ErrServerError so the token endpoint answers 500, not invalid_grant")
	assert.Equal(t, []string{"first"}, called,
		"an outage stops the chain too: we cannot know whether this backend would have accepted the credential")
}

// TestScopeProvider_NotPresentContinuesToNextLookup guards the one case that
// legitimately falls through. "Not present here" says nothing about the
// credential, so a multi-lookup deployment must still consult lookup #2.
func TestScopeProvider_NotPresentContinuesToNextLookup(t *testing.T) {
	var called []string
	rp := &scopeProvider{lookups: []Lookup{
		stubLookup{name: "first", ok: false, called: &called},
		stubLookup{name: "second", ok: true, claims: jwt.MapClaims{"sub": "alice"}, called: &called},
	}}

	claims, err := rp.FindInternal("alice", "hunter2")

	require.NoError(t, err)
	assert.Equal(t, []string{"first", "second"}, called,
		"a subject absent from lookup #1 must still be looked for in lookup #2")
	assert.Equal(t, "alice", claims["sub"])
}

// TestLDAPLookup_InfrastructureFailuresAreUnavailable completes #171 for the
// ldapLookup paths the original change missed.
//
// Only the SEARCH failure was marked. A dial failure and a service-account bind
// failure -- between them the most common LDAP outages -- still returned an
// unmarked error, so scopeProvider passed them through as a rejection and the
// token endpoint answered 400 invalid_grant. That is precisely the behaviour
// #171 exists to fix: a client told its credential is dead during OUR outage
// discards a working refresh token and forces the user to re-authenticate.
//
// A dial failure is provoked with an address nothing is listening on; both
// paths are reached before any credential is evaluated, so no LDAP server is
// needed to distinguish them.
func TestLDAPLookup_InfrastructureFailuresAreUnavailable(t *testing.T) {
	ll := &ldapLookup{
		addr:     "ldap://127.0.0.1:1", // nothing listens here
		bindUser: "cn=svc,dc=example,dc=test",
		bindPass: "irrelevant",
		baseDN:   "dc=example,dc=test",
	}

	_, _, err := ll.FindInternal("alice", "hunter2")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLookupUnavailable),
		"an unreachable LDAP server is OUR outage, not a verdict on the caller's password")
}

package host

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// GHSA-qp3j-f436-pggf. These drive the handlers through the REAL
// AuthorizationChecker, because the defect was in WHICH entitlement the
// handlers asked for, and a mock that answers true/false cannot see that.
//
// The self-service grant site charts bind to every authenticated subject is
// {resources: [apitokens], verbs: [mint, revoke]} with no resourceNames, i.e.
// apitokens::mint + apitokens::revoke. It must cover a caller's OWN tokens and
// nothing else: acting on another subject's tokens takes a distinct verb
// (impersonate to mint, revoke-any to revoke) that the blanket grant does not
// name.

var selfServiceGrant = []any{"apitokens::mint", "apitokens::revoke"}

func crossSubjectHost(t *testing.T) (*HostHandler, *apitoken.TokenManager) {
	t.Helper()
	cm, _ := cache.NewCacheManager("", "host", nil)
	tm, err := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), cm.GetCache("revocation", cache.CacheOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	return &HostHandler{
		authConfig:  &auth.Config{TokenManager: tm},
		authChecker: auth.NewAuthorizationChecker(nil, logr.Discard()),
		host:        &kdexv1alpha1.KDexHostSpec{},
	}, tm
}

func callerCtx(r *http.Request, sub string, entitlements []any) *http.Request {
	return r.WithContext(auth.SetAuthContext(r.Context(), auth.AuthContext{"sub": sub, "entitlements": entitlements}))
}

func mintAs(t *testing.T, hh *HostHandler, caller string, entitlements []any, sub string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MintRequest{Audience: "aud", Sub: sub, Action: "key-1", TTL: "1h"})
	req := callerCtx(httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(body)), caller, entitlements)
	rr := httptest.NewRecorder()
	hh.apitokenMintHandler(rr, req)
	return rr
}

func revokeAs(t *testing.T, hh *HostHandler, caller string, entitlements []any, rr RevokeRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(rr)
	req := callerCtx(httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(body)), caller, entitlements)
	rec := httptest.NewRecorder()
	hh.apitokenRevokeHandler(rec, req)
	return rec
}

func TestApitokenMint_SelfServiceGrantCannotMintForAnotherSubject(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := mintAs(t, hh, "alice", selfServiceGrant, "admin")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the self-service grant minted a token for another subject (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenMint_SelfServiceGrantMintsOwnToken(t *testing.T) {
	hh, tm := crossSubjectHost(t)

	rr := mintAs(t, hh, "alice", selfServiceGrant, "alice")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	var resp MintResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	data, err := tm.ValidateToken(t.Context(), resp.Token, "aud")
	if err != nil {
		t.Fatal(err)
	}
	if data.Subject != "alice" {
		t.Fatalf("minted sub = %q, want alice", data.Subject)
	}
}

func TestApitokenMint_ImpersonateGrantMintsForAnotherSubject(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := mintAs(t, hh, "ops", []any{"apitokens::impersonate"}, "bob")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenMint_ImpersonateIsScopedToTheNamedSubject(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := mintAs(t, hh, "ops", []any{"apitokens:bob:impersonate"}, "admin")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: apitokens:bob:impersonate minted for admin", rr.Code)
	}
}

// An admin role is {resources: [apitokens], verbs: [all]}; "all" keeps every
// apitokens capability, cross-subject ones included.
func TestApitokenMint_AllVerbGrantMintsForAnotherSubject(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := mintAs(t, hh, "root", []any{"apitokens::all"}, "bob")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

// The mint gate used to have no subject check of its own: an anonymous caller
// whose anonymousEntitlements happened to include apitokens::mint could mint
// for anyone. With no authenticated subject there is no "self", so it is 401.
func TestApitokenMint_AnonymousCallerIsRejectedEvenWithAnonymousGrant(t *testing.T) {
	hh, _ := crossSubjectHost(t)
	hh.authChecker = auth.NewAuthorizationChecker([]string{"apitokens::mint"}, logr.Discard())

	body, _ := json.Marshal(MintRequest{Audience: "aud", Sub: "admin"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	hh.apitokenMintHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestApitokenRevoke_SelfServiceGrantCannotRevokeAnotherSubjectsToken(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	victim, _ := tm.MintStatelessKey("aud", "bob", "key-1", "", time.Hour)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Token: victim})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the self-service grant revoked another subject's token", rr.Code)
	}
}

func TestApitokenRevoke_SelfServiceGrantCannotRevokeAnotherSubjectByMetadata(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Audience: "aud", Sub: "bob", Action: "key-1"})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the self-service grant revoked another subject's tokens by metadata", rr.Code)
	}
}

// The cross-subject check used to be keyed on the CALLER's subject, so a grant
// scoped to the caller's own name satisfied it for any target.
func TestApitokenRevoke_CallerScopedGrantCannotRevokeAnotherSubjectsToken(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	victim, _ := tm.MintStatelessKey("aud", "bob", "key-1", "", time.Hour)

	rr := revokeAs(t, hh, "alice", []any{"apitokens:alice:revoke", "apitokens:alice:revoke-any"}, RevokeRequest{Token: victim})

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a grant scoped to the caller revoked bob's token", rr.Code)
	}
}

func TestApitokenRevoke_SelfServiceGrantRevokesOwnToken(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	own, _ := tm.MintStatelessKey("aud", "alice", "key-1", "", time.Hour)

	rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Token: own})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenRevoke_RevokeAnyGrantRevokesAnotherSubjectsToken(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	victim, _ := tm.MintStatelessKey("aud", "bob", "key-1", "", time.Hour)

	rr := revokeAs(t, hh, "ops", []any{"apitokens:bob:revoke-any"}, RevokeRequest{Token: victim})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenRevoke_AllVerbGrantRevokesAnotherSubjectByMetadata(t *testing.T) {
	hh, _ := crossSubjectHost(t)

	rr := revokeAs(t, hh, "root", []any{"apitokens::all"}, RevokeRequest{Audience: "aud", Sub: "bob", Action: "key-1"})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

package host

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// An anonymous caller presented no credential, so the answer is 401 -- and a
// 401 MUST carry a challenge (RFC 7235). This endpoint returned a bare one.
func TestApitokenRevokeAnonymousGets401WithChallenge(t *testing.T) {
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		host:       &kdexv1alpha1.KDexHostSpec{},
	}

	reqBody, _ := json.Marshal(RevokeRequest{Token: "irrelevant"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	hh.apitokenRevokeHandler(rr, req) // no auth context

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an anonymous caller", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
}

// An authenticated caller who may not revoke for another subject gets 403 and
// no challenge: re-authenticating as the same subject would not help.
func TestApitokenRevokeUnderEntitledGets403WithoutChallenge(t *testing.T) {
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		host:       &kdexv1alpha1.KDexHostSpec{},
		authChecker: &mockApitokenAuthChecker{
			CheckAccessFn: func(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
				return false, nil
			},
		},
	}

	token, _ := tm.MintStatelessKey("aud", "other-user", "act", "scope", time.Hour)
	reqBody, _ := json.Marshal(RevokeRequest{Token: token})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/revoke", bytes.NewBuffer(reqBody))
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "test-user"}))
	rr := httptest.NewRecorder()

	hh.apitokenRevokeHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none on a NoIdentity 403", got)
	}
}

// The mint gate has no dedicated pre-check for an absent auth context (unlike
// revoke's two anonymous checks) -- it relies on the authChecker denying and
// denial.Classify itself reading auth.GetAuthContext. Assert that path lands
// on 401 + challenge, not the old bare 403, by driving apitokenMintHandler
// directly (this is the only test in the repo that calls it).
func TestApitokenMintAnonymousGets401WithChallenge(t *testing.T) {
	tm, _ := apitoken.NewTokenManager("issuer", apitoken.GenerateDevmodeKeyPair(), nil)
	hh := &HostHandler{
		authConfig: &auth.Config{TokenManager: tm},
		host:       &kdexv1alpha1.KDexHostSpec{},
		authChecker: &mockApitokenAuthChecker{
			CheckAccessFn: func(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error) {
				return false, nil // a real checker denies a caller with no credential
			},
		},
	}

	reqBody, _ := json.Marshal(MintRequest{Audience: "aud", Sub: "someone"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()

	hh.apitokenMintHandler(rr, req) // no auth context

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an anonymous caller", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 with no WWW-Authenticate violates RFC 7235")
	}
}

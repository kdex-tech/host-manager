package host

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// KDexHost.spec.auth.apiToken.maxTTL at the /-/apitokens/mint surface. A ttl
// above the maximum is refused, never shortened; a missing ttl gets the 24h
// default capped at the maximum; the maximum is discoverable. See
// kdex-tech/host-manager#238.

func mintWithTTL(t *testing.T, hh *HostHandler, caller string, entitlements []any, sub, ttl string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MintRequest{Audience: "aud", Sub: sub, Action: "key-1", TTL: ttl})
	req := callerCtx(httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(body)), caller, entitlements)
	rr := httptest.NewRecorder()
	hh.apitokenMintHandler(rr, req)
	return rr
}

func TestApitokenMint_RefusesATTLAboveTheHostMaximum(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	tm.WithMaxTTL(90 * 24 * time.Hour)

	rr := mintWithTTL(t, hh, "alice", selfServiceGrant, "alice", "876000h")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("2160h0m0s")) {
		t.Fatalf("body %q does not name the maximum", rr.Body.String())
	}
}

func TestApitokenMint_ImpersonationIsBoundedToo(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	tm.WithMaxTTL(time.Hour)

	rr := mintWithTTL(t, hh, "ops", []any{"apitokens::impersonate"}, "bob", "2h")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenMint_MintsAtOrBelowTheHostMaximum(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	tm.WithMaxTTL(time.Hour)

	rr := mintWithTTL(t, hh, "alice", selfServiceGrant, "alice", "1h")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

func TestApitokenMint_DefaultTTLIsCappedAtTheHostMaximum(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	tm.WithMaxTTL(time.Hour)

	rr := mintWithTTL(t, hh, "alice", selfServiceGrant, "alice", "")

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
	if lifetime := time.Duration(data.Expiration-data.IssuedAt) * time.Second; lifetime != time.Hour {
		t.Fatalf("default lifetime = %s, want the 1h maximum rather than 24h", lifetime)
	}
}

func TestApitokenDiscovery_PublishesTheHostMaximum(t *testing.T) {
	for name, tc := range map[string]struct {
		maxTTL time.Duration
		want   any
	}{
		"set":   {maxTTL: 90 * 24 * time.Hour, want: "2160h0m0s"},
		"unset": {want: nil},
	} {
		t.Run(name, func(t *testing.T) {
			hh, tm := crossSubjectHost(t)
			tm.WithMaxTTL(tc.maxTTL)

			rr := httptest.NewRecorder()
			hh.apitokenDiscoveryHandler(rr, httptest.NewRequest(http.MethodGet, "/.well-known/pks.json", nil))

			var doc map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
				t.Fatal(err)
			}
			if got := doc["max_ttl"]; got != tc.want {
				t.Fatalf("max_ttl = %v, want %v", got, tc.want)
			}
		})
	}
}

// "Never silently shortened" has to hold for a ttl the server cannot read too:
// "90d" is a natural mistake (Go has no day unit), and "0s"/"-1h" would mint a
// token that is already expired.
func TestApitokenMint_RefusesAnUnusableTTL(t *testing.T) {
	for _, ttl := range []string{"90d", "forever", "0s", "-1h"} {
		t.Run(ttl, func(t *testing.T) {
			hh, _ := crossSubjectHost(t)

			rr := mintWithTTL(t, hh, "alice", selfServiceGrant, "alice", ttl)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %q)", rr.Code, rr.Body.String())
			}
		})
	}
}

// A revoke is a security action: an unusable ttl, which could only have
// lengthened the revocation, must not make it fail.
func TestApitokenRevoke_IgnoresAnUnusableTTL(t *testing.T) {
	for _, ttl := range []string{"90d", "0s", "-1h"} {
		t.Run(ttl, func(t *testing.T) {
			hh, tm := crossSubjectHost(t)
			token, err := tm.MintStatelessKey("aud", "alice", "User", "key-1", "", time.Hour)
			if err != nil {
				t.Fatal(err)
			}

			rr := revokeAs(t, hh, "alice", selfServiceGrant, RevokeRequest{Audience: "aud", Sub: "alice", Action: "key-1", TTL: ttl})

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
			}
			if _, err := tm.ValidateToken(t.Context(), token, "aud"); err == nil {
				t.Fatal("the token must be revoked")
			}
		})
	}
}

// The revoke ttl's OpenAPI description is built from apitoken.RevocationHorizon,
// so it states the horizon in years rather than restating a literal.
func TestRevokeTTLDescription_StatesTheRevocationHorizon(t *testing.T) {
	if !strings.Contains(revokeTTLDescription, "max(10 years, the host's max_ttl)") {
		t.Fatalf("description = %q", revokeTTLDescription)
	}
}

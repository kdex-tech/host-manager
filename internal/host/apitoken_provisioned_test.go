package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// apitokens_impersonate_provisioned: a confidential client mints API tokens
// for the subjects it provisioned. Ownership is the target's provisioned_by
// Lookup claim, resolved live at mint time and compared with the caller's own
// client_credentials sub. See kdex-tech/host-manager#237.

const orchestrator = "orchestrator"

// provisioningLookup answers ResolveClaimsWithError from a per-subject map, or
// with err when set (a Lookup outage).
type provisioningLookup struct {
	claims map[string]jwt.MapClaims
	err    error
}

func (p provisioningLookup) FindInternal(string, string) (jwt.MapClaims, error) { return nil, nil }

// The orchestrator client's own KDexRoleBinding grants it the class scope.
func (p provisioningLookup) FindInternalRolesAndEntitlements(bs auth.BindingSubject, _ *auth.BindingNames) ([]string, []string, error) {
	if bs.Key == orchestrator {
		return []string{"provisioner"}, []string{provisionedMintScope}, nil
	}
	return nil, nil, nil
}

func (p provisioningLookup) ResolveClaimsWithError(subject string) (jwt.MapClaims, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.claims[subject], nil
}

// provisioningHost is a host whose exchanger resolves through lookup: a
// provisioningLookup, or any provider that also resolves claims.
func provisioningHost(t *testing.T, lookup auth.InternalIdentityProvider) *HostHandler {
	t.Helper()
	hh, _ := crossSubjectHost(t)
	cm, err := cache.NewCacheManager("", "provisioned-mint-237", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.NewConfigBuilder().
		WithAuthClientLoader(func() (map[string]auth.AuthClient, error) {
			return map[string]auth.AuthClient{
				orchestrator:  {ClientID: orchestrator, ClientSecret: "s"},
				"billing-svc": {ClientID: "billing-svc", ClientSecret: "s"},
			}, nil
		}).
		WithKeyLoader(func() (*keys.KeyPairs, error) { return keys.GenerateECDSAKeyPair(), nil }).
		WithOIDCClientConfigLoader(func() (*auth.OIDCClientConfig, error) { return nil, nil }).
		WithAudience("aud").WithIssuer("iss").WithDevMode(true).WithCacheManager(cm).
		Build(&kdexv1alpha1.Auth{})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := auth.NewExchanger(t.Context(), *cfg, cm, lookup, nil)
	if err != nil {
		t.Fatal(err)
	}
	hh.authExchanger = ex
	return hh
}

// clientCaller is the auth context of a verified client_credentials token
// holding the class scope.
func clientCaller() map[string]any {
	return map[string]any{
		"sub": orchestrator, "azp": orchestrator, "grant_type": "client_credentials",
		"entitlements": []any{provisionedMintScope},
	}
}

// realClientCaller is the auth context the host middleware builds from a real
// client_credentials token: the claims the signer actually emits, not a
// hand-built map that could carry claims no real token has.
func realClientCaller(t *testing.T, hh *HostHandler) map[string]any {
	t.Helper()
	ts, err := hh.authExchanger.LoginClient(t.Context(), orchestrator, "s", "entitlements")
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(ts.AccessToken, claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func mintFor(t *testing.T, hh *HostHandler, caller map[string]any, sub string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(MintRequest{Audience: "aud", Sub: sub, Action: "key-1", TTL: "1h"})
	req := httptest.NewRequest(http.MethodPost, "/-/apitokens/mint", bytes.NewBuffer(body))
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext(caller)))
	rr := httptest.NewRecorder()
	hh.apitokenMintHandler(rr, req)
	return rr
}

func sandbox(provisionedBy string) provisioningLookup {
	return provisioningLookup{claims: map[string]jwt.MapClaims{"sandbox-1": {"provisioned_by": provisionedBy}}}
}

func TestProvisionedMint_MintsForASubjectTheClientProvisioned(t *testing.T) {
	hh := provisioningHost(t, sandbox(orchestrator))

	rr := mintFor(t, hh, clientCaller(), "sandbox-1")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	var resp MintResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	data, err := hh.authConfig.TokenManager.ValidateToken(t.Context(), resp.Token, "aud")
	if err != nil {
		t.Fatal(err)
	}
	if data.Subject != "sandbox-1" {
		t.Fatalf("minted sub = %q, want the provisioned subject", data.Subject)
	}
}

func TestProvisionedMint_AcceptsARealClientCredentialsToken(t *testing.T) {
	hh := provisioningHost(t, sandbox(orchestrator))

	rr := mintFor(t, hh, realClientCaller(t, hh), "sandbox-1")

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
}

// Minting for a subject named like a client would hand the token that client's
// KDexRoleBindings: the PAT paths resolve roles by sub, as a Client (#243, #255).
func TestProvisionedMint_RefusesATargetNamedLikeAClient(t *testing.T) {
	for _, target := range []string{"billing-svc", "dcr_0a1b2c"} {
		t.Run(target, func(t *testing.T) {
			hh := provisioningHost(t, provisioningLookup{claims: map[string]jwt.MapClaims{
				target: {"provisioned_by": orchestrator},
			}})

			rr := mintFor(t, hh, realClientCaller(t, hh), target)

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestProvisionedMint_Refuses(t *testing.T) {
	notClientCredentials := clientCaller()
	delete(notClientCredentials, "grant_type")
	notAClient := clientCaller()
	notAClient["sub"] = "sandbox-2"
	noScope := clientCaller()
	noScope["entitlements"] = selfServiceGrant

	for name, tc := range map[string]struct {
		lookup provisioningLookup
		caller map[string]any
	}{
		"a subject another client provisioned": {lookup: sandbox("other-client"), caller: clientCaller()},
		"a subject the Lookup no longer attributes (claimed)": {
			lookup: provisioningLookup{claims: map[string]jwt.MapClaims{"sandbox-1": {"email": "x@y"}}}, caller: clientCaller(),
		},
		"an unknown subject": {lookup: provisioningLookup{}, caller: clientCaller()},
		// A user session that happens to hold the scope (e.g. a user named
		// like the client) is not the client.
		"a caller that is not a client_credentials token": {lookup: sandbox(orchestrator), caller: notClientCredentials},
		"a caller that is not a configured client":        {lookup: sandbox("sandbox-2"), caller: notAClient},
		"a caller without the scope":                      {lookup: sandbox(orchestrator), caller: noScope},
	} {
		t.Run(name, func(t *testing.T) {
			hh := provisioningHost(t, tc.lookup)

			rr := mintFor(t, hh, tc.caller, "sandbox-1")

			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
			}
		})
	}
}

// Ownership can't be decided without the Lookup, and a failure to decide is
// the server's, never a grant and never the caller's fault.
func TestProvisionedMint_LookupOutageIs503(t *testing.T) {
	hh := provisioningHost(t, provisioningLookup{err: errors.New("lookup down")})

	rr := mintFor(t, hh, clientCaller(), "sandbox-1")

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %q)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("a 503 must say when to retry")
	}
}

// The scope only ever matches by exact name: a wildcard or `all` grant on
// apitokens must not imply it. (It grants impersonation outright, so the
// provisioned path is never consulted; this pins that the scope is not
// satisfied by apitokens:*:mint, the closest wildcard short of that.)
func TestProvisionedMint_WildcardMintDoesNotImplyTheScope(t *testing.T) {
	hh := provisioningHost(t, sandbox(orchestrator))
	caller := clientCaller()
	caller["entitlements"] = []any{"apitokens:*:mint"}

	rr := mintFor(t, hh, caller, "sandbox-1")

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body %q)", rr.Code, rr.Body.String())
	}
}

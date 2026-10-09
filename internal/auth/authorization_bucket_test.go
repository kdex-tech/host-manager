package auth

import (
	"context"
	"maps"
	"net/url"
	"testing"

	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// oauth2Requirement is an operation protected ONLY by the oauth2 scheme —
// the shape aa73843 exists to let a PAT satisfy.
func oauth2Requirement(pattern string) []kdexv1alpha1.SecurityRequirement {
	return []kdexv1alpha1.SecurityRequirement{{"oauth2": []string{pattern}}}
}

// TestGetParsedEntitlements_ScopesDoNotClobberThePATBridgeMirror pins a latent
// regression risk found while investigating #175.
//
// GetParsedEntitlements writes the "oauth2" bucket twice. The first write is
// aa73843's PAT-bridge mirror, which puts the caller's role-resolved
// ENTITLEMENTS there so a PAT can satisfy an operation declaring only
// {oauth2: [...]} — that mirror is what makes `Authorization: Bearer <api key>`
// work on knowdb-mcp. The second write, for auth_method == "oauth2", puts the
// caller's OAuth SCOPES there and overwrote the first.
//
// Nothing hits both conditions today, so this is latent rather than live: the
// live PAT path was verified working on dev 0.5.0. But it is one added `scope`
// claim away from silently un-fixing aa73843, and the two writes describe
// different things about the same caller, so they must merge rather than
// replace.
func TestGetParsedEntitlements_ScopesDoNotClobberThePATBridgeMirror(t *testing.T) {
	ac := NewAuthorizationChecker(nil, logr.Discard())
	ac.scopeBuckets = true // the kept, disabled logic: see AuthorizationChecker.scopeBuckets

	ctx := SetAuthContext(context.Background(), AuthContext{
		"sub":          "alice",
		"entitlements": []string{"functions:/api/v1/mcp:read"},
		"scope":        "openid profile",
		"auth_method":  string(AuthMethodOAuth2),
		PATBridgeClaim: true,
	})

	parsed := ac.GetParsedEntitlements(ctx)

	authorized, err := ac.ec.VerifyResourceParsedEntitlements(
		"functions", "/api/v1/mcp", parsed,
		ac.ParseRequirements(oauth2Requirement("functions:/api/v1/mcp:read")),
		"read")

	require.NoError(t, err)
	assert.True(t, authorized,
		"a PAT-bridge caller that also carries a scope claim must keep the aa73843 entitlements mirror "+
			"in the oauth2 bucket; scopes must merge alongside it, not replace it")
}

// TestGetParsedEntitlements_ScopesStillSatisfyAnOAuth2Requirement is the other
// half: the merge must not drop the scopes an ordinary oauth2 caller relies on.
//
// Note the shape. VerifyResourceParsedEntitlements gates on IDENTITY first,
// reading only the default (bearer) bucket for the same resource+verb, and only
// then evaluates the declared requirements. This test is built accordingly:
// bearer supplies the identity, and the oauth2 bucket must supply the
// requirement.
//
// An earlier version of this comment claimed "a scope can never GRANT access to
// something bearer does not already cover". That is TRUE of the identity gate
// and FALSE of the requirements, which is where the real authorization lives:
// an oauth2-declared requirement IS satisfiable from the oauth2 bucket, so a
// scope the caller chose could satisfy a constraint their role bindings never
// granted. The quad review demonstrated the escalation. It does not reach
// production because scope bucketing is off (AuthorizationChecker.scopeBuckets):
// applyScopeFilter narrows only the user grants, and a client_credentials scope
// is not filtered at all (TestGate_ClientCredentialsScopeDoesNotSatisfyAnOAuth2Requirement).
// This test turns bucketing on to cover the logic kept for that decision.
func TestGetParsedEntitlements_ScopesStillSatisfyAnOAuth2Requirement(t *testing.T) {
	ac := NewAuthorizationChecker(nil, logr.Discard())
	ac.scopeBuckets = true

	ctx := SetAuthContext(context.Background(), AuthContext{
		"sub":          "alice",
		"entitlements": []string{"functions:/api/v1/mcp:read"},
		"scope":        "functions:/api/v1/mcp:read",
		"auth_method":  string(AuthMethodOAuth2),
		// No PATBridgeClaim: the oauth2 bucket is scopes alone.
	})

	parsed := ac.GetParsedEntitlements(ctx)

	authorized, err := ac.ec.VerifyResourceParsedEntitlements(
		"functions", "/api/v1/mcp", parsed,
		ac.ParseRequirements(oauth2Requirement("functions:/api/v1/mcp:read")),
		"read")

	require.NoError(t, err)
	assert.True(t, authorized,
		"a scope-declared grant must still satisfy an oauth2 requirement after the merge")
}

// Scope bucketing is off by default: a scope never satisfies an oauth2 or oidc
// requirement, whatever auth_method the token carries.
func TestGetParsedEntitlements_ScopeBucketingIsOff(t *testing.T) {
	ac := NewAuthorizationChecker(nil, logr.Discard())
	for _, method := range []AuthMethod{AuthMethodOAuth2, AuthMethodOIDC} {
		ctx := SetAuthContext(context.Background(), AuthContext{
			"sub":          "alice",
			"entitlements": []string{"functions:/api/v1/mcp:read"},
			"scope":        "openid functions:/api/v1/mcp:read",
			"auth_method":  string(method),
		})
		parsed := ac.GetParsedEntitlements(ctx)
		for _, scheme := range []string{"oauth2", "oidc"} {
			for _, reqs := range [][]string{{}, {"openid"}, {"functions:/api/v1/mcp:read"}} {
				authorized, err := ac.ec.VerifyResourceParsedEntitlements(
					"functions", "/api/v1/mcp", parsed,
					ac.ParseRequirements([]kdexv1alpha1.SecurityRequirement{{scheme: reqs}}), "read")
				require.NoError(t, err)
				assert.False(t, authorized, "%s token, %s requirement %v", method, scheme, reqs)
			}
		}
	}
}

// TestGetParsedEntitlements_NonBridgeCallerBucketingUnchanged guards the
// property the original mirror was careful about: an ordinary JWT-cookie user
// who logged in via oauth2 carries auth_method == "oauth2" too, and must NOT
// have their entitlements mirrored into the oauth2 bucket.
func TestGetParsedEntitlements_NonBridgeCallerBucketingUnchanged(t *testing.T) {
	ac := NewAuthorizationChecker(nil, logr.Discard())

	ctx := SetAuthContext(context.Background(), AuthContext{
		"sub":          "alice",
		"entitlements": []string{"functions:/api/v1/mcp:read"},
		"auth_method":  string(AuthMethodOAuth2),
		// no PATBridgeClaim
	})

	parsed := ac.GetParsedEntitlements(ctx)

	authorized, err := ac.ec.VerifyResourceParsedEntitlements(
		"functions", "/api/v1/mcp", parsed,
		ac.ParseRequirements(oauth2Requirement("functions:/api/v1/mcp:read")),
		"read")

	require.NoError(t, err)
	assert.False(t, authorized,
		"a cookie/JWT oauth2 caller must keep bearer-only bucketing; only the PAT bridge mirrors into oauth2")
}

// The page and proxy gates decide on GetParsedEntitlements followed by
// VerifyResourceParsedEntitlements. These tests run REAL minted tokens through
// that pair and compare each decision with the one the same token got before
// the signer projected auth_method (the claim removed): signing auth_method
// for the DCR consent gate must not change any authorization decision.

const (
	gatePage     = "/home"
	gateFunction = "/api/v1/vs"
)

// gateGrantingProvider logs any username in as itself and grants every
// subject the identity entitlements the gates check first, so the declared
// requirement is what decides.
func gateGrantingProvider() *mockScopeProvider {
	grants := []string{"pages:" + gatePage + ":read", "functions:" + gateFunction + ":read"}
	return &mockScopeProvider{
		resolveIdentity: func(subject, _ string) (jwt.MapClaims, error) {
			return jwt.MapClaims{"sub": subject, "entitlements": grants}, nil
		},
		resolveRolesAndEntitlements: func(string) ([]string, []string, error) { return nil, grants, nil },
	}
}

// gateDecision verifies a host-signed token as the middleware does and runs
// it through the gate. base is the decision for the same claims without
// auth_method.
func gateDecision(t *testing.T, cfg *Config, token, resource, name string, reqs []kdexv1alpha1.SecurityRequirement) (now, base bool) {
	t.Helper()
	sctx, ac := verifiedCookieSession(t, cfg, token)
	checker := NewAuthorizationChecker(nil, logr.Discard())
	decide := func(ac AuthContext) bool {
		parsed := checker.GetParsedEntitlements(SetAuthContext(sctx, ac))
		ok, err := checker.VerifyResourceParsedEntitlements(resource, name, parsed, checker.ParseRequirements(reqs))
		require.NoError(t, err)
		return ok
	}
	baseShape := maps.Clone(ac)
	delete(baseShape, "auth_method")
	return decide(ac), decide(baseShape)
}

// A client_credentials client with no AllowedScopes gets whatever scope it
// asks for. Its scope is not an oauth2 grant: an entitlement-shaped string it
// asked for must not satisfy an oauth2-declared requirement.
func TestGate_ClientCredentialsScopeDoesNotSatisfyAnOAuth2Requirement(t *testing.T) {
	f := newConsentFixture(t)
	f.ex.sp = gateGrantingProvider()
	f.ex.config.Clients["svc"] = AuthClient{ClientID: "svc", ClientSecret: "svc-secret"}

	ts, err := f.ex.LoginClient(context.Background(), "svc", "svc-secret", "entitlements roles vector_stores:vs_victim:write")
	require.NoError(t, err)
	require.Contains(t, claimsOf(t, ts.AccessToken)["scope"], "vector_stores:vs_victim:write", "precondition: the scope was granted")

	now, _ := gateDecision(t, &f.ex.config, ts.AccessToken, "functions", gateFunction, nil)
	require.True(t, now, "precondition: the identity check passes")

	now, base := gateDecision(t, &f.ex.config, ts.AccessToken, "functions", gateFunction,
		[]kdexv1alpha1.SecurityRequirement{{"oauth2": []string{"vector_stores:vs_victim:write"}}})
	assert.False(t, now)
	assert.Equal(t, base, now, "same decision as before auth_method was signed")
}

// Tokens issued to OAuth clients carry auth_method "oauth2" and a scope. An
// oauth2-declared requirement, empty or naming a granted scope, decides
// exactly as it did before auth_method was signed.
func TestGate_OAuthClientTokensDecideAsBefore(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	f.ex.sp = gateGrantingProvider()
	f.ex.config.Clients["svc"] = AuthClient{ClientID: "svc", ClientSecret: "svc-secret"}

	code := codeFrom(t, f.allow(t, f.query(appRedirect, url.Values{"scope": {"openid email entitlements"}})))
	authCode, err := f.ex.RedeemAuthorizationCode(ctx, code, f.clientID, appRedirect, f.verifier)
	require.NoError(t, err)
	refreshed, err := f.ex.RedeemRefreshToken(ctx, authCode.RefreshToken, f.clientID)
	require.NoError(t, err)
	password, err := f.ex.LoginLocal(ctx, "alice", "pw", "openid email entitlements", "svc", AuthMethodOAuth2)
	require.NoError(t, err)

	for name, token := range map[string]string{
		"authorization_code": authCode.AccessToken,
		"client refresh":     refreshed.AccessToken,
		"password":           password.AccessToken,
	} {
		for reqName, reqs := range map[string][]kdexv1alpha1.SecurityRequirement{
			"empty oauth2":  {{"oauth2": []string{}}},
			"oauth2 openid": {{"oauth2": []string{"openid"}}},
		} {
			t.Run(name+"/"+reqName, func(t *testing.T) {
				require.Equal(t, string(AuthMethodOAuth2), claimsOf(t, token)["auth_method"], "precondition")
				now, base := gateDecision(t, &f.ex.config, token, "functions", gateFunction, nil)
				require.True(t, now && base, "precondition: the identity check passes")

				now, base = gateDecision(t, &f.ex.config, token, "functions", gateFunction, reqs)
				assert.False(t, now)
				assert.Equal(t, base, now, "same decision as before auth_method was signed")
			})
		}
	}
}

// An OIDC login session carries auth_method "oidc" and a scope. An
// oidc-declared requirement decides exactly as it did before auth_method was
// signed.
func TestGate_OIDCSessionsDecideAsBefore(t *testing.T) {
	o := newOIDCFixture(t)
	o.ex.sp = gateGrantingProvider()
	upstream, err := o.ex.ExchangeCode(o.ctx, "alice")
	require.NoError(t, err)
	login, err := o.ex.ExchangeToken(o.ctx, upstream)
	require.NoError(t, err)
	rotated, err := o.ex.RedeemRefreshToken(o.ctx, login.RefreshToken, "")
	require.NoError(t, err)

	for name, token := range map[string]string{"login": login.AccessToken, "rotated": rotated.AccessToken} {
		for reqName, reqs := range map[string][]kdexv1alpha1.SecurityRequirement{
			"empty oidc":  {{"oidc": []string{}}},
			"oidc openid": {{"oidc": []string{"openid"}}},
		} {
			t.Run(name+"/"+reqName, func(t *testing.T) {
				require.Equal(t, string(AuthMethodOIDC), claimsOf(t, token)["auth_method"], "precondition")
				now, base := gateDecision(t, &o.ex.config, token, "pages", gatePage, nil)
				require.True(t, now && base, "precondition: the identity check passes")

				now, base = gateDecision(t, &o.ex.config, token, "pages", gatePage, reqs)
				assert.False(t, now)
				assert.Equal(t, base, now, "same decision as before auth_method was signed")
			})
		}
	}
}

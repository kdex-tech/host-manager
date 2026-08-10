package auth

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
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
// granted. The quad review demonstrated the escalation. It is closed upstream
// now — applyScopeFilter grants nothing outside SupportedScopes, so a client
// can no longer author an entitlement-shaped scope — but the invariant as
// originally written was wrong and should not be relied on.
func TestGetParsedEntitlements_ScopesStillSatisfyAnOAuth2Requirement(t *testing.T) {
	ac := NewAuthorizationChecker(nil, logr.Discard())

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

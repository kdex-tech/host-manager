package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyScopeFilter_DropsScopesOutsideTheVocabulary pins RFC 6749 §3.3:
// "The value of the scope parameter is expressed as a list of space-delimited,
// case-sensitive strings. The strings are defined by the AUTHORIZATION SERVER."
//
// A client selects from a vocabulary the AS defines and publishes as
// scopes_supported (RFC 8414 §2); it cannot invent values. Copying an
// unrecognised request string into the signed `scope` claim let a client define
// its own scope values — and because GetParsedEntitlements files that claim in
// the "oauth2" scheme bucket, a client-authored string could satisfy an
// oauth2-declared operation requirement that the caller's role bindings never
// granted.
func TestApplyScopeFilter_DropsScopesOutsideTheVocabulary(t *testing.T) {
	signingContext := jwt.MapClaims{}

	granted := applyScopeFilter(signingContext,
		"openid entitlements vector_stores:vs_victim:write", nil)

	assert.NotContains(t, granted, "vector_stores:vs_victim:write",
		"a scope value the AS does not define must never be granted")
	assert.Equal(t, "openid entitlements", signingContext["scope"],
		"only vocabulary scopes may reach the signed claim")
}

// TestApplyScopeFilter_GrantsEveryAdvertisedScope is the other direction: every
// value the AS advertises must remain requestable, or discovery would be lying.
func TestApplyScopeFilter_GrantsEveryAdvertisedScope(t *testing.T) {
	for _, scope := range SupportedScopes {
		t.Run(scope, func(t *testing.T) {
			signingContext := jwt.MapClaims{}
			granted := applyScopeFilter(signingContext, scope, nil)
			assert.Contains(t, granted, scope)
		})
	}
}

// TestSupportedScopes_MatchesDiscovery guards the single source of truth. The
// vocabulary used to be hardcoded twice — once in applyScopeFilter, once in the
// discovery document — so the filter and the advertisement could drift, and a
// scope could be advertised but ungrantable (or grantable but unadvertised).
func TestSupportedScopes_MatchesDiscovery(t *testing.T) {
	rec := httptest.NewRecorder()
	DiscoveryHandler("https://host.example", "")(rec,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var doc struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))

	assert.ElementsMatch(t, SupportedScopes, doc.ScopesSupported,
		"the filter's vocabulary and the advertised scopes_supported must be the same list")
}

// TestApplyScopeFilter_UnknownOnlyRequestYieldsNoScope: a request made entirely
// of unrecognised values grants nothing, so the claim is dropped rather than
// emitted empty.
func TestApplyScopeFilter_UnknownOnlyRequestYieldsNoScope(t *testing.T) {
	signingContext := jwt.MapClaims{"scope": "stale"}

	granted := applyScopeFilter(signingContext, "not_a_scope also:not:one", nil)

	assert.Empty(t, granted)
	assert.NotContains(t, signingContext, "scope")
}

package host

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProxyPAT_HostAudiencePATThroughMiddleware closes a gap that
// TestProxyPAT_HostAudienceOnOAuth2APIKeyFunction cannot see.
//
// That test drives hh.reverseProxyHandler DIRECTLY. In production the request
// passes through Config.WithAuthentication FIRST, and the proxy PAT bridge is
// guarded on `!alreadyLoggedIn` -- so anything the middleware puts on the
// context makes the bridge step aside.
//
// That matters because of kdex-tech/host-manager#175: the middleware now
// authenticates a HOST-audience PAT so non-proxied endpoints (/-/check et al)
// see a real identity. A host-audience PAT sent to an oauth2-protected function
// therefore reaches the bridge already-logged-in, and the bridge no longer runs.
// If the middleware's identity does not carry everything the bridge's did, this
// silently regresses aa73843 -- the fix that made
// `Authorization: Bearer <api key>` work on knowdb-mcp -- and no existing test
// would notice, because none of them run both layers.
//
// Concretely: the bridge sets auth.PATBridgeClaim, which is what mirrors the
// caller's entitlements into the "oauth2" scheme bucket so they can satisfy an
// operation declaring only {oauth2: [...]}. The middleware's identity must carry
// the same marker, or the same token authenticated one layer earlier becomes
// strictly less capable.
func TestProxyPAT_HostAudiencePATThroughMiddleware(t *testing.T) {
	idp := stubInternalIdentityProvider{
		roles: []string{"mcp-role"},
		ents:  []string{"functions:" + patProxyBasePath + ":read"},
	}
	scopes := []string{"functions:" + patProxyBasePath + ":read"}

	handler, tm, backendReached := patProxyFixtureWithMiddleware(t, idp,
		newReadyFunctionWithOAuth2AndAPIKey(t, patProxyBasePath, scopes))

	// What the developer-keys UI mints: aud = the host origin.
	pat, err := tm.MintStatelessKey(patProxyHostAud, "mcp-bob", "act", "scope:x", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", patProxyBasePath, nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.True(t, *backendReached,
		"a host-audience PAT must still reach an oauth2-protected function when the auth middleware "+
			"authenticated it first (#175 must not regress aa73843)")
	assert.Equal(t, http.StatusOK, rec.Code)
}

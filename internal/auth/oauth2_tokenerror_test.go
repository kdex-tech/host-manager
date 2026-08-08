package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeOAuthError reads the RFC 6749 5.2 body off a response recorder.
func decodeOAuthError(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"),
		"5.2 requires the error parameters in an application/json entity body")
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body),
		"body was not JSON: %q", rec.Body.String())
	return body
}

// postToken drives the token handler with form values.
func postToken(t *testing.T, o *OAuth2, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	o.OAuth2TokenHandler(rec, req)
	return rec
}

// newTokenErrorTestHandler builds an OAuth2 handler over the same stub
// Exchanger the rotation tests use, which already registers a public client
// named "app".
func newTokenErrorTestHandler(t *testing.T) *OAuth2 {
	t.Helper()
	ex := newRotationTestExchanger(t)
	return &OAuth2{
		AuthConfig:        &ex.config,
		AuthExchanger:     ex,
		ResourceAudiences: map[string]bool{},
		AccessTokenTTL:    time.Hour,
	}
}

// TestTokenHandler_DeadRefreshTokenIsInvalidGrant is the literal #168
// reproduction: a dead refresh token must produce 400 +
// {"error":"invalid_grant"}, the spec-defined signal telling a client to
// start a fresh authorization flow. Before the fix this was 401 +
// text/plain "Authentication failed", and one MCP client retried the same
// dead token 290 times as a result.
//
// It also pins the exact error_description text: a #168 review round found
// that wrapping the message with ErrGrantFailure via
// fmt.Errorf("%w: ...", ErrGrantFailure) put the sentinel's OWN text
// ("grant failure: ...") on the wire ahead of the grant message, so the
// response no longer matched what #168's reporter is matching on. No test
// asserted error_description end-to-end, so it slipped through; this is
// that assertion, on the endpoint's literal flagship reproduction.
func TestTokenHandler_DeadRefreshTokenIsInvalidGrant(t *testing.T) {
	o := newTokenErrorTestHandler(t)

	rec := postToken(t, o, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"DEADBEEFNOTAREALTOKEN000000"},
		"client_id":     {"app"},
	})

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"5.2 reserves 401 for failed client authentication via the Authorization header")
	body := decodeOAuthError(t, rec)
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "refresh token not found or expired", body["error_description"],
		"the description must be exactly the grant message, with no sentinel wording prepended (#168 round 2)")
}

// TestTokenHandler_ErrorMapping walks the rest of the 5.2 table.
func TestTokenHandler_ErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantCode   string
	}{
		{
			name:       "missing refresh_token",
			form:       url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "missing code",
			form:       url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
		{
			name:       "unknown client_id",
			form:       url.Values{"grant_type": {"refresh_token"}, "client_id": {"no-such-client"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_client",
		},
		{
			name:       "unknown grant_type",
			form:       url.Values{"grant_type": {"telepathy"}, "client_id": {"app"}},
			wantStatus: http.StatusBadRequest,
			wantCode:   "unsupported_grant_type",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := postToken(t, newTokenErrorTestHandler(t), tc.form)
			assert.Equal(t, tc.wantStatus, rec.Code)
			assert.Equal(t, tc.wantCode, decodeOAuthError(t, rec)["error"])
		})
	}
}

// TestTokenHandler_MethodNotAllowed keeps the 405 but gives it the same
// JSON shape, so a client never has to branch on content type.
func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	o := newTokenErrorTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/-/token", nil)
	rec := httptest.NewRecorder()
	o.OAuth2TokenHandler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "invalid_request", decodeOAuthError(t, rec)["error"])
}

// TestTokenHandler_BasicAuthRejectionIs401WithChallenge pins the ONE case
// where 5.2 does want 401: client authentication attempted through the
// Authorization request header. It then obliges a WWW-Authenticate header.
// No current client takes this path — they are public PKCE clients — but
// the branch must be correct or a future confidential client gets a
// non-conformant response.
func TestTokenHandler_BasicAuthRejectionIs401WithChallenge(t *testing.T) {
	o := newTokenErrorTestHandler(t)
	o.AuthExchanger.config.Clients["confidential"] = AuthClient{
		ClientID:     "confidential",
		ClientSecret: "correct-secret",
	}

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}}
	req := httptest.NewRequest(http.MethodPost, "/-/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("confidential", "wrong-secret")
	rec := httptest.NewRecorder()
	o.OAuth2TokenHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"5.2 requires 401 when client auth was attempted via the Authorization header")
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"),
		"a 401 from the token endpoint must carry WWW-Authenticate")
	assert.Equal(t, "invalid_client", decodeOAuthError(t, rec)["error"])
}

// TestTokenHandler_NoStoreOnBothPaths pins RFC 6749 5.1's caching
// requirement, which the endpoint omitted entirely before #168. A cached
// token response is a credential leak into any shared cache on the path.
func TestTokenHandler_NoStoreOnBothPaths(t *testing.T) {
	rec := postToken(t, newTokenErrorTestHandler(t), url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"DEADBEEFNOTAREALTOKEN000000"},
		"client_id":     {"app"},
	})
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"error responses from the token endpoint must be no-store (5.1)")

	// The success path is exercised end-to-end by minting a live refresh
	// token and redeeming it.
	o := newTokenErrorTestHandler(t)
	tokenID, err := o.AuthExchanger.createRefreshToken(context.Background(), RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	rec = postToken(t, o, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenID},
		"client_id":     {"app"},
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"success responses from the token endpoint must be no-store (5.1)")
}

// TestTokenHandler_ResourcePATErrorPathIsJSON pins the #168 review finding
// that writeResourcePATResponse — the code path serving MCP clients, the
// exact client class #168 was filed about — still used http.Error and
// carried no no-store headers on its own failure branch after the rest of
// the handler was fixed. It drives a real MintResourcePAT failure (the
// rotation-test Exchanger's config carries no TokenManager) through a
// resource-bound refresh_token redemption, which only enters
// writeResourcePATResponse when ResourceAudiences actually contains the
// requested resource.
func TestTokenHandler_ResourcePATErrorPathIsJSON(t *testing.T) {
	o := newTokenErrorTestHandler(t)
	resource := "https://mcp.example.test/tools"
	o.ResourceAudiences[resource] = true

	tokenID, err := o.AuthExchanger.createRefreshToken(context.Background(), RefreshTokenClaims{
		AuthMethod: AuthMethodLocal,
		ClientID:   "app",
		Subject:    "alice",
		Scope:      "openid",
	})
	require.NoError(t, err)

	rec := postToken(t, o, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenID},
		"client_id":     {"app"},
		"resource":      {resource},
	})

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"the resource-PAT error path must be no-store too, not just the standard path (#168)")
	body := decodeOAuthError(t, rec)
	assert.Equal(t, "server_error", body["error"])
	assert.NotContains(t, body["error_description"], "token manager",
		"the resource-PAT error path must not echo internals either (#168)")
}

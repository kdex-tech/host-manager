package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWriteOAuthError_Shape pins the RFC 6749 5.2 response shape: JSON body
// with an `error` code, and no-store caching headers. A text/plain body
// gives a conforming client nothing to parse — that is #168.
func TestWriteOAuthError_Shape(t *testing.T) {
	rec := httptest.NewRecorder()
	writeOAuthError(rec, http.StatusBadRequest, "invalid_grant", "refresh token not found or expired")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rec.Header().Get("Pragma"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "refresh token not found or expired", body["error_description"])
}

// TestOAuthErrorForRedemption pins the classifier's allowlist. A prior
// revision treated "not ErrServerError" as license to echo err.Error() —
// that leaked internal HTTP dial errors (service URL, pod IP) out of
// LoginLocal, and signer/resolver failures out of mintTokensFromCode, on
// every authorization_code redemption. Review caught it; see
// kdex-tech/host-manager#168. The allowlist is: ErrServerError -> 500
// generic; ErrGrantFailure -> 400 with its own message (deliberately
// client-facing); anything else -> 400 with a fixed generic message, cause
// logged only.
func TestOAuthErrorForRedemption(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantDescNot string
	}{
		{
			name:       "explicit grant failure echoes its own message",
			err:        errGrantFailureForTest(),
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_grant",
		},
		{
			name:        "infrastructure failure is a server error",
			err:         errServerFailureForTest(),
			wantStatus:  http.StatusInternalServerError,
			wantCode:    "server_error",
			wantDescNot: "cache unreachable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, code, desc := oauthErrorForRedemption(tc.err)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantCode, code)
			if tc.wantDescNot != "" {
				assert.NotContains(t, desc, tc.wantDescNot,
					"server_error must not echo internals to an unauthenticated caller")
			}
		})
	}
}

// TestOAuthErrorForRedemption_DefaultIsClosed pins the regression the #168
// review caught: an error carrying NEITHER sentinel — the shape every
// infrastructure failure inside mintTokensFromCode, LoginLocal and
// LoginClient actually has today, since Task 3 wrapped only the seven sites
// inside RedeemRefreshToken/RedeemAuthorizationCode themselves — must still
// classify as invalid_grant, but with the fixed generic description, never
// its own text. The worst real instance of this is LoginLocal's HTTP
// identity-lookup failure, which can read
// `httpLookup: request: Post "http://<internal-svc>": dial tcp <pod-ip>:8080:
// connect: connection refused` — exactly the internal-service disclosure
// this default exists to prevent. A future error added anywhere in that
// call graph that forgets to opt in to ErrGrantFailure is safe BY DEFAULT,
// not by having remembered to wrap it — this test is what stops that
// property from regressing silently.
func TestOAuthErrorForRedemption_DefaultIsClosed(t *testing.T) {
	err := errUnmarkedInternalForTest()

	status, code, desc := oauthErrorForRedemption(err)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", code)
	assert.Equal(t, genericGrantFailureDescription, desc,
		"an error carrying neither sentinel must get the fixed generic description, not err.Error()")
	assert.NotContains(t, desc, "10.0.0.7",
		"an unmarked internal error must not leak its own text to an unauthenticated caller")
	assert.NotEqual(t, err.Error(), desc,
		"the default must not fall back to echoing the error's own message")
}

// errGrantFailureForTest is the shape RedeemRefreshToken/RedeemAuthorizationCode
// now produce for a rejection genuinely about the presented grant (e.g. a
// dead refresh token) — explicitly marked, so its message is client-facing
// by design.
func errGrantFailureForTest() error {
	return fmt.Errorf("%w: refresh token not found or expired", ErrGrantFailure)
}

// errUnmarkedInternalForTest is the shape an infrastructure failure produces
// when nothing along its call path has opted it in to either sentinel — the
// pre-review LoginLocal leak, reproduced.
func errUnmarkedInternalForTest() error {
	return fmt.Errorf("httpLookup: request: Post \"http://identity-svc.internal:8080\": dial tcp 10.0.0.7:8080: connect: connection refused")
}

// errServerFailureForTest is the shape an infrastructure failure produces
// after Task 3's wrapping.
func errServerFailureForTest() error {
	return fmt.Errorf("%w: failed to read refresh token: %v", ErrServerError, "cache unreachable")
}

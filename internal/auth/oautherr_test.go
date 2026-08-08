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

// TestOAuthErrorForRedemption pins the classification that makes #168 safe:
// an infrastructure failure must become 500 server_error with a GENERIC
// description, never 400 invalid_grant with internals echoed to an
// unauthenticated caller.
func TestOAuthErrorForRedemption(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantDescNot string
	}{
		{
			name:       "dead refresh token is a grant failure",
			err:        errDeadGrantForTest(),
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

// errDeadGrantForTest is the shape a dead refresh token produces: a plain
// error carrying no ErrServerError.
func errDeadGrantForTest() error {
	return fmt.Errorf("refresh token not found or expired")
}

// errServerFailureForTest is the shape an infrastructure failure produces
// after Task 3's wrapping.
func errServerFailureForTest() error {
	return fmt.Errorf("%w: failed to read refresh token: %v", ErrServerError, "cache unreachable")
}

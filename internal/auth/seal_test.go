package auth

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealRoundTripsPerPurpose(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	s, err := ex.sealJSON(sealPurposeConsent, map[string]string{"a": "b"})
	require.NoError(t, err)

	var got map[string]string
	require.NoError(t, ex.openJSON(sealPurposeConsent, s, &got))
	assert.Equal(t, "b", got["a"])

	// a seal for one purpose does not open under another
	assert.ErrorIs(t, ex.openJSON(sealPurposeLoginState, s, &got), errSealDecrypt)
	assert.ErrorIs(t, ex.openJSON(sealPurposeConsent, "not-a-jwe", &got), errSealParse)
}

// Authorization codes keep the key they had before the helper existed, so
// codes minted just before the rollout still redeem after it.
func TestSealAuthCodeKeyIsUnchanged(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	legacy := sha256.Sum256([]byte(ex.config.OIDC.BlockKey))
	assert.Equal(t, legacy[:], ex.sealKey(sealPurposeAuthCode))
	assert.NotEqual(t, legacy[:], ex.sealKey(sealPurposeConsent))
}

// Login-state cookies keep the key they had before the helper existed.
func TestSealLoginStateKeyIsUnchanged(t *testing.T) {
	ex, _ := newTestExchangerWithDCR(t)
	legacy := sha256.Sum256([]byte("oidc-login-state\x00" + ex.config.OIDC.BlockKey))
	assert.Equal(t, legacy[:], ex.sealKey(sealPurposeLoginState))
}

package host

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// Scriptless is a rule of the Consent type, not a per-call option: rendering
// a Consent page through the ordinary renderer leaves out every script.
func TestRenderUtilityPage_ConsentIsAlwaysScriptless(t *testing.T) {
	hh, _ := newConsentPageHost(t, consentArchetype, consentBlockSlot)
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	ph := hh.utilityPages[kdexv1alpha1.ConsentUtilityPageType]
	rendered, err := hh.L10nRender(ph, map[string]any{}, language.English,
		map[string]any{"consent": map[string]any{"Block": "BLOCK"}}, &hh.Translations)
	require.NoError(t, err)
	assert.Contains(t, rendered, consentHeader)
	assert.NotContains(t, rendered, "importmap")
	assert.NotContains(t, rendered, "console.log")
	assert.NotContains(t, rendered, "NAV")

	// Another type keeps its scripts.
	ph.UtilityPage = &kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.LoginUtilityPageType}
	rendered, err = hh.L10nRender(ph, map[string]any{}, language.English, map[string]any{}, &hh.Translations)
	require.NoError(t, err)
	assert.Contains(t, rendered, "console.log")
}

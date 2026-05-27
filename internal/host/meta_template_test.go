package host

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKdexUIMetaTemplate_TranslationPathParity ensures the meta tag's
// data-path-translations attribute advertises the same path that the
// translation HTTP handler actually mounts at. Before the fix the meta tag
// emitted "/-/translations/{l10n}" (plural) while the handler lived at
// "/-/translation/{l10n}" (singular), so any client that read the meta tag
// literally would 404. See kdex-tech/host-manager#35.
func TestKdexUIMetaTemplate_TranslationPathParity(t *testing.T) {
	// The mounter (handlers.go translationHandler) uses
	// `/-/translation/{l10n}` — the singular form. The emitter (this
	// template) must match.
	assert.Contains(t, kdexUIMetaTemplate, `data-path-translations="/-/translation/{l10n}"`,
		"meta tag's data-path-translations must match the singular path mounted by translationHandler")
	assert.NotContains(t, kdexUIMetaTemplate, `data-path-translations="/-/translations/{l10n}"`,
		"meta tag must not advertise the plural form — it 404s on a literal follow")
}

// TestKdexUIMetaTemplate_HasAllExpectedAttributes guards against accidental
// drift in the meta-tag contract that downstream clients (knowdrive-l10n,
// @kdex-tech/ui) rely on for endpoint discovery.
func TestKdexUIMetaTemplate_HasAllExpectedAttributes(t *testing.T) {
	required := []string{
		`name="kdex-ui"`,
		`data-navigation-endpoint=`,
		`data-openapi-endpoint=`,
		`data-page-basepath=`,
		`data-path-check=`,
		`data-path-login=`,
		`data-path-logout=`,
		`data-path-state=`,
		`data-path-separator=`,
		`data-path-translations=`,
	}
	for _, attr := range required {
		t.Run(strings.TrimSuffix(attr, "="), func(t *testing.T) {
			assert.Contains(t, kdexUIMetaTemplate, attr,
				"meta tag attribute %q missing — downstream clients depend on it for endpoint discovery", attr)
		})
	}
}

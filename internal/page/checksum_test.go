package page

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// TestPageHandler_Checksum_StatusNilCollapsesKey documents the bug fixed in
// kdexpage_controller.go: when PageHandler.Status is nil (the pre-fix state),
// Checksum returns the empty string and every page's CacheKey collapses to
// "<name>::<lang>" — the page-render cache never invalidates.
func TestPageHandler_Checksum_StatusNilCollapsesKey(t *testing.T) {
	ph := PageHandler{Name: "page-home"}
	assert.Equal(t, "", ph.Checksum(),
		"nil Status must collapse Checksum to empty string (this is the bug the controller fix avoids)")

	assert.Equal(t, "page-home::en", ph.CacheKey(language.English),
		"with empty Checksum the CacheKey contains no entropy from page state")
}

// TestPageHandler_Checksum_StatusAttributesShiftKey verifies the fix: when
// the controller wires Status into PageHandler, mutations of
// Status.Attributes (e.g. header.generation flipping when the referenced
// KDexPageHeader's content changes) produce a different cache key.
func TestPageHandler_Checksum_StatusAttributesShiftKey(t *testing.T) {
	status := &kdexv1alpha1.KDexObjectStatus{
		ObservedGeneration: 1,
		Attributes: map[string]string{
			"header.generation":    "1",
			"footer.generation":    "1",
			"archetype.generation": "1",
		},
	}
	ph := PageHandler{Name: "page-home", Status: status}

	baseline := ph.Checksum()
	assert.NotEmpty(t, baseline, "non-nil Status should produce a non-empty Checksum")

	// Same input → same output.
	assert.Equal(t, baseline, ph.Checksum(), "checksum must be stable for unchanged Status")

	// Bump header.generation (simulates the referenced KDexPageHeader's spec
	// changing — the controller writes the new gen to Status.Attributes).
	status.Attributes["header.generation"] = "2"
	mutatedHeader := PageHandler{Name: "page-home", Status: status}
	assert.NotEqual(t, baseline, mutatedHeader.Checksum(),
		"changing Status.Attributes['header.generation'] must invalidate the cache key")

	// Bumping the page's own ObservedGeneration (simulates editing
	// KDexPage.spec, e.g. switching overrideHeaderRef) also invalidates.
	status.Attributes["header.generation"] = "1"
	status.ObservedGeneration = 2
	mutatedObs := PageHandler{Name: "page-home", Status: status}
	assert.NotEqual(t, baseline, mutatedObs.Checksum(),
		"changing Status.ObservedGeneration must invalidate the cache key")
}

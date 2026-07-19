package auth

import (
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/stretchr/testify/assert"
)

// An opaque (colon-less) capability scope is immune to wildcard grants: a
// covering wildcard neither dominates it nor absorbs it under Compact. That
// immunity is what makes a context-less capability un-inheritable via
// verbs:[all] (kdex-crds#15) -- the whole reason a role emits opaque scopes
// verbatim rather than as a structured pattern.
//
// host-manager depends on this property directly: the entitlements claim
// transits entitlements.Compact at sign time (internal/sign/sign.go), so an
// opaque grant co-resident with a covering wildcard must survive compaction.
// This pins the property in-repo rather than trusting the pinned dependency
// silently -- a regression or mis-pin of github.com/kdex-tech/entitlements/go
// would fail here.
func TestOpaqueScope_ImmuneToWildcard(t *testing.T) {
	const opaque = "vector_stores_create"
	const wildcard = "vector_stores::all" // short form of vector_stores:*:all

	assert.False(t, entitlements.Dominates(wildcard, opaque),
		"a wildcard grant must NOT dominate an opaque scope")
	assert.False(t, entitlements.Dominates(opaque, wildcard),
		"an opaque scope must NOT dominate a wildcard grant")

	compacted := entitlements.Compact([]string{wildcard, opaque})
	assert.Contains(t, compacted, opaque,
		"Compact must retain the opaque scope alongside a covering wildcard")
}

package host

import (
	"testing"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A page (or host-level) security block has no per-request store identity and
// no x-entitlement-binding, so a {placeholder} requirement can never be bound
// at the page layer. Left as the literal resourceName "{vector_store_id}", it
// is matched by a held wildcard (vector_stores::all) -- silently admitting
// every wildcard holder. parsePageRequirementsFailClosed must detect the
// unbindable placeholder and substitute an unsatisfiable requirement so all
// three page readers (render, navigation, /-/check) deny.
func TestParsePageRequirements_UnbindablePlaceholderDeniesWildcardHolder(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "foo", nil)
	require.NoError(t, err)

	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	realChecker := auth.NewAuthorizationChecker(nil, logr.Discard())
	hh.authChecker = realChecker

	const basePath = "/store"
	reqs := []kdexv1alpha1.SecurityRequirement{
		{"bearer": {"vector_stores:{vector_store_id}:read"}},
	}

	parsed := hh.parsePageRequirementsFailClosed(reqs, "store-page", basePath)

	// A wildcard holder: has the page identity AND a wildcard vector_stores
	// grant that satisfies any single store. Under the pre-fix behaviour the
	// placeholder verifies as a literal that this wildcard matches.
	held := realChecker.ParseEntitlements(entitlements.Entitlements{
		"bearer": {"pages:" + basePath + ":read", "vector_stores:*:read"},
	})

	authorized, err := realChecker.VerifyResourceParsedEntitlements(
		"pages", basePath, held, parsed)
	require.NoError(t, err)
	assert.False(t, authorized,
		"a wildcard vector_stores holder must NOT be admitted to a page whose requirement carries an unbindable {placeholder}")
}

// Control: a page whose requirement names a concrete store must keep admitting
// the holder of that exact grant -- the fail-closed substitution must fire only
// on an unbindable placeholder, never on an ordinary requirement.
func TestParsePageRequirements_ConcreteRequirementAdmitsMatchingHolder(t *testing.T) {
	cacheManager, err := cache.NewCacheManager("", "foo", nil)
	require.NoError(t, err)

	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cacheManager)
	realChecker := auth.NewAuthorizationChecker(nil, logr.Discard())
	hh.authChecker = realChecker

	const basePath = "/store"
	reqs := []kdexv1alpha1.SecurityRequirement{
		{"bearer": {"vector_stores:vs_alice:read"}},
	}

	parsed := hh.parsePageRequirementsFailClosed(reqs, "store-page", basePath)

	held := realChecker.ParseEntitlements(entitlements.Entitlements{
		"bearer": {"pages:" + basePath + ":read", "vector_stores:vs_alice:read"},
	})

	authorized, err := realChecker.VerifyResourceParsedEntitlements(
		"pages", basePath, held, parsed)
	require.NoError(t, err)
	assert.True(t, authorized,
		"a concrete-store holder must still be admitted to a page requiring that exact store")
}

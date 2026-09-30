package rewrite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlaceholders(t *testing.T) {
	assert.Equal(t, []string{"user", "rest"}, Placeholders("u/{user}/x/{rest}"))
	assert.Empty(t, Placeholders("static/path"))
	assert.Empty(t, Placeholders(""))
}

func TestUnknownPlaceholders(t *testing.T) {
	assert.Empty(t, UnknownPlaceholders("{rest}", "/docs/latest/{rest...}"))
	assert.Empty(t, UnknownPlaceholders("{a}/{b}", "/x/{a}/{b}/{$}"))
	assert.Equal(t, []string{"id"}, UnknownPlaceholders("{id}", "/alias/{user}"))
	assert.Equal(t, []string{"id"}, UnknownPlaceholders("{id}", ""))
	assert.Empty(t, UnknownPlaceholders("", ""))
}

func vals(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestTarget(t *testing.T) {
	cases := []struct {
		name, base, exact, tmpl string
		v                       map[string]string
		want                    string
	}{
		{"empty path uses exact form", "/docs/v3", "/docs/v3", "", nil, "/docs/v3"},
		{"one slash at the seam", "/docs/v3", "/docs/v3", "{rest}", map[string]string{"rest": "a/b"}, "/docs/v3/a/b"},
		{"base trailing slash collapsed", "/docs/v3/", "/docs/v3/", "/{rest}", map[string]string{"rest": "a"}, "/docs/v3/a"},
		{"author trailing slash kept", "/profile", "/profile", "{user}/", map[string]string{"user": "bob"}, "/profile/bob/"},
		{"empty rest value", "/docs/v3", "/docs/v3", "{rest}", map[string]string{"rest": ""}, "/docs/v3/"},
		{"function target", "/api/downloads", "/api/downloads", "{id}", map[string]string{"id": "42"}, "/api/downloads/42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Target(c.base, c.exact, c.tmpl, "/x/{rest...}/{user}/{id}", vals(c.v))
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestTarget_RefusesUnsafeSubstitutions(t *testing.T) {
	for name, v := range map[string]string{
		"dot-dot":          "..",
		"embedded dot-dot": "a/../../etc",
		"dot":              ".",
		"double slash":     "a//b",
		"leading slash":    "/abs", // would create "//" at the seam
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Target("/docs/v3", "/docs/v3", "{rest}", "/d/{rest...}", vals(map[string]string{"rest": v}))
			assert.ErrorIs(t, err, ErrUnsafe)
		})
	}
}

// A {name...} copied from patternPath into rewrite.path is the same
// placeholder as {name}, never literal text (final review I3).
func TestPlaceholders_AcceptMultiSegmentSuffix(t *testing.T) {
	assert.Equal(t, []string{"rest"}, Placeholders("{rest...}"))
	assert.Equal(t, []string{"user", "rest"}, Placeholders("u/{user}/x/{rest...}"))
	assert.Empty(t, UnknownPlaceholders("{rest...}", "/d/{rest...}"))
	assert.Equal(t, []string{"id"}, UnknownPlaceholders("{id...}", "/d/{rest...}"))

	got, err := Target("/docs/v3", "/docs/v3", "{rest...}", "/d/{rest...}", vals(map[string]string{"rest": "a/b"}))
	require.NoError(t, err)
	assert.Equal(t, "/docs/v3/a/b", got)
}

// A single-segment {name} wildcard never spans segments: its value can hold
// a '/' only via a decoded %2F, which must not reach another route of the
// target (final review I1).
func TestTarget_SingleSegmentValueWithSlashIsNotFound(t *testing.T) {
	_, err := Target("/", "/", "{id}", "/m/{id}", vals(map[string]string{"id": "-/userinfo"}))
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = Target("/", "/", "{id}", "/m/{id}", vals(map[string]string{"id": ".well-known/x"}))
	assert.ErrorIs(t, err, ErrNotFound)
	// Even when rewrite.path spells it {id...}: multi-ness is patternPath's.
	_, err = Target("/", "/", "{id...}", "/m/{id}", vals(map[string]string{"id": "a/b"}))
	assert.ErrorIs(t, err, ErrNotFound)
	// A multi-segment wildcard may span segments.
	got, err := Target("/", "/", "{rest}", "/m/{rest...}", vals(map[string]string{"rest": "a/b"}))
	require.NoError(t, err)
	assert.Equal(t, "/a/b", got)
	// Traversal in a single-segment value is still unsafe (400), not 404.
	_, err = Target("/p", "/p", "{id}", "/m/{id}", vals(map[string]string{"id": ".."}))
	assert.ErrorIs(t, err, ErrUnsafe)
}

// An empty value that leaves '//' is a missing segment, not a malformed one
// (final review M1): 404, while '..', '.', and a value that itself holds '//'
// or a leading '/' stay ErrUnsafe.
func TestTarget_EmptyValueLeavingDoubleSlashIsNotFound(t *testing.T) {
	_, err := Target("/profile", "/profile", "{user}/", "/u/{user}", vals(map[string]string{"user": ""}))
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = Target("/profile", "/profile", "a/{x}/b", "/u/{x}", vals(map[string]string{"x": ""}))
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = Target("/d", "/d", "{x}/{rest}", "/u/{x}/{rest...}", vals(map[string]string{"x": "", "rest": "a//b"}))
	assert.ErrorIs(t, err, ErrUnsafe, "an empty value never masks a genuinely unsafe one")
}

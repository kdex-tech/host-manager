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
		{"empty path uses exact form", "/docs/v3", "/docs/v3/", "", nil, "/docs/v3/"},
		{"one slash at the seam", "/docs/v3", "/docs/v3/", "{rest}", map[string]string{"rest": "a/b"}, "/docs/v3/a/b"},
		{"base trailing slash collapsed", "/docs/v3/", "/docs/v3/", "/{rest}", map[string]string{"rest": "a"}, "/docs/v3/a"},
		{"author trailing slash kept", "/profile", "/profile/", "{user}/", map[string]string{"user": "bob"}, "/profile/bob/"},
		{"empty rest value", "/docs/v3", "/docs/v3/", "{rest}", map[string]string{"rest": ""}, "/docs/v3/"},
		{"function target", "/api/downloads", "/api/downloads", "{id}", map[string]string{"id": "42"}, "/api/downloads/42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Target(c.base, c.exact, c.tmpl, vals(c.v))
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
			_, err := Target("/docs/v3", "/docs/v3/", "{rest}", vals(map[string]string{"rest": v}))
			assert.ErrorIs(t, err, ErrUnsafe)
		})
	}
	_, err := Target("/profile", "/profile/", "a/{x}/b", vals(map[string]string{"x": ""}))
	assert.ErrorIs(t, err, ErrUnsafe, "an empty mid-path value produces '//'")
}

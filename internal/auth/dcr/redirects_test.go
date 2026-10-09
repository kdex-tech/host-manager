package dcr

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterRedirectURIs_KeepsAllowedInOrderWithoutDuplicates(t *testing.T) {
	got := FilterRedirectURIs([]string{
		"https://app.example/cb",
		"http://127.0.0.1:3000/cb",
		"https://app.example/cb",
		"javascript://x",
	}, DefaultRedirectSchemes)
	assert.Equal(t, []string{"https://app.example/cb", "http://127.0.0.1:3000/cb"}, got)
}

func TestFilterRedirectURIs_RefusesAmbiguousURIs(t *testing.T) {
	for _, uri := range []string{
		"https://app.example@other.example/cb", // userinfo
		"https://app.example/cb#frag",          // fragment
		"https://app.example/cb#",              // empty fragment
		"https:///cb",                          // empty host
		"https://xn--clude-6ve.ai/cb#",         // fragment again (punycode host itself is fine)
		"https://clаude.ai/cb",            // non-ASCII host (Cyrillic a)
		"https://a‮b.example/cb",          // bidi override in host
		"https://app.example/" + strings.Repeat("a", 2100),
		"",
	} {
		assert.Empty(t, FilterRedirectURIs([]string{uri}, DefaultRedirectSchemes), uri)
	}
}

func TestFilterRedirectURIs_SchemePolicies(t *testing.T) {
	schemes := []string{"https", SchemeLoopback, SchemePrivateUse, "cursor"}
	for uri, want := range map[string]bool{
		"https://app.example/cb":          true,
		"http://localhost:8080/cb":        true,
		"http://app.example/cb":           false, // cleartext non-loopback
		"com.example.app:/oauth2redirect": true,  // private-use, no host
		"cursor://anysphere.cursor/cb":    true,  // explicit literal
		"vscode://x/cb":                   false, // not listed
		"data:text/html,x":                false,
	} {
		assert.Equal(t, want, len(FilterRedirectURIs([]string{uri}, schemes)) == 1, uri)
	}
	// a dangerous scheme is never honoured even when listed
	assert.Empty(t, FilterRedirectURIs([]string{"javascript:alert(1)"}, []string{"javascript"}))
	// a bare http literal is never honoured
	assert.Empty(t, FilterRedirectURIs([]string{"http://app.example/cb"}, []string{"http"}))
}

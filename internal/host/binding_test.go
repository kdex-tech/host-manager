package host

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/stretchr/testify/assert"
)

func TestPathParamFromMatch(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		uriPath   string
		param     string
		wantVal   string
		wantFound bool
	}{
		{"simple", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs_abc", "vector_store_id", "vs_abc", true},
		{"middle segment", "/v1/vector_stores/{vector_store_id}/files", "/v1/vector_stores/vs_abc/files", "vector_store_id", "vs_abc", true},
		{"two params picks the right one", "/v1/vector_stores/{vector_store_id}/files/{file_id}", "/v1/vector_stores/vs_abc/files/f_1", "file_id", "f_1", true},
		{"param absent from pattern", "/v1/ingest", "/v1/ingest", "vector_store_id", "", false},
		{"segment count mismatch", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs_abc/files", "vector_store_id", "", false},
		{"percent-decoded", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/vs%2Fabc", "vector_store_id", "vs/abc", true},
		{"catch-all: earlier param still found", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores/vs_abc/path/content/a/b/c.md", "vector_store_id", "vs_abc", true},
		{"catch-all is never a target", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores/vs_abc/path/content/a/b", "uri", "", false},
		{"catch-all with too-short uri", "/v1/vector_stores/{vector_store_id}/path/content/{uri...}", "/v1/vector_stores", "vector_store_id", "", false},
		{"empty value is not found", "/v1/vector_stores/{vector_store_id}", "/v1/vector_stores/", "vector_store_id", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotFound := pathParamFromMatch(tt.pattern, tt.uriPath, tt.param)
			assert.Equal(t, tt.wantVal, gotVal)
			assert.Equal(t, tt.wantFound, gotFound)
		})
	}
}

func TestParseBindingSpec(t *testing.T) {
	t.Run("absent extension yields nil spec and no error", func(t *testing.T) {
		got, err := parseBindingSpec(map[string]any{})
		assert.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("single header source", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "header", "name": "X-Vector-Store-Id"}},
		}}
		got, err := parseBindingSpec(ext)
		assert.NoError(t, err)
		assert.Equal(t, []bindingSource{{In: "header", Name: "X-Vector-Store-Id"}}, got["vector_store_id"])
	})

	t.Run("ordered chain preserves order", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{
				map[string]any{"in": "query", "name": "vector_store_id"},
				map[string]any{"in": "header", "name": "X-Vector-Store-Id"},
			},
		}}
		got, err := parseBindingSpec(ext)
		assert.NoError(t, err)
		assert.Equal(t, []bindingSource{
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}, got["vector_store_id"])
	})

	t.Run("rejects an AS-unreadable location", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "body", "name": "vector_store_id"}},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{map[string]any{"in": "header", "name": ""}},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects an empty chain", func(t *testing.T) {
		ext := map[string]any{"x-entitlement-binding": map[string]any{
			"vector_store_id": []any{},
		}}
		_, err := parseBindingSpec(ext)
		assert.Error(t, err)
	})

	t.Run("rejects a non-object extension", func(t *testing.T) {
		_, err := parseBindingSpec(map[string]any{"x-entitlement-binding": "nonsense"})
		assert.Error(t, err)
	})
}

func TestResolveBinding(t *testing.T) {
	t.Run("path identity match with no spec", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/vector_stores/vs_abc", nil)
		got := resolveBinding(r, "/v1/vector_stores/{vector_store_id}", nil, []string{"vector_store_id"})
		assert.Equal(t, "vs_abc", got["vector_store_id"])
	})

	// Each path segment is decoded exactly once, so the gate binds the
	// instance the backend's r.PathValue addresses. Go has already decoded
	// r.URL.Path; matching against it decoded %25 a second time and split a
	// segment at %2F. See #230.
	t.Run("path segment decoded exactly once", func(t *testing.T) {
		const pattern = "/v1/roles/{key}"
		for _, tc := range []struct{ target, want string }{
			{"/v1/roles/analysts", "analysts"},
			{"/v1/roles/a%20b", "a b"},
			{"/v1/roles/a%2525", "a%25"},
			{"/v1/roles/a%2Fb", "a/b"},
		} {
			implicit := resolveBinding(httptest.NewRequest("PUT", tc.target, nil), pattern, nil, []string{"key"})
			assert.Equal(t, entitlements.Binding{"key": tc.want}, implicit, "implicit path match for %s", tc.target)

			spec := bindingSpec{"role": {{In: "path", Name: "key"}}}
			declared := resolveBinding(httptest.NewRequest("PUT", tc.target, nil), pattern, spec, []string{"role"})
			assert.Equal(t, entitlements.Binding{"role": tc.want}, declared, "declared path source for %s", tc.target)
		}
	})

	t.Run("declared header source", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_abc")
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_abc", got["vector_store_id"])
	})

	t.Run("chain: first link wins", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/search?vector_store_id=vs_query", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_header")
		spec := bindingSpec{"vector_store_id": {
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}}
		got := resolveBinding(r, "/v1/search", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_query", got["vector_store_id"], "query must outrank header")
	})

	t.Run("chain: falls through to the second link", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/search", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_header")
		spec := bindingSpec{"vector_store_id": {
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}}
		got := resolveBinding(r, "/v1/search", spec, []string{"vector_store_id"})
		assert.Equal(t, "vs_header", got["vector_store_id"])
	})

	t.Run("unresolvable key is ABSENT, never defaulted", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "unresolved key must be absent so BindRequirements errors")
	})

	t.Run("declared chain that fails must NOT fall back to the path", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/vector_stores/vs_attacker", nil)
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/vector_stores/{vector_store_id}", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "a declared chain that fails to resolve must not fall back to the path identity match, or a caller-controlled path segment could satisfy a header-declared placeholder")
	})

	t.Run("empty value is absent", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest?vector_store_id=", nil)
		spec := bindingSpec{"vector_store_id": {{In: "query", Name: "vector_store_id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "an empty value must not bind")
	})

	// The backend acts on the raw value, so the gate must check the raw
	// value. Trimming bound "vs1" for "?vector_store_id=%20vs1%20" while the
	// backend addressed " vs1 " -- a different, look-alike instance.
	t.Run("values bind raw, never trimmed", func(t *testing.T) {
		q := httptest.NewRequest("GET", "/v1/search?vector_store_id=%20vs1%20", nil)
		qs := bindingSpec{"vector_store_id": {{In: "query", Name: "vector_store_id"}}}
		assert.Equal(t, entitlements.Binding{"vector_store_id": " vs1 "},
			resolveBinding(q, "/v1/search", qs, []string{"vector_store_id"}))

		p := httptest.NewRequest("PUT", "/v1/roles/%20analysts", nil)
		ps := bindingSpec{"role": {{In: "path", Name: "key"}}}
		assert.Equal(t, entitlements.Binding{"role": " analysts"},
			resolveBinding(p, "/v1/roles/{key}", ps, []string{"role"}))

		h := httptest.NewRequest("POST", "/v1/ingest", nil)
		h.Header.Set("X-Vector-Store-Id", "vs1\u00a0")
		hs := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		assert.Equal(t, entitlements.Binding{"vector_store_id": "vs1\u00a0"},
			resolveBinding(h, "/v1/ingest", hs, []string{"vector_store_id"}))
	})

	// A whitespace-only value is present to the backend, so it must not fall
	// through to the next link: the gate would then check a different source
	// from the one the backend acts on.
	t.Run("whitespace-only value does not fall through the chain", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/search?vector_store_id=%20%20", nil)
		r.Header.Set("X-Vector-Store-Id", "vs_header")
		spec := bindingSpec{"vector_store_id": {
			{In: "query", Name: "vector_store_id"},
			{In: "header", Name: "X-Vector-Store-Id"},
		}}
		got := resolveBinding(r, "/v1/search", spec, []string{"vector_store_id"})
		assert.Equal(t, "  ", got["vector_store_id"])
	})

	t.Run("resolves only requested keys", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/vector_stores/vs_abc/files/f_1", nil)
		got := resolveBinding(r, "/v1/vector_stores/{vector_store_id}/files/{file_id}", nil, []string{"vector_store_id"})
		_, present := got["file_id"]
		assert.False(t, present)
	})

	t.Run("no keys yields a nil binding", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/ingest", nil)
		assert.Nil(t, resolveBinding(r, "/v1/ingest", nil, nil))
	})
}

func TestPlaceholderKeys(t *testing.T) {
	t.Run("union of declared keys and pattern params, deduped", func(t *testing.T) {
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := placeholderKeys(spec, "/v1/vector_stores/{vector_store_id}/files/{file_id}")
		assert.ElementsMatch(t, []string{"vector_store_id", "file_id"}, got)
	})

	t.Run("catch-all is not a key", func(t *testing.T) {
		got := placeholderKeys(nil, "/v1/vector_stores/{vector_store_id}/path/content/{uri...}")
		assert.ElementsMatch(t, []string{"vector_store_id"}, got)
	})

	t.Run("no spec and no params yields empty", func(t *testing.T) {
		assert.Empty(t, placeholderKeys(nil, "/v1/ingest"))
	})
}

// A bracketed bound name's aliases are the keys PHP reads as it -- text after
// its ']' is dropped, an empty [] matches any index -- and the bare base that
// replaces the array; its sibling segments are not aliases. A plain bound
// name's alias is any key with the same base.
func TestAmbiguousQueryName(t *testing.T) {
	for _, tc := range []struct {
		bound, other string
		alias        bool
	}{
		{"filter[store]", "filter[status]", false},
		{"filter[store]", "filter[store]x", true},
		{"filter[store]", "filter[store]]", true},
		{"filter[store]", "FILTER[STORE]", true},
		{"filter[store]", "filter[store][y]", true},
		{"filter[store]", "filter[store][]", true},
		{"filter[store]", "filter[]", true},
		{"filter[store]", "filter", true},
		{"filter[store]", "filters[store]", false},
		{"ids[]", "ids[0]", true},
		{"store", "store[]", true},
		{"store", "store[x]", true},
		{"store", "STORE", true},
		{"store", "st.ore", false},
		{"vector_store_id", "vector.store.id", true},
		{"vector_store_id", " vector_store_id", true},
		{"vector_store_id", "vector_store_id\x00x", true},
		{"vector_store_id", "vector_store", false},
		{"filter[store]", "filter" + strings.Repeat("[x]", 65), true},
		{"filter[store]", "filter" + strings.Repeat("[x]", 64), false},
	} {
		q := url.Values{tc.bound: {"mine"}, tc.other: {"theirs"}}
		assert.Equal(t, tc.alias, ambiguousQueryName(q, tc.bound), "%s vs %q", tc.bound, tc.other)
	}
	assert.True(t, ambiguousQueryName(url.Values{"store": {"a", "b"}}, "store"), "a repeated name")
	assert.False(t, ambiguousQueryName(url.Values{"store": {"a"}, "other": {"b"}}, "store"))
}

// The query is the caller's, so another key is parsed only as far as the
// comparison needs: a key of a million bytes of [] costs a scan, not a slice
// per segment.
func TestAmbiguousQueryName_DoesNotParseOtherKeysWhole(t *testing.T) {
	q := url.Values{
		"vector_store_id":                                {"mine"},
		"z" + strings.Repeat("[]", 500_000):              {"x"},
		"filter" + strings.Repeat("[]", 500_000):         {"x"},
		"Vector_Store_Id_X" + strings.Repeat("[a]", 100): {"x"},
	}
	for _, bound := range []string{"vector_store_id", "filter[store]"} {
		allocs := testing.AllocsPerRun(5, func() { ambiguousQueryName(q, bound) })
		assert.Less(t, allocs, 20.0, "bound %s: allocations must not grow with the size of another key", bound)
	}
}

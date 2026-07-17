package host

import (
	"net/http/httptest"
	"testing"

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

	t.Run("blank header is absent, not empty", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/v1/ingest", nil)
		r.Header.Set("X-Vector-Store-Id", "   ")
		spec := bindingSpec{"vector_store_id": {{In: "header", Name: "X-Vector-Store-Id"}}}
		got := resolveBinding(r, "/v1/ingest", spec, []string{"vector_store_id"})
		_, present := got["vector_store_id"]
		assert.False(t, present, "a blank value would be ErrInvalidBoundValue; it must not bind")
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

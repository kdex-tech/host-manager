package host

import (
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

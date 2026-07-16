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

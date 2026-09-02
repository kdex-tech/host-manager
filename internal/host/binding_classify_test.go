package host

import (
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
)

// bindFailureIsClientError is the #195 classifier: a bind failure is a
// caller-fixable 400 only when EVERY absent placeholder has a header/query
// source the caller could have supplied; anything the caller cannot supply
// (a path-only source, or no source at all) makes the whole failure a 500.
func TestBindFailureIsClientError(t *testing.T) {
	cases := []struct {
		name    string
		spec    bindingSpec
		binding entitlements.Binding
		keys    []string
		want    bool
	}{
		{
			name:    "declared header source omitted -> caller-fixable",
			spec:    bindingSpec{"vector_store_id": {{In: bindingInHeader, Name: "X-Vector-Store-Id"}}},
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id"},
			want:    true,
		},
		{
			name:    "declared query source omitted -> caller-fixable",
			spec:    bindingSpec{"vector_store_id": {{In: bindingInQuery, Name: "vector_store_id"}}},
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id"},
			want:    true,
		},
		{
			name:    "path-only source unmatched -> server fault",
			spec:    bindingSpec{"vector_store_id": {{In: bindingInPath, Name: "vector_store_id"}}},
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id"},
			want:    false,
		},
		{
			name:    "no declared source -> server fault",
			spec:    nil,
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id"},
			want:    false,
		},
		{
			name: "mixed: one caller-fixable, one path-only -> server fault",
			spec: bindingSpec{
				"vector_store_id": {{In: bindingInHeader, Name: "X-Vector-Store-Id"}},
				"tenant_id":       {{In: bindingInPath, Name: "tenant_id"}},
			},
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id", "tenant_id"},
			want:    false,
		},
		{
			name: "header chain with a path fallback is still caller-fixable",
			spec: bindingSpec{"vector_store_id": {
				{In: bindingInPath, Name: "vector_store_id"},
				{In: bindingInHeader, Name: "X-Vector-Store-Id"},
			}},
			binding: entitlements.Binding{},
			keys:    []string{"vector_store_id"},
			want:    true,
		},
		{
			name:    "all keys resolved (no absent) -> not a client error",
			spec:    bindingSpec{"vector_store_id": {{In: bindingInHeader, Name: "X-Vector-Store-Id"}}},
			binding: entitlements.Binding{"vector_store_id": "vs_abc"},
			keys:    []string{"vector_store_id"},
			want:    false,
		},
		{
			name:    "empty key set -> server fault (placeholder had no source at all)",
			spec:    nil,
			binding: entitlements.Binding{},
			keys:    nil,
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bindFailureIsClientError(tc.spec, tc.binding, tc.keys); got != tc.want {
				t.Fatalf("bindFailureIsClientError = %v, want %v", got, tc.want)
			}
		})
	}
}

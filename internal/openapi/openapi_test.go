package openapi

import (
	"fmt"
	"net/http"
	"testing"

	G "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func Test_ExtractPathParameters(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		query         string
		header        http.Header
		expectedCount int
		expectedNames []string
		expectedIn    []string // "path" or "query"
		expectedArray []bool   // whether parameter is an array
		hasWildcard   bool
	}{
		{
			name:          "simple path parameter",
			path:          "/users/{id}",
			expectedCount: 1,
			expectedNames: []string{"id"},
			expectedIn:    []string{"path"},
			expectedArray: []bool{false},
			hasWildcard:   false,
		},
		{
			name:          "multiple path parameters",
			path:          "/-/navigation/{navKey}/{l10n}/{basePathMinusLeadingSlash...}",
			expectedCount: 3,
			expectedNames: []string{"navKey", "l10n", "basePathMinusLeadingSlash"},
			expectedIn:    []string{"path", "path", "path"},
			expectedArray: []bool{false, false, false},
			hasWildcard:   true,
		},
		{
			name:          "localized path parameter",
			path:          "/-/translation/{l10n}",
			expectedCount: 1,
			expectedNames: []string{"l10n"},
			expectedIn:    []string{"path"},
			expectedArray: []bool{false},
			hasWildcard:   false,
		},
		{
			name:          "no parameters",
			path:          "/-/check/",
			expectedCount: 0,
			expectedNames: []string{},
			expectedIn:    []string{},
			expectedArray: []bool{},
			hasWildcard:   false,
		},
		{
			name:          "wildcard parameter",
			path:          "/static/{path...}",
			expectedCount: 1,
			expectedNames: []string{"path"},
			expectedIn:    []string{"path"},
			expectedArray: []bool{false},
			hasWildcard:   true,
		},
		{
			name:          "query parameters",
			path:          "/static",
			query:         "key=one&key=two",
			expectedCount: 1,
			expectedNames: []string{"key"},
			expectedIn:    []string{"query"},
			expectedArray: []bool{true}, // Array because key appears twice
			hasWildcard:   false,
		},
		{
			name: "header parameters",
			path: "/static",
			header: http.Header{
				"foo": []string{"bar"},
			},
			expectedCount: 1,
			expectedNames: []string{"foo"},
			expectedIn:    []string{"header"},
			expectedArray: []bool{true}, // Array because key appears twice
			hasWildcard:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := G.NewGomegaWithT(t)

			params := ExtractParameters(tt.path, tt.query, tt.header)

			g.Expect(params).To(G.HaveLen(tt.expectedCount), fmt.Sprintf("was %d", len(params)))

			for i, expectedName := range tt.expectedNames {
				g.Expect(params[i].Value.Name).To(G.Equal(expectedName))
				g.Expect(params[i].Value.In).To(G.Equal(tt.expectedIn[i]))

				// Path parameters are required, query parameters are optional
				if tt.expectedIn[i] == "path" {
					g.Expect(params[i].Value.Required).To(G.BeTrue())
				} else {
					g.Expect(params[i].Value.Required).To(G.BeFalse())
				}

				g.Expect(params[i].Value.Schema).NotTo(G.BeNil())
				g.Expect(params[i].Value.Schema.Value).NotTo(G.BeNil())

				// Check if array type matches expectation
				if tt.expectedArray[i] {
					g.Expect(params[i].Value.Schema.Value.Type.Is("array")).To(G.BeTrue())
					g.Expect(params[i].Value.Schema.Value.Items).NotTo(G.BeNil())
				} else if tt.expectedIn[i] == "query" {
					g.Expect(params[i].Value.Schema.Value.Type.Is("string")).To(G.BeTrue())
				}
			}

			if tt.hasWildcard && len(params) > 0 {
				// Check that at least one parameter has wildcard description
				foundWildcard := false
				for _, param := range params {
					if param.Value.Schema.Value.Description != "" {
						foundWildcard = true
						break
					}
				}
				g.Expect(foundWildcard).To(G.BeTrue(), "Expected to find wildcard parameter description")
			}
		})
	}
}

func Test_GenerateNameFromPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		headerName string
		want       string
	}{
		{
			name: "from simple path",
			path: "/users",
			want: "gen-users",
		},
		{
			name: "from nested path",
			path: "/api/v1/users",
			want: "gen-api-v1-users",
		},
		{
			name: "from pattern path",
			path: "/users/{id}",
			want: "gen-users-id",
		},
		{
			name: "from wildcard pattern",
			path: "/static/{path...}",
			want: "gen-static-path",
		},
		{
			name:       "from header name",
			path:       "/users",
			headerName: "custom-name",
			want:       "custom-name",
		},
		{
			name: "root path",
			path: "/",
			want: "gen-root",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateNameFromPath(tt.path, tt.headerName)
			assert.Equal(t, tt.want, got)
		})
	}
}

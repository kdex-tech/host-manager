package http

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/text/language"
)

func TestGetLang_NoHeaderFallsBackToDefault(t *testing.T) {
	// With languages = [de, en, fr] (alphabetical, as catalog.Builder
	// returns them) and no Accept-Language header, GetLang must return the
	// configured defaultLanguage ("en"), not whichever tag happened to sort
	// first.
	supported := []language.Tag{
		language.Make("de"),
		language.Make("en"),
		language.Make("fr"),
	}
	g := NewGomegaWithT(t)
	req := httptest.NewRequest("GET", "/", nil)
	got, err := GetLang(req, "en", supported)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(got).To(Equal(language.Make("en")))
}

func TestDecodeJSONBody(t *testing.T) {
	type Thing struct {
		Name string `json:"name"`
	}

	tests := []struct {
		name    string
		body    string
		max     int64
		wantErr bool
		want    string
	}{
		{name: "valid under limit", body: `{"name":"alice"}`, max: 1024, want: "alice"},
		{name: "empty body fails", body: "", max: 1024, wantErr: true},
		{name: "malformed JSON fails", body: `{name:`, max: 1024, wantErr: true},
		{name: "unknown field fails", body: `{"name":"a","extra":1}`, max: 1024, wantErr: true},
		{name: "exceeds limit fails", body: `{"name":"` + strings.Repeat("a", 200) + `"}`, max: 64, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			req := httptest.NewRequest("POST", "/", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			var got Thing
			err := DecodeJSONBody(rec, req, tt.max, &got)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got.Name).To(Equal(tt.want))
		})
	}
}

func TestSafeReturnPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults to /", in: "", want: "/"},
		{name: "root", in: "/", want: "/"},
		{name: "absolute path", in: "/foo", want: "/foo"},
		{name: "absolute path with query", in: "/foo?bar=baz", want: "/foo?bar=baz"},
		{name: "absolute path with fragment", in: "/foo#section", want: "/foo#section"},

		// Open-redirect attempts:
		{name: "absolute URL", in: "https://evil.com", want: "/"},
		{name: "absolute URL with path", in: "https://evil.com/path", want: "/"},
		{name: "scheme-relative", in: "//evil.com", want: "/"},
		{name: "scheme-relative with path", in: "//evil.com/foo", want: "/"},
		{name: "backslash trick", in: "/\\evil.com", want: "/"},
		{name: "leading backslash", in: "\\evil.com", want: "/"},
		{name: "double backslash", in: "\\\\evil.com", want: "/"},
		{name: "javascript scheme", in: "javascript:alert(1)", want: "/"},
		{name: "data scheme", in: "data:text/html,<script>", want: "/"},
		{name: "relative path", in: "foo/bar", want: "/"},
		{name: "whitespace-prefixed scheme-relative", in: " //evil.com", want: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			g.Expect(SafeReturnPath(tt.in)).To(Equal(tt.want))
		})
	}
}

func TestIsSecure(t *testing.T) {
	tests := []struct {
		name    string
		tls     bool
		headers map[string]string
		want    bool
	}{
		{
			name: "plain http, no proxy headers",
			want: false,
		},
		{
			name: "direct TLS connection",
			tls:  true,
			want: true,
		},
		{
			name:    "X-Forwarded-Proto https",
			headers: map[string]string{"X-Forwarded-Proto": "https"},
			want:    true,
		},
		{
			name:    "X-Forwarded-Proto http",
			headers: map[string]string{"X-Forwarded-Proto": "http"},
			want:    false,
		},
		{
			name:    "X-Forwarded-Proto HTTPS (uppercase)",
			headers: map[string]string{"X-Forwarded-Proto": "HTTPS"},
			want:    true,
		},
		{
			name:    "X-Forwarded-Proto multi-hop, first is https",
			headers: map[string]string{"X-Forwarded-Proto": "https, http"},
			want:    true,
		},
		{
			name:    "X-Forwarded-Proto multi-hop, first is http",
			headers: map[string]string{"X-Forwarded-Proto": "http, https"},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			req, err := http.NewRequest("GET", "/", nil)
			g.Expect(err).NotTo(HaveOccurred())
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			g.Expect(IsSecure(req)).To(Equal(tt.want))
		})
	}
}

func TestGetParam(t *testing.T) {
	tests := []struct {
		expectError    bool
		headers        *map[string]string
		name           string
		parameterNames []string
		path           string
		pattern        string
		supportedLangs *[]language.Tag
		want           Results
	}{
		{
			name:           "from path",
			parameterNames: []string{"lang", "path"},
			path:           "/one/two/three",
			pattern:        "/{lang}/{path...}",
			want: Results{
				Lang: "en",
				Parameters: map[string][]string{
					"lang": {"one"},
					"path": {"two/three"},
				},
			},
		},
		{
			name:           "from path, wrong param name",
			parameterNames: []string{"lang", "path"},
			path:           "/one/two/three",
			pattern:        "/{lang}/{foo...}",
			want: Results{
				Lang: "en",
				Parameters: map[string][]string{
					"lang": {"one"},
				},
			},
		},
		{
			name:           "from query",
			parameterNames: []string{"lang", "path"},
			path:           "/path?lang=one&path=two&path=three",
			pattern:        "/path",
			want: Results{
				Lang: "en",
				Parameters: map[string][]string{
					"lang": {"one"},
					"path": {"two", "three"},
				},
			},
		},
		{
			name:           "from both",
			parameterNames: []string{"lang", "path"},
			path:           "/one?path=two&path=three",
			pattern:        "/{lang}",
			want: Results{
				Lang: "en",
				Parameters: map[string][]string{
					"lang": {"one"},
					"path": {"two", "three"},
				},
			},
		},
		{
			name:           "get lang from path",
			parameterNames: []string{},
			path:           "/fr/one",
			pattern:        "/{l10n}/{path...}",
			supportedLangs: &[]language.Tag{
				language.Make("en"),
				language.Make("fr"),
			},
			want: Results{
				Lang: "fr",
			},
		},
		{
			name:           "get lang from query",
			parameterNames: []string{},
			path:           "/one?l10n=fr",
			pattern:        "/{path...}",
			supportedLangs: &[]language.Tag{
				language.Make("en"),
				language.Make("fr"),
			},
			want: Results{
				Lang: "fr",
			},
		},
		{
			name: "get lang from headers",
			headers: &map[string]string{
				"Accept-Language": "zh,fr;q=0.9,en;q=0.8",
			},
			parameterNames: []string{},
			path:           "/one",
			pattern:        "/{path...}",
			supportedLangs: &[]language.Tag{
				language.Make("en"),
				language.Make("fr"),
			},
			want: Results{
				Lang: "fr",
			},
		},
		{
			name:           "get lang from query, unsupported",
			parameterNames: []string{},
			path:           "/one?l10n=de",
			pattern:        "/{path...}",
			supportedLangs: &[]language.Tag{
				language.Make("en"),
				language.Make("fr"),
			},
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			got, err := setupHandler(
				g, tt.pattern, tt.parameterNames, tt.path, tt.supportedLangs, tt.headers)
			if tt.expectError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(got).To(Equal(tt.want))
			}
		})
	}
}

type Results struct {
	Lang       string              `json:"lang"`
	Parameters map[string][]string `json:"parameters,omitempty"`
}

func setupHandler(
	g *GomegaWithT,
	path string,
	parameterNames []string,
	url string,
	languages *[]language.Tag,
	headers *map[string]string,
) (Results, error) {
	server := MockServer(
		func(mux *http.ServeMux) {
			mux.HandleFunc(
				path,
				func(w http.ResponseWriter, r *http.Request) {
					results := Results{}
					for _, name := range parameterNames {
						values := GetParamArray(name, []string{}, r)
						if len(values) > 0 {
							if results.Parameters == nil {
								results.Parameters = map[string][]string{}
							}
							results.Parameters[name] = values
						}
					}

					if languages == nil {
						languages = &[]language.Tag{
							language.Make("en"),
						}
					}

					lang, err := GetLang(r, "en", *languages)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}

					results.Lang = lang.String()

					jsonBytes, err := json.Marshal(results)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					w.Write(jsonBytes)
					w.WriteHeader(http.StatusOK)
				},
			)
		},
	)

	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+url, nil)
	g.Expect(err).NotTo(HaveOccurred())

	if headers != nil {
		for key, value := range *headers {
			req.Header.Add(key, value)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	g.Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Results{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	g.Expect(err).NotTo(HaveOccurred())

	results := Results{}
	err = json.Unmarshal(body, &results)
	g.Expect(err).NotTo(HaveOccurred())

	return results, nil
}

func MockServer(setup func(mux *http.ServeMux)) *httptest.Server {
	mux := http.NewServeMux()

	setup(mux)

	server := httptest.NewServer(mux)

	return server
}

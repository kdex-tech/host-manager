package controller

import "testing"

func TestParseBuilderGenerator(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantBuilder string
		wantLang    string
		wantErr     bool
	}{
		{name: "valid", in: "kpack/go", wantBuilder: "kpack", wantLang: "go"},
		{name: "valid with extra slashes goes into language", in: "kpack/go/extra", wantBuilder: "kpack", wantLang: "go/extra"},
		{name: "empty", in: "", wantErr: true},
		{name: "no slash", in: "kpack", wantErr: true},
		{name: "only slash", in: "/", wantBuilder: "", wantLang: ""},
		{name: "leading slash", in: "/go", wantBuilder: "", wantLang: "go"},
		{name: "trailing slash", in: "kpack/", wantBuilder: "kpack", wantLang: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder, lang, err := parseBuilderGenerator(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (builder=%q lang=%q)", builder, lang)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if builder != tt.wantBuilder {
				t.Errorf("builder: got %q, want %q", builder, tt.wantBuilder)
			}
			if lang != tt.wantLang {
				t.Errorf("lang: got %q, want %q", lang, tt.wantLang)
			}
		})
	}
}

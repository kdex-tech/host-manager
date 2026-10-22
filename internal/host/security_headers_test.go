package host

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func TestHSTSHeaderValue(t *testing.T) {
	i32 := func(v int32) *int32 { return &v }
	cases := []struct {
		name   string
		scheme string
		h      *kdexv1alpha1.HSTS
		want   string
	}{
		{"default", "https", nil, "max-age=31536000"},
		{"explicit zero", "https", &kdexv1alpha1.HSTS{MaxAge: i32(0)}, "max-age=0"},
		{"all", "https", &kdexv1alpha1.HSTS{MaxAge: i32(63072000), IncludeSubDomains: true, Preload: true}, "max-age=63072000; includeSubDomains; preload"},
		{"subdomains only", "https", &kdexv1alpha1.HSTS{IncludeSubDomains: true}, "max-age=31536000; includeSubDomains"},
		{"http", "http", &kdexv1alpha1.HSTS{MaxAge: i32(100)}, ""},
		{"case-insensitive scheme", "HTTPS", nil, "max-age=31536000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hstsHeaderValue(tc.scheme, tc.h))
		})
	}
}

const testHSTS = "max-age=31536000"

func requirePageSecurityHeaders(t *testing.T, h http.Header, wantHSTS string) {
	t.Helper()
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	assert.Equal(t, "frame-ancestors 'self'", h.Get("Content-Security-Policy"))
	assert.Equal(t, "SAMEORIGIN", h.Get("X-Frame-Options"))
	assert.Equal(t, wantHSTS, h.Get("Strict-Transport-Security"))
}

func requireNoSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	for _, k := range []string{"X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
		assert.Empty(t, h.Values(k), k)
	}
}

// securityHost is compressHost with the HSTS value SetHost would compute.
func securityHost(t *testing.T, fns []kdexv1alpha1.KDexFunction, extra ...page.PageHandler) *HostHandler {
	t.Helper()
	hh := compressHost(t, fns, extra...)
	hh.hstsValue = hstsHeaderValue("https", nil)
	return hh
}

func TestSecurityHeaders_RenderedPage(t *testing.T) {
	hh := securityHost(t, nil)
	rr := compressGet(t, hh, "/doc", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	requirePageSecurityHeaders(t, rr.Header(), testHSTS)
}

func TestSecurityHeaders_TextPage(t *testing.T) {
	hh := securityHost(t, nil, textPageForTest(t, "robots", "/robots.txt", "txt", "User-agent: *"))
	rr := compressGet(t, hh, "/robots.txt", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/plain")
	requirePageSecurityHeaders(t, rr.Header(), testHSTS)
}

func TestSecurityHeaders_ErrorPage(t *testing.T) {
	hh := securityHost(t, nil)
	rr := compressGet(t, hh, "/nowhere", map[string]string{"Accept": "text/html", "Accept-Encoding": "gzip"})
	require.Equal(t, http.StatusNotFound, rr.Code)
	requirePageSecurityHeaders(t, rr.Header(), testHSTS)
}

func TestSecurityHeaders_HTTPHostSendsNoHSTS(t *testing.T) {
	two := int32(63072000)
	hh := compressHost(t, nil)
	hh.scheme = "http"
	hh.hstsValue = hstsHeaderValue("http", &kdexv1alpha1.HSTS{MaxAge: &two})
	for _, path := range []string{"/doc", "/nowhere"} {
		rr := compressGet(t, hh, path, map[string]string{"Accept": "text/html"})
		requirePageSecurityHeaders(t, rr.Header(), "")
		assert.Empty(t, rr.Header().Values("Strict-Transport-Security"))
	}
}

// SetHost is where hstsValue is computed, from the scheme and routing.hsts.
func TestSecurityHeaders_SetHostComputesHSTS(t *testing.T) {
	hh := newTestHostHandler(t, "en", []string{"en"})
	three := int32(63072000)
	hh.SetHost(t.Context(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", Routing: kdexv1alpha1.Routing{HSTS: &kdexv1alpha1.HSTS{MaxAge: &three, IncludeSubDomains: true}}},
		&kdexv1alpha1.KDexObjectStatus{}, nil, nil, nil, "", nil, nil, nil, nil, "https", nil, hh.reconcileTime)
	assert.Equal(t, "max-age=63072000; includeSubDomains", hh.hstsValue)
}

// An http host with routing.hsts set computes no HSTS value through SetHost,
// and a rendered page then sends no Strict-Transport-Security.
func TestSecurityHeaders_SetHostHTTPSchemeGatesHSTS(t *testing.T) {
	hh := compressHost(t, nil)
	hundred := int32(100)
	hh.SetHost(t.Context(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", Routing: kdexv1alpha1.Routing{
			Domains: []string{"example.com"},
			HSTS:    &kdexv1alpha1.HSTS{MaxAge: &hundred, IncludeSubDomains: true},
		}},
		&kdexv1alpha1.KDexObjectStatus{}, nil, nil, nil, "", nil, nil, nil, nil, "http", nil, hh.reconcileTime)
	assert.Equal(t, "", hh.hstsValue)

	hh.Pages.Set(page.PageHandler{
		Name:         "doc",
		MainTemplate: "<html><body>doc</body></html>",
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "Doc", Paths: kdexv1alpha1.Paths{BasePath: "/doc"}},
	})
	hh.RebuildMux()
	rr := compressGet(t, hh, "/doc", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	requirePageSecurityHeaders(t, rr.Header(), "")
	assert.Empty(t, rr.Header().Values("Strict-Transport-Security"))
}

func TestSecurityHeaders_ConsentKeepsStricterValues(t *testing.T) {
	hh, _ := newConsentPageHost(t, `<html><body>[[ .Content ]]</body></html>`, "hello")
	hh.hstsValue = hstsHeaderValue("https", nil)

	r := httptest.NewRequest(http.MethodGet, "/-/oauth/authorize", nil)
	w := httptest.NewRecorder()
	// What the flow sets before it calls the renderer.
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Add("Content-Security-Policy", "frame-ancestors 'none'")
	hh.renderConsentPage(w, r, consentTestView)

	h := w.Header()
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "same-origin", h.Get("Referrer-Policy"))
	assert.Contains(t, h.Values("Content-Security-Policy"), "frame-ancestors 'none'")
	assert.NotContains(t, h.Values("Content-Security-Policy"), "frame-ancestors 'self'")
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, testHSTS, h.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_FunctionResponseHasNone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	hh := securityHost(t, []kdexv1alpha1.KDexFunction{readyFunction("fn", "/api/fn", upstream.URL)})

	rr := compressGet(t, hh, "/api/fn/x", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	requireNoSecurityHeaders(t, rr.Header())
}

func TestSecurityHeaders_AliasToFunctionHasNone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)
	alias := aliasPH("events", "/events", "", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "fn"},
	})
	hh := securityHost(t, []kdexv1alpha1.KDexFunction{readyFunction("fn", "/api/fn", upstream.URL)}, alias)
	require.NotEmpty(t, hh.hstsValue)

	rr := compressGet(t, hh, "/events", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"ok":true`)
	requireNoSecurityHeaders(t, rr.Header())
}

func TestSecurityHeaders_FunctionErrorPageHasThem(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "nope")
	}))
	t.Cleanup(upstream.Close)
	hh := securityHost(t, []kdexv1alpha1.KDexFunction{readyFunction("fn", "/api/fn", upstream.URL)})

	rr := compressGet(t, hh, "/api/fn/x", map[string]string{"Accept": "text/html"})
	require.Equal(t, http.StatusNotFound, rr.Code)
	requirePageSecurityHeaders(t, rr.Header(), testHSTS)
}

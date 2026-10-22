package host

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// compressPadding pushes a render past gzhttp's 1024-byte minimum size.
var compressPadding = strings.Repeat("<p>host-manager renders this page and compresses it.</p>", 40)

// compressErrorPage prints the error message where a test can find it, padded
// so the error page itself is large enough to compress.
func compressErrorPage() page.PageHandler {
	return page.PageHandler{
		Name:         "err",
		MainTemplate: `<html><body><p id="msg">[[ .Extra.ErrorMessage ]]</p>` + compressPadding + `</body></html>`,
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "err",
			Paths: kdexv1alpha1.Paths{BasePath: "/-error"},
		},
	}
}

// compressHost builds a host through RebuildMux, as production does, with the
// error utility page, a large page /doc carrying a large navigation, and the
// given functions.
func compressHost(t *testing.T, fns []kdexv1alpha1.KDexFunction, extra ...page.PageHandler) *HostHandler {
	t.Helper()
	hh := newTestHostHandler(t, "en", []string{"en"})
	hh.host.Routing.Domains = []string{"example.com"}
	hh.scheme = "https"
	hh.authConfig = challengeFixtureAuthConfig(t)
	hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = compressErrorPage()
	hh.Pages.Set(page.PageHandler{
		Name:         "doc",
		MainTemplate: "<html><body>[[ .Title ]]" + compressPadding + "</body></html>",
		Navigations:  map[string]string{"main": "<ul><li>[[ .Title ]]</li>" + compressPadding + "</ul>"},
		Page:         &kdexv1alpha1.KDexPageSpec{Label: "Doc", Paths: kdexv1alpha1.Paths{BasePath: "/doc"}},
	})
	for _, p := range extra {
		hh.Pages.Set(p)
	}
	hh.functions = fns
	hh.RebuildMux()
	return hh
}

func compressGet(t *testing.T, hh *HostHandler, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	hh.DesignMiddleware(hh.Mux).ServeHTTP(rr, req)
	return rr
}

// decodedBody returns the body with any gzip Content-Encoding removed.
func decodedBody(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	switch ce := rr.Header().Get("Content-Encoding"); ce {
	case "":
		return rr.Body.String()
	case "gzip":
		zr, err := gzip.NewReader(rr.Body)
		require.NoError(t, err)
		raw, err := io.ReadAll(zr)
		require.NoError(t, err)
		return string(raw)
	default:
		t.Fatalf("unexpected Content-Encoding %q", ce)
		return ""
	}
}

var gzipAE = map[string]string{"Accept-Encoding": "gzip"}

func TestCompress_PageNegotiatesGzip(t *testing.T) {
	hh := compressHost(t, nil)

	plain := compressGet(t, hh, "/doc", nil)
	require.Equal(t, http.StatusOK, plain.Code)

	gz := compressGet(t, hh, "/doc", gzipAE)
	require.Equal(t, http.StatusOK, gz.Code)
	assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
	assert.True(t, varyHas(gz.Header(), "Accept-Encoding"), "Vary = %v", gz.Header().Values("Vary"))
	assert.True(t, varyHas(gz.Header(), "Accept-Language"), "the caching helper's Vary is kept")
	assert.Less(t, gz.Body.Len(), plain.Body.Len())
	assert.Equal(t, plain.Body.String(), decodedBody(t, gz))
}

func TestCompress_IdentityWithoutAcceptEncoding(t *testing.T) {
	hh := compressHost(t, nil)

	rr := compressGet(t, hh, "/doc", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Get("Content-Encoding"))
	assert.Contains(t, rr.Body.String(), "Doc")
}

func TestCompress_ETagPerCoding(t *testing.T) {
	hh := compressHost(t, nil)

	plain := compressGet(t, hh, "/doc", nil)
	gz := compressGet(t, hh, "/doc", gzipAE)
	gzETag := gz.Header().Get("ETag")
	require.NotEmpty(t, gzETag)
	assert.NotEqual(t, plain.Header().Get("ETag"), gzETag, "each coding has its own ETag")

	nm := compressGet(t, hh, "/doc", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": gzETag})
	assert.Equal(t, http.StatusNotModified, nm.Code, "a gzip client revalidates against the gzip ETag")

	cross := compressGet(t, hh, "/doc", map[string]string{"If-None-Match": gzETag})
	assert.Equal(t, http.StatusOK, cross.Code, "the gzip ETag never validates an identity response")
	assert.Empty(t, cross.Header().Get("Content-Encoding"))
}

func TestCompress_TranslationAndNavigation(t *testing.T) {
	hh := compressHost(t, nil)
	kv := map[string]string{}
	for i := range 60 {
		kv[fmt.Sprintf("key.number.%d", i)] = fmt.Sprintf("A translated value long enough to matter, number %d", i)
	}
	hh.AddOrUpdateTranslation("tr-en", &kdexv1alpha1.KDexTranslationSpec{
		Translations: []kdexv1alpha1.Translation{{Lang: "en", KeysAndValues: kv}},
	})

	for _, path := range []string{"/-/translation/en", "/-/navigation/main/en/doc"} {
		plain := compressGet(t, hh, path, nil)
		require.Equal(t, http.StatusOK, plain.Code, path)
		assert.Empty(t, plain.Header().Get("Content-Encoding"), path)

		gz := compressGet(t, hh, path, gzipAE)
		require.Equal(t, http.StatusOK, gz.Code, path)
		assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"), path)
		assert.True(t, varyHas(gz.Header(), "Accept-Encoding"), path)
		assert.Equal(t, plain.Body.String(), decodedBody(t, gz), path)
		assert.NotEqual(t, plain.Header().Get("ETag"), gz.Header().Get("ETag"), path)
	}
}

// The login page and the not-ready announcement are host-manager's own
// utility renders on registered mux routes, so they are compressed too.
func TestCompress_LoginAndAnnouncement(t *testing.T) {
	utility := func(name string, typ kdexv1alpha1.KDexUtilityPageType) page.PageHandler {
		return page.PageHandler{
			Name:         name,
			MainTemplate: "<html><body>" + name + compressPadding + "</body></html>",
			Page:         &kdexv1alpha1.KDexPageSpec{Label: name, Paths: kdexv1alpha1.Paths{BasePath: "/-" + name}},
			UtilityPage:  &kdexv1alpha1.KDexUtilityPageSpec{Type: typ},
		}
	}

	t.Run("login", func(t *testing.T) {
		hh := compressHost(t, nil)
		hh.AddOrUpdateUtilityPage(utility("login", kdexv1alpha1.LoginUtilityPageType))

		gz := compressGet(t, hh, "/-/login", gzipAE)
		require.Equal(t, http.StatusOK, gz.Code)
		assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
		assert.True(t, varyHas(gz.Header(), "Accept-Encoding"))
		assert.Contains(t, decodedBody(t, gz), "login")
	})

	t.Run("announcement", func(t *testing.T) {
		hh := newTestHostHandler(t, "en", []string{"en"})
		hh.utilityPages[kdexv1alpha1.AnnouncementUtilityPageType] = utility("announcement", kdexv1alpha1.AnnouncementUtilityPageType)
		hh.RebuildMux() // no pages, no functions: the not-ready routes

		gz := compressGet(t, hh, "/", gzipAE)
		require.Equal(t, http.StatusOK, gz.Code)
		assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
		assert.True(t, varyHas(gz.Header(), "Accept-Encoding"))
		assert.Contains(t, decodedBody(t, gz), "announcement")
	})
}

func TestCompress_FunctionRouteUntouched(t *testing.T) {
	body := "<html><body>" + strings.Repeat("function output ", 256) + "</body></html>"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(upstream.Close)
	hh := compressHost(t, []kdexv1alpha1.KDexFunction{readyFunction("fn", "/api/fn", upstream.URL)})

	rr := compressGet(t, hh, "/api/fn/x", gzipAE)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, rr.Header().Get("Content-Encoding"), "host-manager never compresses a function")
	assert.False(t, varyHas(rr.Header(), "Accept-Encoding"))
	assert.Equal(t, body, rr.Body.String())
}

// The error capture sits inside the compressor, so the message it records
// from a failing function is the function's plain bytes.
func TestCompress_FunctionErrorMessagePlainText(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "boom")
	}))
	t.Cleanup(upstream.Close)
	hh := compressHost(t, []kdexv1alpha1.KDexFunction{readyFunction("fn", "/api/fn", upstream.URL)})

	rr := compressGet(t, hh, "/api/fn/x", map[string]string{"Accept": "text/html", "Accept-Encoding": "gzip"})
	require.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, decodedBody(t, rr), `<p id="msg">boom</p>`)
}

func TestCompress_UnmatchedErrorPageCompressedWithVary(t *testing.T) {
	hh := compressHost(t, nil)

	plain := compressGet(t, hh, "/nowhere", map[string]string{"Accept": "text/html"})
	require.Equal(t, http.StatusNotFound, plain.Code)

	gz := compressGet(t, hh, "/nowhere", map[string]string{"Accept": "text/html", "Accept-Encoding": "gzip"})
	require.Equal(t, http.StatusNotFound, gz.Code)
	assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
	assert.True(t, varyHas(gz.Header(), "Accept-Encoding"), "unwrap's header wipe must not drop Vary: %v", gz.Header().Values("Vary"))
	decoded := decodedBody(t, gz)
	assert.Contains(t, decoded, `<p id="msg">`)
	assert.Equal(t, plain.Body.String(), decoded)
}

func TestCompress_DeniedPageKeepsPreservedHeaders(t *testing.T) {
	for _, withLogin := range []bool{true, false} {
		t.Run(fmt.Sprintf("login=%v", withLogin), func(t *testing.T) {
			hh := newTestHostHandler(t, "en", []string{"en"})
			hh.authConfig = &auth.Config{AnonymousEntitlements: []string{"public"}, ActivePair: &keys.KeyPair{}}
			hh.authChecker = denyPath("/gated")
			hh.utilityPages[kdexv1alpha1.ErrorUtilityPageType] = compressErrorPage()
			if withLogin {
				hh.utilityPages[kdexv1alpha1.LoginUtilityPageType] = page.PageHandler{Name: "login"}
			}
			gated := page.PageHandler{
				Name:               "gated",
				MainTemplate:       "<html><body>secret" + compressPadding + "</body></html>",
				Page:               &kdexv1alpha1.KDexPageSpec{Label: "Gated", Paths: kdexv1alpha1.Paths{BasePath: "/gated"}},
				ParsedRequirements: &entitlements.ParsedRequirements{},
			}
			hh.registerRendersForTest(t, nil, gated)

			browser := map[string]string{"Accept": "text/html"}
			plain := compressGet(t, hh, "/gated", browser)
			gz := compressGet(t, hh, "/gated", map[string]string{"Accept": "text/html", "Accept-Encoding": "gzip"})

			if withLogin {
				require.Equal(t, http.StatusSeeOther, plain.Code)
				assert.NotEmpty(t, plain.Header().Get("Location"))
			} else {
				require.Equal(t, http.StatusUnauthorized, plain.Code)
				assert.NotEmpty(t, plain.Header().Get("WWW-Authenticate"))
				assert.Equal(t, "no-store", plain.Header().Get("Cache-Control"))
			}
			assert.Equal(t, plain.Code, gz.Code)
			if !withLogin {
				// The re-rendered error page is negotiated, and the
				// preserved denial headers survive the compressed path.
				assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
				assert.True(t, varyHas(gz.Header(), "Accept-Encoding"))
			}
			for _, h := range []string{"Location", "WWW-Authenticate", "Cache-Control"} {
				assert.Equal(t, plain.Header().Get(h), gz.Header().Get(h), h)
			}
			decoded := decodedBody(t, gz)
			assert.NotContains(t, decoded, "secret")
			assert.Equal(t, plain.Body.String(), decoded)
		})
	}
}

// A rewrite alias may target a streaming function. gzhttp buffers below its
// minimum size and has no text/event-stream exclusion, so an alias must never
// be compressed: the first event has to reach the client while the function
// is still holding the stream open.
func TestCompress_AliasToSSEFunctionNotBuffered(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	releaseOnce := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		_, _ = io.WriteString(w, "data: two\n\n")
		w.(http.Flusher).Flush()
	}))
	t.Cleanup(upstream.Close)

	alias := aliasPH("events", "/events", "", kdexv1alpha1.RewriteSpec{
		TargetRef: kdexv1alpha1.KDexObjectReference{Kind: "KDexFunction", Name: "sse"},
	})
	hh := compressHost(t, []kdexv1alpha1.KDexFunction{readyFunction("sse", "/api/sse", upstream.URL)}, alias)

	srv := httptest.NewServer(hh.DesignMiddleware(hh.Mux))
	t.Cleanup(srv.Close)
	t.Cleanup(releaseOnce) // runs before upstream.Close: never leave the upstream parked

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/events", nil)
	require.NoError(t, err)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Content-Encoding"))

	br := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		first <- line
	}()
	select {
	case line := <-first:
		assert.Equal(t, "data: one\n", line)
	case <-time.After(5 * time.Second):
		t.Fatal("the first event did not reach the client before the function wrote the second: the alias buffered the stream")
	}
	releaseOnce()

	rest, err := io.ReadAll(br)
	require.NoError(t, err)
	assert.Contains(t, string(rest), "data: two")
}

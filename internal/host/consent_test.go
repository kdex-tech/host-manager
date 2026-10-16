package host

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	consentPageName = "consent-page-test-consent"

	// consentArchetype prints every slot an archetype can, the script slots
	// and the navigation included: scriptless rendering must blank those
	// whatever the archetype asks for.
	consentArchetype = `<!DOCTYPE html>
<html lang="[[ .Language ]]"><head>
[[ .Meta ]]
[[ .Theme ]]
[[ .HeadScript ]]
</head><body>
<header>[[ .Header ]]</header>
<nav>[[ .Navigation.main ]]</nav>
<main>[[ .Content.main ]]</main>
<footer>[[ .Footer ]]</footer>
[[ .FootScript ]]
</body></html>`

	consentThemeStyle = "body{color:rebeccapurple}"
	consentHeader     = "BRANDED HEADER"
	consentFooter     = "BRANDED FOOTER"
	consentBlockSlot  = `<section class="consent">[[ .Extra.consent.Block ]]</section>`
)

var consentTestView = auth.ConsentView{
	RedirectKind:      auth.RedirectKindWeb,
	RedirectDisplay:   "app.example",
	RegistrableDomain: "app.example",
	RedirectURI:       "https://app.example/cb",
	ClientName:        "Example App",
	Account:           "alice@example.com",
	Request:           "SEALED-REQUEST",
	Action:            auth.OAuthConsentPath,
}

// syncLog collects a logger's output for assertions; renders run
// concurrently, so writes are serialized. The logger rides on the request
// context, as the request path logs.
type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
	l  logr.Logger
}

func (s *syncLog) write(prefix, args string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.WriteString(prefix + " " + args + "\n")
}

func (s *syncLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// setConsentTestHost is the controller's SetHost: a theme with a style asset,
// a host script library (a script and a package reference, so HeadScript
// would carry an importmap and a module), and an importmap.
func setConsentTestHost(hh *HostHandler) {
	hh.SetHost(
		context.Background(),
		&kdexv1alpha1.KDexHostSpec{DefaultLang: "en", BrandName: "Brand"},
		&kdexv1alpha1.KDexObjectStatus{},
		[]kdexv1alpha1.PackageReference{{Name: "@kdex/ui", Version: "1.0.0"}},
		[]kdexv1alpha1.Asset{{Style: consentThemeStyle}},
		[]kdexv1alpha1.ScriptDef{
			{Script: "console.log('head')"},
			{Script: "console.log('foot')", FootScript: true},
		},
		`{"imports":{"@kdex/ui":"/-/modules/@kdex/ui/index.js"}}`,
		nil, nil, nil, nil, "http", nil, time.Now(),
	)
}

// newConsentPageHost returns a host whose Consent utility page uses
// mainTemplate as its archetype and content as its main slot. An empty
// mainTemplate installs no Consent page.
func newConsentPageHost(t *testing.T, mainTemplate, content string) (*HostHandler, *syncLog) {
	t.Helper()
	logs := &syncLog{}
	logs.l = funcr.New(logs.write, funcr.Options{Verbosity: 1})
	cm, err := cache.NewCacheManager("", "consent-page-test", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "consent-page-test", "default", logr.Discard(), cm)
	setConsentTestHost(hh)
	hh.AddOrUpdateTranslation("consent-fr", &kdexv1alpha1.KDexTranslationSpec{
		Translations: []kdexv1alpha1.Translation{
			{Lang: "en", KeysAndValues: map[string]string{"brand": "Brand"}},
			{Lang: "fr", KeysAndValues: map[string]string{"consent.title": "Autoriser l'accès à votre compte ?"}},
		},
	})
	if mainTemplate == "" {
		return hh, logs
	}
	hh.AddOrUpdateUtilityPage(page.PageHandler{
		Name:         consentPageName,
		MainTemplate: mainTemplate,
		Header:       consentHeader,
		Footer:       consentFooter,
		Content:      map[string]page.PackedContent{"main": {Content: content, Slot: "main"}},
		Navigations:  map[string]string{"main": "NAV"},
		Scripts:      []kdexv1alpha1.ScriptDef{{Script: "console.log('page')"}},
		PackageReferences: []kdexv1alpha1.PackageReference{
			{Name: "@kdex/page", Version: "1.0.0"},
		},
		Page: &kdexv1alpha1.KDexPageSpec{
			Label: "Consent",
			Paths: kdexv1alpha1.Paths{BasePath: "/-/consent"},
		},
		UtilityPage: &kdexv1alpha1.KDexUtilityPageSpec{Type: kdexv1alpha1.ConsentUtilityPageType},
	})
	return hh, logs
}

func renderConsentRequest(hh *HostHandler, logs *syncLog, target, acceptLanguage string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r = r.WithContext(logf.IntoContext(r.Context(), logs.l))
	if acceptLanguage != "" {
		r.Header.Set("Accept-Language", acceptLanguage)
	}
	w := httptest.NewRecorder()
	// The flow sets this before it calls the renderer.
	w.Header().Add("Content-Security-Policy", "frame-ancestors 'none'")
	hh.renderConsentPage(w, r, consentTestView)
	return w
}

func expectedBuiltinConsentCSP() string {
	return "default-src 'none'; script-src " + auth.ConsentScriptHash() +
		"; style-src 'unsafe-inline'; frame-ancestors 'none'"
}

func expectedBrandedConsentCSP() string {
	return "default-src 'none'; script-src " + auth.ConsentScriptHash() +
		"; style-src 'self' https: 'unsafe-inline'; font-src 'self' https: data:; img-src 'self' https: data:; base-uri 'none'"
}

func assertBuiltinConsent(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "<title>Allow access?</title>")
	assert.NotContains(t, body, consentHeader)
	assert.Equal(t, 1, strings.Count(body, auth.ConsentMarkerAttr+`="`), "built-in page carries the block once")
	csp := w.Header().Values("Content-Security-Policy")
	assert.Contains(t, csp, expectedBuiltinConsentCSP())
	assert.Contains(t, csp, "frame-ancestors 'none'", "the flow's own policy stays")
	assert.NotContains(t, csp, expectedBrandedConsentCSP(), "the fallback never carries two page policies")
	assert.Empty(t, w.Header().Get("Content-Language"))
}

// assertConsentErrorLog checks that an error-level line names the utility page.
func assertConsentErrorLog(t *testing.T, logs *syncLog) {
	t.Helper()
	for line := range strings.SplitSeq(logs.String(), "\n") {
		if strings.Contains(line, `"error"=`) && strings.Contains(line, `"page"="`+consentPageName+`"`) {
			return
		}
	}
	t.Errorf("no error-level log naming %s in:\n%s", consentPageName, logs.String())
}

func TestConsentPage_Branded(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot)

	w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en")

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, consentThemeStyle, "the theme renders")
	assert.Contains(t, body, consentHeader, "the header renders")
	assert.Contains(t, body, consentFooter, "the footer renders")
	assert.Contains(t, body, `name="kdex-ui"`, "the meta renders")
	assert.Contains(t, body, "Allow access to your account?", "the block renders")
	assert.Contains(t, body, "SEALED-REQUEST", "the block carries the sealed request")
	assert.Equal(t, 1, strings.Count(body, auth.ConsentMarkerAttr+`="`), "the block appears exactly once")

	// Scriptless: no head/foot script, no importmap, no module, no
	// navigation fetch, whatever the archetype prints.
	assert.NotContains(t, body, `type="importmap"`)
	assert.NotContains(t, body, `type="module"`)
	assert.NotContains(t, body, "fetch('/-/navigation/")
	assert.NotContains(t, body, "console.log")
	assert.NotContains(t, body, "NAV")
	assert.Equal(t, 1, strings.Count(body, "<script"), "only the hold-back script remains")

	csp := w.Header().Values("Content-Security-Policy")
	assert.Contains(t, csp, expectedBrandedConsentCSP())
	assert.Contains(t, csp, "frame-ancestors 'none'", "the flow's own policy stays alongside")
	assert.NotContains(t, csp, expectedBuiltinConsentCSP())
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "en", w.Header().Get("Content-Language"))
}

func TestConsentPage_Translated(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot)

	w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "fr")

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "Autoriser l&#39;accès à votre compte ?", "a translated key is used")
	assert.Contains(t, body, ">Allow<", "a key missing from the catalog falls back to English")
	assert.Equal(t, "fr", w.Header().Get("Content-Language"))
}

// The consent flow must not answer a bad language with a 400.
func TestConsentPage_BadLanguageUsesDefault(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot)

	w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath+"?l10n=!!", "!!, zz-ZZ;q=x")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), consentHeader)
	assert.Equal(t, "en", w.Header().Get("Content-Language"))
}

func TestConsentPage_FallbackNoUtilityPage(t *testing.T) {
	hh, logs := newConsentPageHost(t, "", "")

	assertBuiltinConsent(t, renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en"))
	// A host without a Consent page is supported: V(1) info, not an error.
	assert.Contains(t, logs.String(), `"level"=1 "msg"="serving the built-in consent page"`)
	assert.NotContains(t, logs.String(), `"error"=`)
}

func TestConsentPage_FallbackMarkerMissing(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, `<p>no block here</p>`)

	assertBuiltinConsent(t, renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en"))
	assertConsentErrorLog(t, logs)
}

func TestConsentPage_FallbackMarkerTwice(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot+consentBlockSlot)

	assertBuiltinConsent(t, renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en"))
	assertConsentErrorLog(t, logs)
}

func TestConsentPage_FallbackRenderError(t *testing.T) {
	// Parses, then fails at execution: index of a non-map.
	hh, logs := newConsentPageHost(t, `<html>[[ index .Title "x" ]]</html>`, consentBlockSlot)

	assertBuiltinConsent(t, renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en"))
	assertConsentErrorLog(t, logs)
}

// A template that hides the block. Wrapped in an HTML comment, the block is
// gone: html/template drops comments and the actions inside them, so the
// marker is missing and the built-in page is served. Wrapped in an inert
// <template>, the markup survives and passes the exactly-once check, but the
// page shows no working form. That is a broken-looking page the operator
// made, not a bypass: the form, the sealed request and the hold-back script
// are still host-manager's, and no other script can run.
func TestConsentPage_HiddenBlock(t *testing.T) {
	t.Run("html comment: html/template drops it, so the built-in page is served", func(t *testing.T) {
		hh, logs := newConsentPageHost(t, consentArchetype, `<!-- [[ .Extra.consent.Block ]] -->`)

		assertBuiltinConsent(t, renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en"))
	})
	t.Run("inert template element: branded page, marker once", func(t *testing.T) {
		hh, logs := newConsentPageHost(t, consentArchetype, `<template>[[ .Extra.consent.Block ]]</template>`)

		w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en")

		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, consentHeader)
		assert.Equal(t, 1, strings.Count(body, auth.ConsentMarkerAttr+`="`))
		assert.Contains(t, w.Header().Values("Content-Security-Policy"), expectedBrandedConsentCSP())
	})
}

// The OAuth2 request path holds no host lock, so renderConsentPage takes its
// own; a reconcile racing renders must not race them (run under -race).
func TestConsentPage_ConcurrentSetHost(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot)

	stop := make(chan struct{})
	setHostDone := make(chan struct{})
	go func() {
		defer close(setHostDone)
		for {
			select {
			case <-stop:
				return
			default:
				setConsentTestHost(hh)
			}
		}
	}()

	var wg sync.WaitGroup
	codes := make([]int, 50)
	branded := make([]bool, 50)
	for i := range codes {
		wg.Go(func() {
			w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath, "en")
			codes[i] = w.Code
			branded[i] = strings.Contains(w.Body.String(), consentHeader)
		})
	}
	wg.Wait()
	close(stop)
	<-setHostDone

	for i := range codes {
		assert.Equal(t, http.StatusOK, codes[i], "render %d", i)
		assert.True(t, branded[i], "render %d is the branded page", i)
	}
}

func TestNewOAuth2SetsRenderConsent(t *testing.T) {
	hh, _ := newConsentPageHost(t, consentArchetype, consentBlockSlot)
	hh.mu.Lock()
	hh.authConfig = &auth.Config{}
	hh.mu.Unlock()

	render := hh.newOAuth2().RenderConsent
	require.NotNil(t, render)

	// It is the host's renderer: the branded page, not the built-in one.
	w := httptest.NewRecorder()
	render(w, httptest.NewRequest(http.MethodGet, auth.OAuthAuthorizePath, nil), consentTestView)
	assert.Contains(t, w.Body.String(), consentHeader)
}

// The authorize request's query is built by whoever sends the user there, so
// the consent page's language comes from the user's Accept-Language only.
func TestConsentPage_LanguageIgnoresTheL10nParam(t *testing.T) {
	hh, logs := newConsentPageHost(t, consentArchetype, consentBlockSlot)

	w := renderConsentRequest(hh, logs, auth.OAuthAuthorizePath+"?l10n=fr", "en")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Allow access to your account?")
	assert.NotContains(t, w.Body.String(), "Autoriser")
	assert.Equal(t, "en", w.Header().Get("Content-Language"))
}

// lockProbeWriter reports whether the host's write lock could be taken while
// the response body was being written.
type lockProbeWriter struct {
	*httptest.ResponseRecorder
	hh           *HostHandler
	lockedInside bool
}

func (w *lockProbeWriter) Write(b []byte) (int, error) {
	if w.hh.mu.TryLock() {
		w.lockedInside = true
		w.hh.mu.Unlock()
	}
	return w.ResponseRecorder.Write(b)
}

// A slow reader must not hold the host's read lock (and so stall a queued
// SetHost and every request behind it): the body is written after the lock
// is released, on the branded page and on the built-in fallback alike.
func TestConsentPage_WritesOutsideTheHostLock(t *testing.T) {
	for name, mainTemplate := range map[string]string{"branded": consentArchetype, "built-in fallback": ""} {
		t.Run(name, func(t *testing.T) {
			hh, logs := newConsentPageHost(t, mainTemplate, consentBlockSlot)
			r := httptest.NewRequest(http.MethodGet, auth.OAuthAuthorizePath, nil)
			r = r.WithContext(logf.IntoContext(r.Context(), logs.l))
			w := &lockProbeWriter{ResponseRecorder: httptest.NewRecorder(), hh: hh}

			hh.renderConsentPage(w, r, consentTestView)

			require.Equal(t, http.StatusOK, w.Code)
			assert.True(t, w.lockedInside, "the host lock is free while the body is written")
		})
	}
}

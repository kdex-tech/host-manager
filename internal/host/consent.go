package host

import (
	"net/http"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// renderConsentPage is the host's auth.OAuth2.RenderConsent: host-manager's
// fixed consent block inside the host's Consent utility page, which always
// renders scriptless. The page is served only when the block appears in it
// exactly once, counted by a marker made fresh for each render, so a stale or
// hand-copied block cannot satisfy the check. The marker is not secret from
// the template, which receives the block; the operator's template is trusted.
// With no Consent page, a render error or a failed check, the built-in page
// is served instead. The language comes from Accept-Language only: whoever
// built the authorize request chose its query, l10n included. The flow has
// already set the no-store, framing and referrer headers.
func (hh *HostHandler) renderConsentPage(w http.ResponseWriter, r *http.Request, v auth.ConsentView) {
	log := logf.FromContext(r.Context())

	// The OAuth2 request path holds no host lock; take a brief one for the
	// transport headers (hstsValue is rewritten by SetHost). The flow already
	// set the framing and referrer headers, which stay as they are.
	hh.mu.RLock()
	hh.setTransportSecurityHeadersLocked(w)
	hh.mu.RUnlock()

	page, ok := hh.renderBrandedConsent(r, v)
	if !ok {
		auth.RenderBuiltinConsent(w, r, v)
		return
	}

	h := w.Header()
	h.Add("Content-Security-Policy", auth.BrandedConsentCSP())
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Language", page.lang.String())
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(page.html)); err != nil {
		log.V(1).Info("writing the consent page", "page", page.name, "err", err)
	}
}

type brandedConsentPage struct {
	html, name string
	lang       language.Tag
}

// renderBrandedConsent renders the Consent utility page with the block under
// the host's read lock, and reports false (having logged why) when the
// built-in page must be served instead. The response is written by the
// caller, after the lock is released, so a slow reader cannot hold it. The
// OAuth2 request path holds no host lock, so this takes its own.
func (hh *HostHandler) renderBrandedConsent(r *http.Request, v auth.ConsentView) (brandedConsentPage, bool) {
	log := logf.FromContext(r.Context())

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	ph, ok := hh.utilityPages[kdexv1alpha1.ConsentUtilityPageType]
	if !ok {
		// A host without a Consent page is a supported configuration.
		log.V(1).Info("serving the built-in consent page", "reason", "no Consent utility page")
		return brandedConsentPage{}, false
	}

	// A bad Accept-Language must not fail the consent flow.
	l, err := kdexhttp.GetAcceptLanguage(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		l = language.Make(hh.defaultLanguage)
	}

	p := hh.messagePrinter(&hh.Translations, l)
	translate := func(key string, args ...any) (string, bool) {
		if p.Sprintf(key) == key {
			return "", false
		}
		return p.Sprintf(key, args...), true
	}

	marker := auth.NewConsentMarker()
	rendered := hh.renderUtilityPage(
		kdexv1alpha1.ConsentUtilityPageType,
		l,
		map[string]any{"consent": map[string]any{"Block": auth.RenderConsentCore(v, marker, translate)}},
		&hh.Translations,
	)
	if rendered == "" {
		log.Error(nil, "serving the built-in consent page", "page", ph.Name, "reason", "render failed")
		return brandedConsentPage{}, false
	}
	if n := strings.Count(rendered, auth.ConsentMarkerAttr+`="`+marker+`"`); n != 1 {
		log.Error(nil, "serving the built-in consent page: the Consent utility page must show .Extra.consent.Block exactly once",
			"page", ph.Name, "reason", "marker count", "count", n)
		return brandedConsentPage{}, false
	}
	return brandedConsentPage{html: rendered, name: ph.Name, lang: l}, true
}

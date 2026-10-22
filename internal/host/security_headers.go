package host

import (
	"fmt"
	"net/http"
	"strings"

	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// defaultHSTSMaxAge is one year, the max-age sent when routing.hsts leaves
// maxAge unset.
//
// kdex-crds depends on this exact value: its HSTS CEL rule and field doc
// treat an unset maxAge as 31536000 (the preload minimum), so changing it
// here without changing kdex-crds would make the CRD validate one policy and
// host-manager send another.
const defaultHSTSMaxAge int32 = 31536000

// hstsHeaderValue builds the Strict-Transport-Security value for a host. It
// is empty unless the scheme is https: HSTS over plain http is ignored by
// browsers and would be misleading to send.
func hstsHeaderValue(scheme string, h *kdexv1alpha1.HSTS) string {
	if !strings.EqualFold(scheme, "https") {
		return ""
	}
	maxAge := defaultHSTSMaxAge
	if h != nil && h.MaxAge != nil {
		maxAge = *h.MaxAge
	}
	v := fmt.Sprintf("max-age=%d", maxAge)
	if h != nil {
		if h.IncludeSubDomains {
			v += "; includeSubDomains"
		}
		if h.Preload {
			v += "; preload"
		}
	}
	return v
}

// setPageSecurityHeadersLocked sets the browser security headers every
// rendered page, text page and utility page carries. The caller MUST hold
// hh.mu.RLock (hstsValue is rewritten by SetHost under the write lock). It
// uses Set throughout so a later, stricter Set wins. It must never run on a
// function, backend, module, theme or transfer response.
func (hh *HostHandler) setPageSecurityHeadersLocked(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Content-Security-Policy", "frame-ancestors 'self'")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	hh.setTransportSecurityHeadersLocked(w)
}

// setTransportSecurityHeadersLocked sets only nosniff and HSTS. The consent
// flow uses it because it has already set its own, stricter framing and
// referrer headers. The caller MUST hold hh.mu.RLock.
func (hh *HostHandler) setTransportSecurityHeadersLocked(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	if hh.hstsValue != "" {
		h.Set("Strict-Transport-Security", hh.hstsValue)
	}
}

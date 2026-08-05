package host

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (hh *HostHandler) LoginGet(w http.ResponseWriter, r *http.Request) {
	log := logf.FromContext(r.Context())

	returnURL := kdexhttp.SafeReturnPath(r.URL.Query().Get("return"))

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// applyCachingHeadersWithLang folds the language tag into the ETag
	// so en-CA and fr-CA login renders get distinct ETags.
	// See kdex-tech/host-manager#43.
	if hh.applyCachingHeadersWithLang(w, r, []kdexv1alpha1.SecurityRequirement{{"bearer": {}}}, hh.reconcileTime, l.String()) {
		return
	}

	extras := map[string]any{}

	if authCodeURL := hh.authExchanger.AuthCodeURL(returnURL); authCodeURL != "" {
		extras["oidc"] = map[string]any{
			"authCodeURL": authCodeURL,
			"name":        hh.authConfig.OIDC.Name,
			"provider":    hh.authConfig.OIDC.ProviderURL,
		}
	}

	rendered := hh.renderUtilityPage(
		kdexv1alpha1.LoginUtilityPageType,
		l,
		extras,
		&hh.Translations,
	)

	if rendered == "" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	log.V(1).Info("serving login page", "language", l.String())

	w.Header().Set("Content-Language", l.String())
	w.Header().Set("Content-Type", "text/html")

	_, err = w.Write([]byte(rendered))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (hh *HostHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	// Login-CSRF defense: reject a cross-origin submission before touching
	// credentials. See originAllowed / kdex-tech/host-manager#163.
	if !hh.originAllowed(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	returnURL := kdexhttp.SafeReturnPath(r.FormValue("return"))

	log := logf.FromContext(r.Context())

	log.V(1).Info("processing local login", "user", username)

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	// Local login doesn't have a clientID, so we pass empty string
	// We also don't need the ID Token for cookie-based session
	ts, err := hh.authExchanger.LoginLocal(r.Context(), username, password, "", "", auth.AuthMethodLocal)
	if err != nil {
		// FAILED: 401 Unauthorized / render login page again with error message?
		// For now simple redirect back to login
		log.Error(err, "local login failed")
		http.Redirect(w, r, "/-/login?error=invalid_credentials&return="+url.QueryEscape(returnURL), http.StatusSeeOther)
		return
	}

	// SUCCESS: Set cookie and redirect
	http.SetCookie(w, &http.Cookie{
		Name:     hh.authConfig.CookieName,
		Value:    ts.AccessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   hh.isSecure(),
		SameSite: http.SameSiteLaxMode,
	})

	if ts.RefreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     hh.authConfig.CookieName + "_refresh",
			Value:    ts.RefreshToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   hh.isSecure(),
			SameSite: http.SameSiteLaxMode,
		})
	}

	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (hh *HostHandler) LogoutPost(w http.ResponseWriter, r *http.Request) {
	// Login-CSRF defense (forced logout): reject a cross-origin submission.
	// See originAllowed / kdex-tech/host-manager#163.
	if !hh.originAllowed(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	returnURL := "/"

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	// Revoke the server-side refresh-token entry BEFORE we tell the
	// browser to forget the cookie. Without this a stolen `_refresh`
	// cookie value (XSS, log leak, shared-device residual) replays
	// for up to RefreshTokenTTL after the user "logs out". See
	// kdex-tech/host-manager#84.
	if hh.authConfig != nil && hh.authExchanger != nil {
		if c, err := r.Cookie(hh.authConfig.CookieName + "_refresh"); err == nil && c.Value != "" {
			// Fire-and-forget: errors here shouldn't block the logout
			// from completing.
			_ = hh.authExchanger.RevokeRefreshToken(r.Context(), c.Value)
		}
	}

	// Clear local cookies
	http.SetCookie(w, &http.Cookie{
		Name:     hh.authConfig.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Tells browser to delete immediately
		HttpOnly: true,
		Secure:   hh.isSecure(),
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     hh.authConfig.CookieName + "_refresh",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Tells browser to delete immediately
		HttpOnly: true,
		Secure:   hh.isSecure(),
		SameSite: http.SameSiteLaxMode,
	})

	// Build the OIDC Logout URL
	logoutURLString, err := hh.authExchanger.EndSessionURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if logoutURLString != "" {
		store := hh.authConfig.OIDC.IDTokenStore

		// Get the ID Token from the user's session
		idToken, err := store.Get(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logoutURL, err := url.Parse(logoutURLString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		returnURL := fmt.Sprintf("%s%s", hh.serverAddress(r), returnURL)

		q := logoutURL.Query()
		q.Add("id_token_hint", idToken)
		q.Add("post_logout_redirect_uri", returnURL)
		logoutURL.RawQuery = q.Encode()

		// 4. Redirect the user's browser to the OIDC Provider
		http.Redirect(w, r, logoutURL.String(), http.StatusFound)
	} else {
		http.Redirect(w, r, returnURL, http.StatusFound)
	}
}

// originAllowed enforces a same-origin check on state-changing POSTs
// (login/logout) to defend against login CSRF (kdex-tech/host-manager#163).
// SameSite=Lax does NOT cover this: the attacker submits their OWN credentials,
// and the browser stores the resulting Set-Cookie from the cross-site POST, so
// the victim ends up browsing as the attacker. Browsers always send Origin on a
// cross-site POST, so a present-but-cross-origin Origin (or Referer, when Origin
// is absent) is rejected. Both headers absent → allowed: that is a non-browser
// client (curl, server-to-server) which carries no ambient credentials and so is
// not subject to CSRF. A same-origin programmatic login — e.g. the signup app's
// post-claim-invite auto-login — sends a matching Origin and passes unchanged.
func (hh *HostHandler) originAllowed(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return hh.isSameOrigin(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return hh.isSameOrigin(ref)
	}
	return true
}

// isSameOrigin reports whether raw (an Origin header value or a Referer URL) has
// the host's scheme and exactly one of its configured domains. It compares
// against the host's own Routing.Domains — authoritative — rather than the
// request Host header, which the caller can influence.
func (hh *HostHandler) isSameOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != hh.scheme || hh.host == nil {
		return false
	}
	host := u.Hostname()
	for _, d := range hh.host.Routing.Domains {
		if strings.EqualFold(host, d) {
			return true
		}
	}
	return false
}

package host

import (
	"fmt"
	"net/http"
	"net/url"

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

	if oidc := hh.loginOIDCExtra(r, returnURL); oidc != nil {
		extras["oidc"] = oidc
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

// loginOIDCExtra is the login page's `oidc` template data. authCodeURL keeps
// its name for existing templates, but points at /-/oauth/login, which binds
// the login to this browser before sending it to the provider (#234); the
// page itself stays cacheable. prompt and login_hint from an authorize
// redirect are passed through to the provider (#233).
func (hh *HostHandler) loginOIDCExtra(r *http.Request, returnURL string) map[string]any {
	if !hh.authConfig.IsOIDCEnabled() {
		return nil
	}
	q := r.URL.Query()
	return map[string]any{
		"authCodeURL": auth.OIDCLoginURL(returnURL, q.Get("prompt"), q.Get("login_hint")),
		"name":        hh.authConfig.OIDC.Name,
		"provider":    hh.authConfig.OIDC.ProviderURL,
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

	// Snapshot the host-swapped state under a BRIEF read lock, then release it
	// before any hook I/O. EmitLogout runs the enforcing-logout hooks as a
	// blocking barrier (an outbound HTTP call bounded only by the hook timeout);
	// holding hh.mu.RLock across that would let a slow/hung logout hook stall a
	// concurrent reconcile's hh.mu.Lock() and, by RWMutex writer priority, every
	// request that needs the read lock. `scheme` is snapshotted too: SetHost
	// rewrites hh.scheme under hh.mu.Lock on every reconcile, and an unsynchronised
	// read of it is a documented data race (see host.go's issuerAddress /
	// issuerAddressLocked split), so the cookie Secure flag and the redirect base
	// below MUST use the local, never hh.isSecure()/hh.serverAddress() after
	// RUnlock. isSameOrigin (originAllowed, above) already runs lock-free.
	// See the #206 quad (PERF-1) and its re-review (RR-1).
	hh.mu.RLock()
	authConfig := hh.authConfig
	authExchanger := hh.authExchanger
	scheme := hh.scheme
	hh.mu.RUnlock()
	secure := scheme == schemeHTTPS

	// Revoke the server-side refresh-token entry BEFORE we tell the
	// browser to forget the cookie. Without this a stolen `_refresh`
	// cookie value (XSS, log leak, shared-device residual) replays
	// for up to RefreshTokenTTL after the user "logs out". See
	// kdex-tech/host-manager#84.
	if authConfig != nil && authExchanger != nil {
		if c, err := r.Cookie(authConfig.CookieName + "_refresh"); err == nil && c.Value != "" {
			// Barrier: run before RevokeRefreshToken so enforcing-logout
			// hooks can still read the refresh token's claims from cache --
			// RevokeRefreshToken deletes that same record. The ID token
			// isn't read yet at this point in the handler (only further
			// down, on the OIDC end-session path), so "" is passed; the
			// parameter is reserved for future OIDC end-session correlation.
			authExchanger.EmitLogout(r.Context(), c.Value, "")

			// Fire-and-forget: errors here shouldn't block the logout
			// from completing.
			_ = authExchanger.RevokeRefreshToken(r.Context(), c.Value)
		} else {
			// No refresh cookie (e.g. refresh tokens disabled, or an
			// already-expired session): the logout barrier must still run,
			// with an empty subject, so enforcing hooks see every logout.
			authExchanger.EmitLogout(r.Context(), "", "")
		}
	}

	// Clear local cookies
	http.SetCookie(w, &http.Cookie{
		Name:     authConfig.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Tells browser to delete immediately
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     authConfig.CookieName + "_refresh",
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Tells browser to delete immediately
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	// Build the OIDC Logout URL
	logoutURLString, err := authExchanger.EndSessionURL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if logoutURLString != "" {
		store := authConfig.OIDC.IDTokenStore

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

		returnURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, returnURL)

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
// the host's scheme and one of its configured domains. It compares against the
// host's own Routing.Domains — authoritative — rather than the request Host
// header, which the caller can influence.
func (hh *HostHandler) isSameOrigin(raw string) bool {
	if hh.host == nil {
		return false
	}
	return kdexhttp.SameOrigin(raw, hh.scheme, hh.host.Routing.Domains)
}

// consentOriginAllowed is originAllowed without the leniency: the consent POST
// releases an authorization code, so a request that does not PROVE it came
// from this host's own page is refused. Browsers send Origin on every form
// POST; "null" (an opaque or no-referrer origin) is not proof.
func consentOriginAllowed(r *http.Request, scheme string, domains []string) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		return kdexhttp.SameOrigin(o, scheme, domains)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return kdexhttp.SameOrigin(ref, scheme, domains)
	}
	return false
}

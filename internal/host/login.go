package host

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/kdex-tech/host-manager/internal/auth"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func (hh *HostHandler) LoginGet(w http.ResponseWriter, r *http.Request) {
	if hh.applyCachingHeaders(w, r, []kdexv1alpha1.SecurityRequirement{{"authenticated": {}}}, hh.reconcileTime) {
		return
	}

	query := r.URL.Query()
	returnURL := query.Get("return")
	if returnURL == "" {
		returnURL = "/"
	}

	// TODO: when OIDC is enabled show it on the Login screen so that we retain ability to login locally

	authCodeURL := hh.authExchanger.AuthCodeURL(returnURL)

	// If OIDC is configured, force login through it
	// if authCodeURL != "" {
	// 	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
	// 	return
	// }

	// Fallback: Local Login Page
	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	extras := map[string]any{}

	if authCodeURL != "" {
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

	hh.log.V(1).Info("serving login page", "language", l.String())

	w.Header().Set("Content-Language", l.String())
	w.Header().Set("Content-Type", "text/html")

	_, err = w.Write([]byte(rendered))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (hh *HostHandler) LoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	returnURL := r.FormValue("return")

	if returnURL == "" {
		returnURL = "/"
	}

	hh.log.V(1).Info("processing local login", "user", username)

	// Local login doesn't have a clientID, so we pass empty string
	// We also don't need the ID Token for cookie-based session
	ts, err := hh.authExchanger.LoginLocal(r.Context(), username, password, "", "", auth.AuthMethodLocal)
	if err != nil {
		// FAILED: 401 Unauthorized / render login page again with error message?
		// For now simple redirect back to login
		hh.log.Error(err, "local login failed")
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
	returnURL := "/"

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

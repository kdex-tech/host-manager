package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const consentRequestTTL = 10 * time.Minute

// consentRequest is what the consent page's form carries back, sealed. Only
// the subject, issuer, original query and expiry: everything else is derived
// from the query with parseAuthorizeRequest, exactly as authorize derives it.
type consentRequest struct {
	Sub   string `json:"sub"`
	Iss   string `json:"iss"`
	Query string `json:"q"`
	Exp   int64  `json:"exp"`
}

// isBrowserSession reports whether the session is a person's browser session,
// the only kind a dynamically registered client may get a code or a consent
// from. It must have come from the session cookie, and it must not be a token
// minted for an OAuth client (auth_method "oauth2": authorization-code,
// password and client_credentials tokens), which whoever holds it can put in
// the cookie. A deny-list, not an allow-list: an OIDC login session carries no
// auth_method until its first refresh, and it must keep working.
func isBrowserSession(ctx context.Context, ac AuthContext) bool {
	if AuthSourceFromContext(ctx) != COOKIE {
		return false
	}
	method, _ := ac["auth_method"].(string)
	return AuthMethod(method) != AuthMethodOAuth2
}

// consentCovers reports whether stored consent covers this request. Any
// store problem means "not covered": the page is shown, never skipped.
func (o *OAuth2) consentCovers(ctx context.Context, subject string, req authorizeRequest) bool {
	store := o.AuthConfig.DCRConsent
	if store == nil {
		return false
	}
	ok, err := store.Covers(ctx, subject, req.ClientID, req.RedirectURI, req.Scopes)
	if err != nil {
		logf.FromContext(ctx).Error(err, "dcr consent: read failed; showing the consent page", "clientID", req.ClientID)
		return false
	}
	return ok
}

// renderConsent answers an authorize request with the consent page.
func (o *OAuth2) renderConsent(w http.ResponseWriter, r *http.Request, client AuthClient, subject, account string, req authorizeRequest) {
	sealed, err := o.AuthExchanger.sealJSON(sealPurposeConsent, consentRequest{
		Sub:   subject,
		Iss:   o.AuthConfig.Issuer,
		Query: r.URL.RawQuery,
		Exp:   time.Now().Add(consentRequestTTL).Unix(),
	})
	if err != nil {
		logf.FromContext(r.Context()).Error(err, "dcr consent: failed to seal the request")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	// Flow-level headers, whoever renders: never cached, never framed (a
	// framed consent page is a click-hijacking target), and a referrer policy
	// that still lets the POST carry a real Origin (no-referrer would make it
	// "null", which the POST refuses).
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Add("Content-Security-Policy", "frame-ancestors 'none'")

	render := o.RenderConsent
	if render == nil {
		render = RenderBuiltinConsent
	}
	render(w, r, newConsentView(client.Name, req.RedirectURI, account, sealed, req.Scopes))
}

// ConsentPost records the user's decision on a consent page.
func (o *OAuth2) ConsentPost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logf.FromContext(ctx)
	forbidden := func(reason string) {
		log.V(1).Info("refusing a consent decision", "reason", reason)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
	unavailable := func(err error) {
		log.Error(err, "dcr consent: store unavailable")
		w.Header().Set("Retry-After", "5")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	}

	if o.ConsentOriginAllowed == nil || !o.ConsentOriginAllowed(r) {
		forbidden("not same-origin")
		return
	}
	authCtx, ok := GetAuthContext(ctx)
	if !ok || !isBrowserSession(ctx, authCtx) {
		forbidden("no browser session")
		return
	}
	subject, err := authCtx.GetSubject()
	if err != nil || subject == "" {
		forbidden("session names nobody")
		return
	}
	if err := r.ParseForm(); err != nil {
		forbidden("unparseable form")
		return
	}
	decision := r.PostFormValue("decision")
	if decision != "allow" && decision != "deny" {
		forbidden("unknown decision")
		return
	}
	var sealed consentRequest
	if err := o.AuthExchanger.openJSON(sealPurposeConsent, r.PostFormValue("request"), &sealed); err != nil {
		forbidden("sealed request does not open")
		return
	}
	if sealed.Sub != subject || sealed.Iss != o.AuthConfig.Issuer || time.Now().Unix() > sealed.Exp {
		forbidden("sealed request is for another session or has expired")
		return
	}
	q, err := url.ParseQuery(sealed.Query)
	if err != nil {
		forbidden("sealed query does not parse")
		return
	}
	req := parseAuthorizeRequest(q)
	client, ok, err := o.AuthExchanger.LookupClient(ctx, req.ClientID)
	if err != nil {
		unavailable(err)
		return
	}
	if !ok || !client.RequireConsent || !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		forbidden("client or redirect no longer registered")
		return
	}
	store := o.AuthConfig.DCRConsent
	if store == nil {
		unavailable(errors.New("no consent store"))
		return
	}

	if decision == "deny" {
		if err := store.Revoke(ctx, subject, req.ClientID, req.RedirectURI); err != nil {
			unavailable(err)
			return
		}
		callbackURL, err := url.Parse(req.RedirectURI)
		if err != nil {
			forbidden("registered redirect does not parse")
			return
		}
		redirectAuthorizeError(w, r, callbackURL, req.State, "access_denied")
		return
	}
	if err := store.Grant(ctx, subject, req.ClientID, req.RedirectURI, req.Scopes); err != nil {
		unavailable(err)
		return
	}
	// Back to authorize, which re-runs every check and mints the code, so
	// minting stays in one place. consent is removed so it cannot loop.
	http.Redirect(w, r, OAuthAuthorizePath+"?"+withoutPrompt(q, "consent").Encode(), http.StatusSeeOther)
}

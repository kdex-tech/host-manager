package host

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"github.com/kdex-tech/host-manager/internal/page"
	"golang.org/x/text/language"
	"kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (hh *HostHandler) pageHandlerFunc(
	ph page.PageHandler,
	translations *Translations,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logf.FromContext(r.Context())

		hh.mu.RLock()
		defer hh.mu.RUnlock()

		l, err := kdexhttp.GetLang(r, hh.defaultLanguage, translations.Languages())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if hh.IsAuthEnabled() && hh.authChecker != nil && ph.ParsedRequirements != nil {
			parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
			authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
				"pages", ph.BasePath(), parsedUserEntitlements, *ph.ParsedRequirements)

			if err != nil {
				log.Error(err, "authorization check failed", "resource", "pages", "resourceName", ph.BasePath())
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
				return
			}

			if !authorized {
				log.V(2).Info("unauthorized access attempt",
					"resource", "pages", "resourceName", ph.BasePath(), "l10n", l.String())

				outcome := denial.Classify(r.Context(), hh.authChecker, "pages", ph.BasePath())

				// An anonymous caller gets the login page with a return trip
				// -- but only if it can render one. This branch used to
				// redirect every anonymous caller, so an API client asking
				// for a gated page received a 303 to an HTML form instead of
				// the 401 that would have told it what to do. See #184 for
				// why the branch sits here, ahead of discovery.
				_, hasLoginPage := hh.utilityPages[v1alpha1.LoginUtilityPageType]
				if outcome == denial.Unauthenticated && hasLoginPage && acceptsHTML(r) {
					log.V(2).Info("unauthenticated, redirecting to login")
					// RequestURI, not Path: the return trip has to carry the
					// query string too, or a gated /search?q=foo sends the
					// user back to a bare /search. SafeReturnPath round-trips
					// a query and still collapses anything cross-origin.
					http.Redirect(w, r,
						"/-/login?return="+url.QueryEscape(r.URL.RequestURI()),
						http.StatusSeeOther)
					return
				}

				// FORBIDDEN has two browser renderings, selected by the
				// knob. Non-HTML callers fall through to the 403 below in
				// BOTH modes: the knob is about presentation, not about the
				// contract.
				//
				// The redirect is bounded to one hop. firstAuthorizedPage
				// can return a page that itself denies -- the navigation
				// walk and the page render are separate checks -- so a
				// request already carrying denied= renders the 403 instead
				// of redirecting again.
				if outcome != denial.Unauthenticated &&
					hh.pageDenialMode != PageDenialForbid &&
					acceptsHTML(r) &&
					!r.URL.Query().Has("denied") {

					first := hh.firstAuthorizedPage(r.Context(), &l, l.String() == hh.defaultLanguage)
					if first != "" {
						if l.String() != hh.defaultLanguage {
							first = "/" + l.String() + first
						}
						// r.URL.Path, not RequestURI: this is a label, never
						// a redirect target, so it needs no SafeReturnPath
						// collapse -- but it IS caller-influenceable, so any
						// consumer that renders it must treat it as text.
						target := first + "?denied=" + url.QueryEscape(r.URL.Path)
						log.V(2).Info("discovery redirect", "to", first, "denied", r.URL.Path)
						// A cached denial follows the user past the grant
						// change that fixed it.
						w.Header().Set("Cache-Control", "no-store")
						http.Redirect(w, r, target, http.StatusSeeOther)
						return
					}
					log.V(2).Info("no accessible page to discover; rendering 403")
				}

				denial.Write(w, r, denial.Opts{
					Outcome: outcome,
					Issuer:  hh.issuerAddress(),
				})
				return
			}
		}
		// Per-page seed: ph.Checksum() is sha256(ObservedGeneration +
		// sorted Status.Attributes), so the ETag invalidates only when
		// this specific KDexPage's observed state moved — not whenever
		// any other CR triggered a host reconcile. See #44.
		if hh.applyCachingHeadersWithSeed(w, r, hh.pageRequirements(&ph), hh.reconcileTime, l.String(), ph.Checksum()) {
			return
		}

		pageCache := hh.cacheManager.GetCache("page", cache.CacheOptions{})

		cacheKey := ph.CacheKey(l)

		rendered, ok, isCurrent, err := pageCache.Get(r.Context(), cacheKey)
		if err != nil {
			log.Error(err, "failed to get from cache", "page", ph.Name, "language", l)
		}

		if ok {
			// Check if we need to migrate this stale entry to the current generation
			if !isCurrent {
				log.V(2).Info("serving stale page, migrating in background", "page", ph.Name, "lang", l)

				// Background Migration. Hold hh.mu.RLock for the
				// duration of the re-render so the goroutine sees
				// consistent hh.* state vs concurrent SetHost writes.
				// See kdex-tech/host-manager#73.
				go func(p page.PageHandler, lang language.Tag, trans *Translations) {
					hh.mu.RLock()
					defer hh.mu.RUnlock()

					bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					newRender, err := hh.L10nRender(p, nil, lang, map[string]any{}, trans)
					if err == nil {
						_ = pageCache.Set(bgCtx, cacheKey, newRender)
					} else {
						log.Error(err, "background migration failed", "page", p.Name)
					}
				}(ph, l, translations)
			}

			log.V(2).Info("serving from cache", "page", ph.Name, "lang", l)

			// Serve the cached content (Current or Stale)
			hh.serveRendered(w, log, l, ph.Name, rendered)
			return
		}

		// 2. Cache Miss: Synchronous Render
		rendered, err = hh.L10nRender(ph, nil, l, map[string]any{}, translations)
		if err != nil {
			log.Error(err, "failed to render page", "page", ph.Name, "language", l)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Store the fresh render
		if err := pageCache.Set(r.Context(), cacheKey, rendered); err != nil {
			log.Error(err, "failed to set cache", "page", ph.Name, "language", l)
		}

		hh.serveRendered(w, log, l, ph.Name, rendered)
	}
}

// Small helper to keep the main handler clean
func (hh *HostHandler) serveRendered(w http.ResponseWriter, log logr.Logger, l language.Tag, name string, rendered string) {
	log.V(1).Info("serving", "page", name, "language", l)
	w.Header().Set("Content-Language", l.String())
	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(rendered)); err != nil {
		log.Error(err, "failed to write response", "page", name, "language", l)
	}
}

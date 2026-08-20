package host

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
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
				log.V(2).Info("unauthorized access attempt", "resource", "pages", "resourceName", ph.BasePath(), "l10n", l.String())

				// An anonymous caller gets the login page with a return
				// trip -- not a consolation page they happen to be allowed
				// to see. This branch used to sit *after* the
				// firstAuthorizedPage discovery below, which made it
				// unreachable on any host with a non-empty
				// anonymousEntitlements list: every caller has some
				// authorized page, so discovery always matched first and
				// the gate sent logged-out users somewhere arbitrary
				// instead of letting them log in. See #184.
				_, authenticated := auth.GetAuthContext(r.Context())
				if !authenticated {
					_, hasLoginPage := hh.utilityPages[v1alpha1.LoginUtilityPageType]
					if hasLoginPage {
						log.V(2).Info("unauthenticated, redirecting to login")
						http.Redirect(w, r, "/-/login?return="+url.QueryEscape(r.URL.Path), http.StatusSeeOther)
						return
					}
				}

				// Reached when the caller is already authenticated (logging
				// in again would not help them) or when the host configures
				// no login page at all.
				log.V(2).Info("attempt discovery of first accessible page", "l10n", l.String())
				first := hh.firstAuthorizedPage(r.Context(), &l, l.String() == hh.defaultLanguage)
				if first != "" {
					if l.String() != hh.defaultLanguage {
						first = "/" + l.String() + first
					}
					log.V(2).Info("first accessible page", "page", first, "l10n", l.String())
					http.Redirect(w, r, first, http.StatusSeeOther)
					return
				}

				log.V(2).Info("no accessible pages, send 404")
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
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

package host

import (
	"context"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"github.com/kdex-tech/host-manager/internal/page"
	"golang.org/x/text/language"
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

		if hh.authChecker != nil && ph.ParsedRequirements != nil {
			parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
			authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
				"pages", ph.BasePath(), parsedUserEntitlements, *ph.ParsedRequirements)

			if err != nil {
				log.Error(err, "authorization check failed", "resource", "pages", "resourceName", ph.BasePath())
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
				return
			}

			if !authorized {
				log.V(1).Info("unauthorized access attempt", "resource", "pages", "resourceName", ph.BasePath())
				if r.URL.Path == "/" {

				}
				http.Error(w, http.StatusText(http.StatusNotFound)+" "+r.URL.Path, http.StatusNotFound)
				return
			}
		}

		if hh.applyCachingHeaders(w, r, hh.pageRequirements(&ph), hh.reconcileTime) {
			return
		}

		l, err := kdexhttp.GetLang(r, hh.defaultLanguage, translations.Languages())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

				// Background Migration
				go func(p page.PageHandler, lang language.Tag, trans *Translations) {
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

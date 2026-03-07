package host

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/kdex-tech/entitlements"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	"github.com/kdex-tech/host-manager/internal/page"
	"golang.org/x/text/language"
	"k8s.io/apimachinery/pkg/api/resource"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/render"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (hh *HostHandler) BuildMenuEntries(
	ctx context.Context,
	entry *render.PageEntry,
	l *language.Tag,
	isDefaultLanguage bool,
	parent *page.PageHandler,
) {
	var parsedUserEntitlements *entitlements.ParsedEntitlements
	if hh.authChecker != nil {
		p := hh.authChecker.GetParsedEntitlements(ctx)
		parsedUserEntitlements = &p
	}

	hh.buildMenuEntriesRecursive(entry, l, isDefaultLanguage, parent, parsedUserEntitlements)
}

func (hh *HostHandler) buildMenuEntriesRecursive(
	entry *render.PageEntry,
	l *language.Tag,
	isDefaultLanguage bool,
	parent *page.PageHandler,
	parsedUserEntitlements *entitlements.ParsedEntitlements,
) {
	for _, handler := range hh.Pages.List() {
		ph := handler.Page

		if hh.authChecker != nil && parsedUserEntitlements != nil && handler.ParsedRequirements != nil {
			access, _ := hh.authChecker.VerifyResourceParsedEntitlements(
				"pages", ph.BasePath, *parsedUserEntitlements, *handler.ParsedRequirements)

			if !access {
				continue
			}
		} else if hh.authChecker != nil && parsedUserEntitlements != nil {
			// Fallback if requirements aren't pre-parsed for some reason
			requirements := hh.authChecker.ParseRequirements(hh.pageRequirements(&handler))
			access, _ := hh.authChecker.VerifyResourceParsedEntitlements(
				"pages", ph.BasePath, *parsedUserEntitlements, requirements)

			if !access {
				continue
			}
		}

		if (parent == nil && ph.ParentPageRef == nil) ||
			(parent != nil && ph.ParentPageRef != nil &&
				parent.Name == ph.ParentPageRef.Name) {

			if parent != nil && parent.Name == handler.Name {
				continue
			}

			if entry.Children == nil {
				entry.Children = &map[string]any{}
			}

			label := ph.Label

			href := ph.BasePath
			if !isDefaultLanguage {
				href = "/" + l.String() + ph.BasePath
			}

			pageEntry := render.PageEntry{
				BasePath: ph.BasePath,
				Href:     href,
				Label:    label,
				Name:     handler.Name,
				Weight:   resource.MustParse("0"),
			}

			if ph.NavigationHints != nil {
				pageEntry.Icon = ph.NavigationHints.Icon
				pageEntry.Weight = ph.NavigationHints.Weight
			}

			hh.buildMenuEntriesRecursive(&pageEntry, l, isDefaultLanguage, &handler, parsedUserEntitlements)

			(*entry.Children)[label] = pageEntry
		}
	}
}

func (hh *HostHandler) NavigationGet(w http.ResponseWriter, r *http.Request) {
	if hh.applyCachingHeaders(w, r, []kdexv1alpha1.SecurityRequirement{{"bearer": {}}}, hh.reconcileTime) {
		return
	}

	log := logf.FromContext(r.Context())

	hh.mu.RLock()
	defer hh.mu.RUnlock()

	basePath := "/" + r.PathValue("basePathMinusLeadingSlash")
	navKey := r.PathValue("navKey")
	defaultLang := hh.defaultLanguage
	translations := hh.Translations
	reconcileTime := hh.reconcileTime
	brandName := hh.host.BrandName
	org := hh.host.Organization

	var pageHandler *page.PageHandler
	for _, ph := range hh.Pages.List() {
		if ph.BasePath() == basePath {
			pageHandler = &ph
			break
		}
	}

	if pageHandler == nil {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}

	l, err := kdexhttp.GetLang(r, defaultLang, translations.Languages())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	navCache := hh.cacheManager.GetCache("nav", cache.CacheOptions{})
	userHash := hh.getUserHash(r)
	cacheKey := fmt.Sprintf("%s:%s:%s:%s", navKey, pageHandler.Checksum(), l.String(), userHash)

	rendered, ok, isCurrent, err := navCache.Get(r.Context(), cacheKey)
	if err == nil && ok {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(rendered))

		if isCurrent {
			return // Perfect hit
		}

		// 2. Stale Hit (vN-1): Serve fast, migrate in background
		log.V(2).Info("stale navigation hit, migrating in background", "key", cacheKey)

		// Clone necessary request context or data for the goroutine
		// Note: we don't pass r.Context() because it cancels when the request ends
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			newRender, err := hh.performNavigationRender(
				bgCtx,
				l,
				pageHandler,
				navKey,
				translations,
				defaultLang,
				brandName,
				org,
				reconcileTime,
			)
			if err == nil {
				_ = navCache.Set(bgCtx, cacheKey, newRender)
			}
		}()
		return
	}

	// 3. Cache Miss: Perform Synchronous Render
	log.V(2).Info("generating navigation", "basePath", basePath, "lang", l.String(), "navKey", navKey)
	rendered, err = hh.performNavigationRender(
		r.Context(),
		l,
		pageHandler,
		navKey,
		translations,
		defaultLang,
		brandName,
		org,
		reconcileTime,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := navCache.Set(r.Context(), cacheKey, rendered); err != nil {
		log.Error(err, "failed to cache navigation", "key", cacheKey)
	}

	w.Header().Set("Content-Type", "text/html")
	if _, err = w.Write([]byte(rendered)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Helper method to encapsulate the rendering logic for both Sync and Async paths
func (hh *HostHandler) performNavigationRender(
	ctx context.Context,
	l language.Tag,
	pageHandler *page.PageHandler,
	navKey string,
	translations Translations,
	defaultLang string,
	brandName string,
	org string,
	reconcileTime time.Time,
) (string, error) {
	var nav string
	for key, n := range pageHandler.Navigations {
		if key == navKey {
			nav = n
			break
		}
	}
	if nav == "" {
		return "", fmt.Errorf("navigation not found")
	}

	rootEntry := &render.PageEntry{}
	hh.BuildMenuEntries(ctx, rootEntry, &l, l.String() == defaultLang, nil)
	var pageMap map[string]any
	if rootEntry.Children != nil {
		pageMap = *rootEntry.Children
	}

	authContext, _ := auth.GetAuthContext(ctx)
	extra := map[string]any{}
	if authContext != nil {
		extra["Identity"] = authContext
	}

	renderer := render.Renderer{
		BasePath:        pageHandler.Page.BasePath,
		BrandName:       brandName,
		DefaultLanguage: defaultLang,
		Extra:           extra,
		Language:        l.String(),
		Languages:       hh.availableLanguages(&translations),
		LastModified:    reconcileTime,
		MessagePrinter:  hh.messagePrinter(&translations, l),
		Organization:    org,
		PageMap:         pageMap,
		PatternPath:     pageHandler.PatternPath(),
		Title:           pageHandler.Label(),
	}

	templateData, err := renderer.TemplateData()
	if err != nil {
		return "", err
	}

	return renderer.RenderOne(navKey, nav, templateData)
}

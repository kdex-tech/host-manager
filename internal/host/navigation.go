package host

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	entitlements "github.com/kdex-tech/entitlements/go"
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

// BuildMenuEntries fills entry.Children with the page tree the caller in ctx
// can see. It reads hh.tree, the page index RebuildMux published together
// with hh.pageSetDigest, so a tree always matches the digest a cache key
// carries for it (#283). Caller holds hh.mu.RLock.
func (hh *HostHandler) BuildMenuEntries(
	ctx context.Context,
	entry *render.PageEntry,
	l *language.Tag,
	isDefaultLanguage bool,
) {
	ents := hh.treeEntitlements(ctx)
	hh.buildMenuEntriesRecursive(entry, l, isDefaultLanguage, "", ents, hh.visibleChildren(ents))
}

// treeEntitlements is the caller's parsed entitlements for a tree build, or
// nil when there is no checker (every page is then visible).
func (hh *HostHandler) treeEntitlements(ctx context.Context) *entitlements.ParsedEntitlements {
	if hh.authChecker == nil {
		return nil
	}
	p := hh.authChecker.GetParsedEntitlements(ctx)
	return &p
}

// visibleChildren checks each page's visibility once and buckets the visible
// ones by parent name ("" for top-level pages), so a tree build costs N
// checks rather than N per level (#285). Buckets keep hh.tree's name order,
// so the build does not depend on map iteration order (#286). A
// parentPageRef with an empty name names no page: such a page is in no
// bucket, as it was in no tree before. Caller holds hh.mu.RLock.
func (hh *HostHandler) visibleChildren(
	parsedUserEntitlements *entitlements.ParsedEntitlements,
) map[string][]page.PageHandler {
	children := map[string][]page.PageHandler{}
	for _, handler := range hh.tree.pages {
		if !hh.visibleInTree(handler, parsedUserEntitlements) {
			continue
		}
		parentName := ""
		if ref := handler.Page.ParentPageRef; ref != nil {
			if ref.Name == "" {
				continue
			}
			parentName = ref.Name
		}
		children[parentName] = append(children[parentName], handler)
	}
	return children
}

// pageMap is the page tree BuildMenuEntries gives the caller in ctx, as a
// template's .PageMap: the root's children, or nil when no page is visible.
// context.Background() has no auth context, so it gives the ANONYMOUS
// caller's tree: GetParsedEntitlements of it is the anonymous set, which the
// checker matches against anonymousEntitlements. Caller holds hh.mu.RLock.
func (hh *HostHandler) pageMap(ctx context.Context, l language.Tag) map[string]any {
	root := &render.PageEntry{}
	hh.BuildMenuEntries(ctx, root, &l, l.String() == hh.defaultLanguage)
	if root.Children == nil {
		return nil
	}
	return *root.Children
}

// firstAuthorizedPage is the basePath of the lightest top-level page the
// caller can see, for a denied caller to land on. Text pages (robots.txt,
// sitemap.xml) are never a landing page. Weight alone is not a total order:
// every page without navigationHints.weight weighs 0, so ties are the normal
// case, and BasePath, unique per page, breaks them (#184). Caller holds
// hh.mu.RLock.
func (hh *HostHandler) firstAuthorizedPage(userEntitlements *entitlements.ParsedEntitlements) string {
	var candidates []page.PageHandler
	for _, ph := range hh.visibleChildren(userEntitlements)[""] {
		if pageModeOf(ph.Page) != render.PageTypeText {
			candidates = append(candidates, ph)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	best := slices.MinFunc(candidates, func(a, b page.PageHandler) int {
		aw, bw := navigationWeight(a.Page), navigationWeight(b.Page)
		if c := aw.Cmp(bw); c != 0 {
			return c
		}
		return strings.Compare(a.Page.BasePath, b.Page.BasePath)
	})
	return best.Page.BasePath
}

// navigationWeight is a page's navigationHints.weight, or 0 when unset.
func navigationWeight(spec *kdexv1alpha1.KDexPageSpec) resource.Quantity {
	if spec.NavigationHints != nil && spec.NavigationHints.Weight != nil {
		return *spec.NavigationHints.Weight
	}
	return resource.MustParse("0")
}

// discoverLandingPage picks where to send a caller the page gate denied. It
// honors the host's ordered spec.auth.defaultLandingPaths first — returning the
// first entry the caller is entitled to render, by the same visibleInTree
// check the tree uses — and falls back to firstAuthorizedPage when the list
// is empty/unset or nothing in it is reachable. The returned value is a bare
// basePath (no language prefix); the caller applies the /<lang> prefix,
// exactly as it does for firstAuthorizedPage.
// See docs/superpowers/specs/2026-09-10-default-landing-paths-design.md.
func (hh *HostHandler) discoverLandingPage(userEntitlements *entitlements.ParsedEntitlements) string {
	if hh.host != nil && hh.host.Auth != nil {
		for _, candidate := range hh.host.Auth.DefaultLandingPaths {
			if handler, ok := hh.tree.byBasePath[candidate]; ok && hh.visibleInTree(handler, userEntitlements) {
				return candidate
			}
		}
	}
	return hh.firstAuthorizedPage(userEntitlements)
}

// visibleInTree reports whether a page tree built for parsedUserEntitlements
// lists handler. It runs the page gate's entitlement check, with one
// difference: a page whose requirements are not parsed yet is hidden, where
// the gate would let it through, because a tree can be cached and shared
// (#283). A checker error hides the page. Caller holds hh.mu.RLock.
func (hh *HostHandler) visibleInTree(
	handler page.PageHandler,
	parsedUserEntitlements *entitlements.ParsedEntitlements,
) bool {
	if !hh.IsAuthEnabled() || hh.authChecker == nil || parsedUserEntitlements == nil {
		return true
	}
	if handler.ParsedRequirements == nil {
		return false
	}
	access, _ := hh.authChecker.VerifyResourceParsedEntitlements(
		"pages", handler.Page.BasePath, *parsedUserEntitlements, *handler.ParsedRequirements)
	return access
}

// pageModeOf is a KDexPage's operating mode, by the fields its spec sets.
// The CRD makes them mutually exclusive.
func pageModeOf(spec *kdexv1alpha1.KDexPageSpec) render.PageType {
	switch {
	case spec == nil:
		return render.PageTypeHTML
	case spec.Rewrite != nil:
		return render.PageTypeRewrite
	case spec.MimeType != "":
		return render.PageTypeText
	default:
		return render.PageTypeHTML
	}
}

// rewriteEntry describes an alias's target for its tree entry (#284). Href is
// the path a request at the alias's own Href ends up served from: the target
// path rewriteHandlerFunc builds for it (where no wildcard has a value),
// after the trailing-slash redirect the runtime follows internally. A
// sitemap can list it as the canonical URL instead of the alias. Href is
// empty when the target is not servable, when the path cannot be built, or
// when the target is a page this tree hides, so a sitemap never lists a
// gated target. Kind and Name are always set: /-/openapi already publishes
// them. Caller holds hh.mu.RLock.
func (hh *HostHandler) rewriteEntry(
	alias page.PageHandler,
	l *language.Tag,
	parsedUserEntitlements *entitlements.ParsedEntitlements,
) *render.PageRewrite {
	rw := alias.Page.Rewrite
	entry := &render.PageRewrite{
		Canonical: rw.Canonical,
		Kind:      rw.TargetRef.Kind,
		Name:      rw.TargetRef.Name,
	}
	if rw.TargetRef.Kind == "KDexPage" {
		target, ok := hh.tree.byName[rw.TargetRef.Name]
		if !ok || !hh.visibleInTree(target, parsedUserEntitlements) {
			return entry
		}
	}
	resolved, ok := resolveRewriteTarget(rw.TargetRef, hh.tree.byName, hh.functions)
	if !ok {
		return entry
	}
	// A localized: false alias registers only its bare route, which serves
	// the default language whatever tree lists it.
	lang := *l
	if !isLocalized(alias.Page.Localized) {
		lang = language.Make(hh.defaultLanguage)
	}
	href, err := rewriteTargetPath(resolved, rw, alias.Page.PatternPath, func(string) string { return "" }, lang, hh.defaultLanguage)
	if err != nil {
		return entry
	}
	if strings.HasSuffix(href, "/") && href != resolved.basePath && href != "/" {
		href = strings.TrimSuffix(href, "/")
	}
	entry.Href = href
	return entry
}

// buildMenuEntriesRecursive adds parentName's visible children to entry and
// recurses into each. Only pages reachable from the root are listed, so a
// page naming itself (or a cycle) as its parent never is.
func (hh *HostHandler) buildMenuEntriesRecursive(entry *render.PageEntry,
	l *language.Tag,
	isDefaultLanguage bool,
	parentName string,
	parsedUserEntitlements *entitlements.ParsedEntitlements,
	children map[string][]page.PageHandler,
) {
	for _, handler := range children[parentName] {
		ph := handler.Page

		if entry.Children == nil {
			entry.Children = &map[string]any{}
		}

		// Entries are keyed by label, so two siblings with one label cannot
		// both be listed. The bucket is in name order, so the page whose name
		// sorts first keeps the slot on every render and every replica.
		// RebuildMux logs the collision (#286).
		label := ph.Label
		if _, taken := (*entry.Children)[label]; taken {
			continue
		}

		// A page with localized: false registers only its bare route, so
		// a language prefix would link a 404 (#283).
		href := ph.BasePath
		if !isDefaultLanguage && isLocalized(ph.Localized) {
			href = "/" + l.String() + ph.BasePath
		}

		pageEntry := render.PageEntry{
			BasePath: ph.BasePath,
			Href:     href,
			Label:    label,
			Name:     handler.Name,
			Type:     pageModeOf(ph),
			Weight:   navigationWeight(ph),
		}

		// The page's mode, so a template can tell a text file or an alias
		// from an HTML page without a tag (#284).
		switch pageEntry.Type {
		case render.PageTypeRewrite:
			pageEntry.Rewrite = hh.rewriteEntry(handler, l, parsedUserEntitlements)
		case render.PageTypeText:
			pageEntry.MimeType = ph.MimeType
		}

		if ph.NavigationHints != nil {
			pageEntry.Icon = ph.NavigationHints.Icon
		}

		// Project the page's spec.tags onto the nav entry so templates can
		// render tag-driven badges, groupings, tooltips, or external links
		// via [[ range $t := $value.Tags ]].
		if len(ph.Tags) > 0 {
			pageEntry.Tags = make([]render.PageTag, 0, len(ph.Tags))
			for _, tag := range ph.Tags {
				pageEntry.Tags = append(pageEntry.Tags, render.PageTag{
					Name:        tag.Name,
					Description: tag.Description,
					URL:         tag.URL,
				})
			}
		}

		hh.buildMenuEntriesRecursive(&pageEntry, l, isDefaultLanguage, handler.Name, parsedUserEntitlements, children)

		(*entry.Children)[label] = pageEntry
	}
}

func (hh *HostHandler) NavigationGet(w http.ResponseWriter, r *http.Request) {
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

	found, ok := hh.tree.byBasePath[basePath]
	if !ok {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	pageHandler := &found

	l, err := kdexhttp.GetLang(r, defaultLang, translations.Languages())
	if err != nil {
		// {l10n} here is a caller-supplied API path parameter (unlike page
		// routes), so a bad/unsupported value is a CLIENT error, never a
		// server fault. See kdex-tech/host-manager task 4.1.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// applyCachingHeadersWithSeed folds language + per-page seed
	// (#43, #44) so en-CA / fr-CA renders get distinct ETags AND each
	// page's nav fragment invalidates only when its own observed state
	// moves rather than on every host reconcile. The fragment renders the
	// whole page tree, so the seed and the cache key also carry the page-set
	// digest (treeSeed, #283).
	seed := hh.treeSeed(pageHandler.Checksum())
	if hh.applyCachingHeadersWithSeed(w, r, []kdexv1alpha1.SecurityRequirement{{"bearer": {}}}, hh.reconcileTime, l.String(), seed) {
		return
	}

	navCache := hh.cacheManager.GetCache(navCacheClass, cache.CacheOptions{})
	renderNav := func(ctx context.Context) (string, error) {
		return hh.performNavigationRender(ctx, l, pageHandler, navKey, translations, defaultLang, brandName, org, reconcileTime)
	}
	write := func(rendered string) {
		// A navigation fragment is per-user HTML like a page, so it carries
		// the same framing and nosniff headers (#248).
		hh.setPageSecurityHeadersLocked(w)
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(rendered)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	userHash, cacheable := hh.getUserHash(r)
	if !cacheable {
		// A signed-in caller getUserHash cannot key: render for them alone,
		// never through a cache key another caller could share.
		rendered, err := renderNav(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		write(rendered)
		return
	}
	cacheKey := navCacheKey(navKey, basePath, seed, l, userHash)
	renderKey := navCacheClass + "\x00" + cacheKey

	rendered, ok, isCurrent, err := navCache.Get(r.Context(), cacheKey)
	if err == nil && ok {
		write(rendered)
		if isCurrent {
			return // Perfect hit
		}

		// 2. Stale Hit (vN-1): serve fast, migrate in background. The
		// fragment is the caller's: the re-render runs with the request's
		// auth context, detached from its cancellation, so it builds the
		// caller's tree and Identity and not the anonymous one.
		log.V(2).Info("stale navigation hit, migrating in background", "key", cacheKey)
		callerCtx := context.WithoutCancel(r.Context())
		hh.migrateInBackground(renderKey, func() {
			if hh.treeSeed(pageHandler.Checksum()) != seed {
				return
			}
			bgCtx, cancel := context.WithTimeout(callerCtx, 15*time.Second)
			defer cancel()
			if fresh, err := renderNav(bgCtx); err == nil {
				_ = navCache.Set(bgCtx, cacheKey, fresh)
			}
		})
		return
	}

	// 3. Cache Miss: synchronous render. Concurrent misses on one key (one
	// caller, or every anonymous caller) share one render (#285), stored
	// under a context detached from the leader's request with its own
	// deadline, as pageHandlerFunc does.
	log.V(2).Info("generating navigation", "basePath", basePath, "lang", l.String(), "navKey", navKey)
	v, err, _ := hh.pageRenders.Do(renderKey, func() (any, error) {
		fresh, err := renderNav(r.Context())
		if err != nil {
			return "", err
		}
		setCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), pageCacheSetTimeout)
		defer cancel()
		if err := navCache.Set(setCtx, cacheKey, fresh); err != nil {
			log.Error(err, "failed to cache navigation", "key", cacheKey)
		}
		return fresh, nil
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rendered, _ = v.(string)
	write(rendered)
}

// navCacheKey is a navigation fragment's cache key: the fragment, the page
// hosting it, its tree seed, the language and the caller.
func navCacheKey(navKey, basePath, seed string, l language.Tag, userHash string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", navKey, basePath, seed, l.String(), userHash)
}

// treeSeed extends a render's per-page seed with the page-set digest, for a
// render that reads the whole page tree: the host checksum the caches cycle
// on does not move when another page changes (#283). Caller holds
// hh.mu.RLock.
func (hh *HostHandler) treeSeed(pageChecksum string) string {
	return pageChecksum + ":" + hh.pageSetDigest
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

	pageMap := hh.pageMap(ctx, l)

	extra := map[string]any{}
	extra["AuthEnabled"] = hh.IsAuthEnabled()

	authContext, _ := auth.GetAuthContext(ctx)
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

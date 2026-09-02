package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host/ico"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	"github.com/kdex-tech/host-manager/internal/utils"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"k8s.io/apimachinery/pkg/api/meta"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"kdex.dev/crds/render"
)

func (hh *HostHandler) AddOrUpdateTranslation(name string, translation *kdexv1alpha1.KDexTranslationSpec) {
	if translation == nil {
		return
	}
	hh.log.V(3).Info("add or update translation", "translation", name)

	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.translationResources[name] = *translation
}

func (hh *HostHandler) AddOrUpdateUtilityPage(ph page.PageHandler) {
	if ph.UtilityPage == nil {
		return
	}
	hh.log.V(3).Info("add or update utility page", "name", ph.Name, "type", ph.UtilityPage.Type)
	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.utilityPages[ph.UtilityPage.Type] = ph
}

func (hh *HostHandler) FootScriptToHTML(handler page.PageHandler) string {
	var buffer bytes.Buffer
	separator := ""

	for _, script := range hh.scripts {
		buffer.WriteString(separator)
		buffer.WriteString(script.ToFootTag())
		separator = "\n"
	}
	for _, script := range handler.Scripts {
		buffer.WriteString(separator)
		buffer.WriteString(script.ToFootTag())
		separator = "\n"
	}

	return buffer.String()
}

func (hh *HostHandler) GetCacheManager() cache.CacheManager {
	return hh.cacheManager
}

func (hh *HostHandler) GetOpenAPIBuilder() *ko.Builder {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	return &hh.openapiBuilder
}

func (hh *HostHandler) Checksum() string {
	if hh.checksum != "" {
		return hh.checksum
	}

	// Generate a checksum based on the hh.status
	// This is used to invalidate the cache when the host changes
	// We use the hh.status to ensure that the cache is invalidated when the host changes

	if hh.status == nil {
		return ""
	}

	// 1. Extract the keys
	keys := make([]string, 0, len(hh.status.Attributes))
	for k := range hh.status.Attributes {
		keys = append(keys, k)
	}

	// 2. Sort the keys alphabetically
	sort.Strings(keys)

	// 3. Create a hash object
	h := sha256.New()

	// 4. Write the status.ObservedGeneration
	h.Write([]byte(strconv.FormatInt(hh.status.ObservedGeneration, 10)))

	// 5. Write key-value pairs in the sorted order
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(hh.status.Attributes[k]))
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func (hh *HostHandler) GeneratePageCacheKey(ph page.PageHandler, l language.Tag) string {
	return fmt.Sprintf("%s:%s", ph.Name, l.String())
}

func (hh *HostHandler) GetStatus() HostStatus {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.status != nil {
		if hh.status.Conditions == nil {
			return HostStatusDegraded
		}

		if meta.IsStatusConditionTrue(hh.status.Conditions, string(kdexv1alpha1.ConditionTypeReady)) {
			return HostStatusReady
		}
		if meta.IsStatusConditionTrue(hh.status.Conditions, string(kdexv1alpha1.ConditionTypeProgressing)) {
			return HostStatusProgressing
		}
		if meta.IsStatusConditionTrue(hh.status.Conditions, string(kdexv1alpha1.ConditionTypeDegraded)) {
			return HostStatusDegraded
		}
	}

	return HostStatusInitializing
}

func (hh *HostHandler) GetUtilityPageHandler(name kdexv1alpha1.KDexUtilityPageType) page.PageHandler {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	ph, ok := hh.utilityPages[name]
	if !ok {
		return page.PageHandler{}
	}
	return ph
}

func (hh *HostHandler) HeadScriptToHTML(handler page.PageHandler) string {
	packageReferences := make(map[string]kdexv1alpha1.PackageReference, len(hh.packageReferences)+len(handler.PackageReferences))
	for _, pr := range hh.packageReferences {
		packageReferences[pr.Name] = pr
	}
	for _, pr := range handler.PackageReferences {
		packageReferences[pr.Name] = pr
	}

	var buffer bytes.Buffer
	separator := ""

	if len(packageReferences) > 0 {
		buffer.WriteString("<script type=\"importmap\">\n")
		buffer.WriteString(hh.importmap)
		buffer.WriteString("\n</script>\n")

		buffer.WriteString("<script type=\"module\">\n")

		seen := map[string]bool{}
		for _, pr := range packageReferences {
			statement := pr.ToImportStatement()
			if seen[statement] {
				continue
			}
			seen[statement] = true
			buffer.WriteString(separator)
			buffer.WriteString(statement)
			separator = "\n"
		}
		buffer.WriteString("\n</script>")
	}

	for _, script := range hh.scripts {
		buffer.WriteString(separator)
		buffer.WriteString(script.ToHeadTag())
		separator = "\n"
	}
	for _, script := range handler.Scripts {
		buffer.WriteString(separator)
		buffer.WriteString(script.ToHeadTag())
		separator = "\n"
	}

	return buffer.String()
}

func (hh *HostHandler) IsAuthEnabled() bool {
	return hh.authConfig != nil && hh.authConfig.IsAuthEnabled()
}

func (hh *HostHandler) L10nRender(
	handler page.PageHandler,
	pageMap map[string]any,
	l language.Tag,
	extraTemplateData map[string]any,
	translations *Translations,
) (string, error) {

	// make sure everything passed to the renderer is mutation safe (i.e. copy it)

	renderer := render.Renderer{
		Extra:   maps.Clone(extraTemplateData),
		PageMap: maps.Clone(pageMap),

		// language details
		DefaultLanguage: hh.defaultLanguage,
		Language:        l.String(),
		Languages:       hh.availableLanguages(translations),
		MessagePrinter:  hh.messagePrinter(translations, l),

		// host details
		BrandName:    hh.getBrandName(),
		LastModified: hh.reconcileTime,
		Organization: hh.getOrganization(),
		Theme:        hh.ThemeAssetsToString(),

		// page details
		BasePath:        handler.BasePath(),
		Contents:        handler.ContentToHTMLMap(),
		Footer:          handler.Footer,
		Header:          handler.Header,
		Navigations:     handler.NavigationToHTMLMap(),
		PatternPath:     handler.PatternPath(),
		TemplateContent: handler.MainTemplate,
		TemplateName:    handler.Name,
		Title:           handler.Label(),

		// combined details
		FootScript: hh.FootScriptToHTML(handler),
		HeadScript: hh.HeadScriptToHTML(handler),
		Meta:       hh.MetaToString(handler, l),
	}

	return renderer.RenderPage()
}

func (hh *HostHandler) L10nRenders(
	handler page.PageHandler,
	pageMaps map[language.Tag]map[string]any,
	translations *Translations,
) map[string]string {
	l10nRenders := make(map[string]string)
	for _, l := range translations.Languages() {
		rendered, err := hh.L10nRender(handler, pageMaps[l], l, map[string]any{}, translations)
		if err != nil {
			hh.log.Error(err, "failed to render page for language", "page", handler.Name, "language", l)
			continue
		}
		l10nRenders[l.String()] = rendered
	}
	return l10nRenders
}

func (hh *HostHandler) MetaToString(handler page.PageHandler, l language.Tag) string {
	var buffer bytes.Buffer

	if hh.host != nil && len(hh.host.Assets) > 0 {
		buffer.WriteString(hh.host.Assets.String())
		buffer.WriteRune('\n')
	}

	basePath := handler.BasePath()
	if l.String() != hh.defaultLanguage {
		basePath = "/" + l.String() + basePath
	}
	patternPath := handler.PatternPath()
	if l.String() != hh.defaultLanguage {
		patternPath = "/" + l.String() + patternPath
	}

	fmt.Fprintf(
		&buffer,
		kdexUIMetaTemplate,
		basePath,
		patternPath,
	)

	return buffer.String()
}

// rebuildSnapshot carries the fully-assembled mux + state from the read
// phase of RebuildMux to the commit phase. Decoupling the two phases lets
// both lock acquisitions use defer'd unlocks so a panic in either phase
// (e.g. ParseRequirements on a corrupted SecurityRequirements slice header,
// kdex-tech/host-manager#26) auto-releases the lock instead of orphaning
// it and deadlocking subsequent reconciles.
type rebuildSnapshot struct {
	translations     *Translations
	registeredPaths  map[string]ko.PathInfo
	mux              *http.ServeMux
	functionHandlers map[string]*KDexFunctionHandler
	// hasFunctionHandlers distinguishes the empty-set case (overwrite
	// hh.functionHandlers with the empty map) from the not-ready case
	// (don't touch hh.functionHandlers at all).
	hasFunctionHandlers bool
}

func (hh *HostHandler) RebuildMux() {
	hh.log.V(3).Info("rebuilding mux")

	snap, ok := hh.rebuildMuxSnapshot()
	if !ok {
		return
	}

	hh.mu.Lock()
	defer hh.mu.Unlock()
	hh.Translations = *snap.translations
	hh.registeredPaths = snap.registeredPaths
	hh.Mux = snap.mux
	if snap.hasFunctionHandlers {
		hh.functionHandlers = snap.functionHandlers
	}
}

// rebuildMuxSnapshot performs all reads and assembles the new mux under a
// single defer'd RLock. A panic anywhere inside (most plausibly inside
// authChecker.ParseRequirements) unwinds through the defer and releases
// the lock cleanly. See kdex-tech/host-manager#26.
func (hh *HostHandler) rebuildMuxSnapshot() (rebuildSnapshot, bool) {
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	if hh.host == nil {
		return rebuildSnapshot{}, false
	}

	defaultLanguageResource := hh.defaultLanguage
	translationResources := maps.Clone(hh.translationResources)

	newTranslations, err := NewTranslations(defaultLanguageResource, translationResources)
	if err != nil {
		hh.log.Error(err, "failed to rebuild translations")
		return rebuildSnapshot{}, false
	}

	registeredPaths := map[string]ko.PathInfo{}
	maps.Copy(registeredPaths, hh.pathsCollectedInReconcile)
	mux := hh.muxWithDefaultsLocked(registeredPaths)

	pageHandlers := hh.Pages.List()
	if len(pageHandlers) == 0 && len(hh.functions) == 0 {
		// One literal prefix per supported language, replacing the /{l10n}
		// wildcard -- same enumerated-prefix treatment as page routes in
		// addHandlerAndRegister. newTranslations (not hh.Translations,
		// which this snapshot has not been swapped into yet) is the source
		// of truth for this build's supported languages.
		for _, lang := range newTranslations.Languages() {
			handler := hh.notReadyHandlerFunc(lang)
			if lang.String() == defaultLanguageResource {
				mux.HandleFunc("GET /{$}", handler)
				continue
			}
			mux.HandleFunc("GET /"+lang.String()+"/{$}", handler)
		}
		return rebuildSnapshot{
			translations:    newTranslations,
			registeredPaths: registeredPaths,
			mux:             mux,
		}, true
	}

	renderedPages := map[string]pageRender{}
	for _, ph := range pageHandlers {
		basePath := ph.BasePath()

		if basePath == "" {
			hh.log.V(1).Info("somehow page has empty basePath, skipping", "page", ph.Name)
			continue
		}

		// Pre-parse requirements for Power API. authChecker.ParseRequirements
		// has its own defensive recover (#26), but the snapshot's defer'd
		// RLock-release is the last line of defense if recovery is bypassed.
		if hh.authChecker != nil {
			reqs := hh.pageRequirements(&ph)
			parsed := hh.parsePageRequirementsFailClosed(reqs, ph.Name, basePath)
			hh.Pages.UpdateParsedRequirements(ph.Name, parsed)
			ph.ParsedRequirements = &parsed // Also update the local copy used for rendering
		}

		renderedPages[basePath] = pageRender{ph: ph}
	}

	functionHandlers := []functionHandler{}
	actualHandlers := map[string]*KDexFunctionHandler{}
	// reverseProxyHandler dereferences hh.authConfig.ActivePair to construct
	// the signing key for FAT minting; without a fully built authConfig the
	// call panics. Skip the function loop entirely when auth isn't set up
	// (envtest fixtures with empty spec.auth, or pre-SetHost startup).
	if hh.issuerAddressLocked() != "" && hh.authConfig != nil && hh.authConfig.ActivePair != nil {
		for _, f := range hh.functions {
			if f.Status.State != kdexv1alpha1.KDexFunctionStateReady {
				continue
			}
			// internal functions are not exposed through the host mux;
			// in-cluster callers reach them at the cluster-local Knative URL
			// (e.g. auth.HTTPLookup credential checks). See kdex-tech/kdex-crds#6.
			if f.Spec.Internal {
				continue
			}
			h := hh.reverseProxyHandler(&f, hh.issuerAddressLocked())
			// reverseProxyHandler returns a plain error handler when it cannot
			// build the proxy -- an unparseable function URL, an invalid
			// ClaimMappings mapper, or a FAT signer it was refused. Assert
			// rather than panic: leaving the route unregistered 404s it, which
			// is the fail-closed outcome, where the unchecked assertion took
			// the whole reconcile down.
			fh, ok := h.(*KDexFunctionHandler)
			if !ok {
				hh.log.Error(nil, "function handler could not be built; route not registered",
					"function", f.Name, "basePath", f.Spec.API.BasePath)
				continue
			}
			actualHandlers[f.Spec.API.BasePath] = fh
			functionHandlers = append(functionHandlers, functionHandler{
				basePath: f.Spec.API.BasePath,
				handler:  fh,
			})
		}
	}

	// Mux mutations happen on local objects (mux + registeredPaths) — no hh
	// state is touched here, so this can stay under the read lock.
	for _, pr := range renderedPages {
		if err := hh.addHandlerAndRegister(mux, pr, registeredPaths, newTranslations); err != nil {
			hh.log.Error(err, "skipping")
		}
	}
	for _, fh := range functionHandlers {
		// Register both the exact path and the prefix path (with trailing slash)
		// to ensure all sub-paths are proxied correctly.
		mux.Handle(fh.basePath, fh.handler)
		if !strings.HasSuffix(fh.basePath, "/") {
			mux.Handle(fh.basePath+"/", fh.handler)
		}
	}

	return rebuildSnapshot{
		translations:        newTranslations,
		registeredPaths:     registeredPaths,
		mux:                 mux,
		functionHandlers:    actualHandlers,
		hasFunctionHandlers: true,
	}, true
}

func (hh *HostHandler) RemovePage(name string) {
	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.log.V(1).Info("delete page", "name", name)
	hh.Pages.Delete(name)
}

func (hh *HostHandler) RemoveTranslation(name string) {
	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.log.V(1).Info("delete translation", "translation", name)
	delete(hh.translationResources, name)
}

func (hh *HostHandler) RemoveUtilityPage(name string) {
	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.log.V(1).Info("delete utility page", "name", name)
	for t, ph := range hh.utilityPages {
		if ph.Name == name {
			delete(hh.utilityPages, t)
			break
		}
	}
}

// oauthFlowScopes is the scope map advertised for every OAuth flow in the
// generated document. The three flows advertise the same set, so it is built
// once -- three verbatim copies could drift a description without anything
// noticing.
func oauthFlowScopes() map[string]string {
	return map[string]string{
		"openid":  "standard oidc scope",
		"profile": "user profile info",
	}
}

func (hh *HostHandler) SecuritySchemes() *openapi.SecuritySchemes {
	req := &openapi.SecuritySchemes{}

	if !hh.IsAuthEnabled() {
		return req
	}

	(*req)["apiKeyCookie"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description: "Stateless API Token in 'X-API-TOKEN' cookie",
			Type:        "apiKey",
			In:          "cookie",
			Name:        "X-API-TOKEN",
		},
	}

	(*req)["apiKeyHeader"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description: "Stateless API Token in 'X-API-TOKEN' header",
			Type:        "apiKey",
			In:          "header",
			Name:        "X-API-TOKEN",
		},
	}

	(*req)["apiKeyQuery"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description: "Stateless API Token in 'api_token' query parameter",
			Type:        "apiKey",
			In:          "query",
			Name:        "api_token",
		},
	}

	(*req)["bearer"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description:  "Bearer Token - This is the default scheme",
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		},
	}

	(*req)["oauth2"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description: "OAuth2 authentication using Password, Authorization Code, or Client Credentials Flow",
			Flows: &openapi.OAuthFlows{
				AuthorizationCode: &openapi.OAuthFlow{
					AuthorizationURL: "/-/oauth/authorize",
					Scopes:           oauthFlowScopes(),
					TokenURL:         "/-/token",
				},
				ClientCredentials: &openapi.OAuthFlow{
					Scopes:   oauthFlowScopes(),
					TokenURL: "/-/token",
				},
				Password: &openapi.OAuthFlow{
					Scopes:   oauthFlowScopes(),
					TokenURL: "/-/token",
				},
			},
			Type: "oauth2",
		},
	}

	(*req)["oidc"] = &openapi.SecuritySchemeRef{
		Value: &openapi.SecurityScheme{
			Description:      "OpenID Connect discovery",
			OpenIdConnectUrl: "/.well-known/openid-configuration",
			Type:             "openIdConnect",
		},
	}

	return req
}

func (hh *HostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Snapshot every field this method dereferences under one RLock.
	// Pre-#88 only hh.Mux was captured; hh.authConfig and
	// hh.authExchanger were read at line 591 with no lock, racing
	// SetHost's writes under Lock. Race detector tripped; an unlucky
	// torn-interface read of hh.authConfig could nil-deref the
	// method-table pointer mid-call.
	hh.mu.RLock()
	mux := hh.Mux
	authConfig := hh.authConfig
	authExchanger := hh.authExchanger
	hh.mu.RUnlock()

	// While the host is initializing we still need to honor the contracts of
	// system endpoints (`/.well-known/*`, `/-/*`, favicon): downstream
	// consumers fetch JWKS, OIDC discovery, OAuth, etc. as part of pod
	// startup and expect JSON, not the HTML announcement page. The
	// announcement only applies to page paths. See kdex-tech/host-manager#33.
	if hh.GetStatus() == HostStatusInitializing && !isSystemPath(r.URL.Path) {
		// Unlike the registered not-ready routes (one literal prefix per
		// supported language -- see rebuildMuxSnapshot), this fires for
		// ANY request path while the host is still initializing, before
		// mux dispatch even applies. There is no literal prefix to read
		// the language from here, so it still resolves per-request via
		// GetLang (Accept-Language / ?l10n= fallback), same as before.
		hh.mu.RLock()
		l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
		hh.mu.RUnlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		hh.notReadyHandlerFunc(l)(w, r)
		return
	}

	if mux == nil {
		hh.serveError(w, r, http.StatusNotFound, "not found")
		return
	}

	// The sniffer (DesignMiddleware) inspects authenticated identity to decide
	// whether the caller may auto-generate KDexFunctions, so authentication must
	// resolve first and place the AuthContext on the request context.
	wrappedMux := hh.DesignMiddleware(mux)
	wrappedMux = authConfig.AddAuthentication(wrappedMux, authExchanger)
	wrappedMux.ServeHTTP(w, r)
}

// TODO: add individual cache configurations
func (hh *HostHandler) SetHost(
	ctx context.Context,
	host *kdexv1alpha1.KDexHostSpec,
	status *kdexv1alpha1.KDexObjectStatus,
	packageReferences []kdexv1alpha1.PackageReference,
	themeAssets []kdexv1alpha1.Asset,
	scripts []kdexv1alpha1.ScriptDef,
	importmap string,
	paths map[string]ko.PathInfo,
	functions []kdexv1alpha1.KDexFunction,
	authExchanger *auth.Exchanger,
	authConfig *auth.Config,
	scheme string,
	snif *sniffer.RequestSniffer,
	reconcileTime time.Time,
) {
	hh.log.V(3).Info("[SetHost] about to lock")

	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.log.V(3).Info("[SetHost] obtained lock")

	hh.checksum = ""
	if host.DefaultLang != "" {
		hh.defaultLanguage = host.DefaultLang
	} else {
		hh.defaultLanguage = "en"
	}
	hh.functions = functions
	hh.host = host
	hh.importmap = importmap
	hh.packageReferences = packageReferences
	hh.pathsCollectedInReconcile = paths
	hh.reconcileTime = reconcileTime
	hh.scheme = scheme
	hh.scripts = scripts
	hh.status = status
	hh.themeAssets = themeAssets

	// force=false: rotate cycled caches (rendered pages, navigation,
	// importmap) with a prevPrefix transition window for graceful cutover,
	// but DO NOT touch Uncycled caches. The refresh-tokens cache is
	// registered Uncycled because it holds user-session state that must
	// survive routine config-change reconciles — force=true here would
	// silently evict every active refresh token on every CR apply,
	// surfacing as "refresh token not found or expired" errors right when
	// a user's JWT is about to expire. See kdex-tech/host-manager#42.
	if err := hh.cacheManager.Cycle(hh.Checksum(), false); err != nil {
		hh.log.Error(err, "failed to cycle cache manager")
	}

	favicon := ico.NewICO(host.FaviconSVGTemplate, render.TemplateData{
		BrandName:       host.BrandName,
		DefaultLanguage: host.DefaultLang,
		Organization:    host.Organization,
	})
	favicon.SetReconcileTime(hh.reconcileTime)
	hh.favicon = favicon

	if snif != nil {
		hh.sniffer = snif
	} else {
		hh.sniffer = nil
	}

	hh.log.V(3).Info("[SetHost] authConfig has been set")

	if authConfig != nil {
		hh.authConfig = authConfig
		hh.authChecker = auth.NewAuthorizationChecker(authConfig.AnonymousEntitlements, hh.log.WithName("authChecker"))
		hh.authExchanger = authExchanger

		// Hand the middleware the map it needs to name a resource in the 401
		// bearer challenge (#180). It must be computed here: hh.functions was
		// set above, and the middleware wraps the whole mux with no way to
		// resolve a path to a function on its own.
		//
		// INSIDE this block deliberately. authConfig is freshly built per
		// reconcile (ConfigBuilder.Build always returns a new *Config, and the
		// exchanger takes a copy rather than the pointer), so nothing can be
		// reading it yet, and both the publication above and this write happen
		// under hh.mu while ServeHTTP takes the pointer under RLock. Hoisting
		// this out to also cover a nil authConfig would mean writing a field of
		// a Config that in-flight requests are already reading — an unsynchronized
		// write for a caller that does not exist today.
		hh.authConfig.OAuth2ResourceMetadata = hh.oauth2ResourceMetadataLocked()
	}

	openapiBuilder := ko.Builder{
		SecuritySchemes: hh.SecuritySchemes(),
		TypesToInclude: utils.MapSlice(host.OpenAPI.TypesToInclude, func(i kdexv1alpha1.TypeToInclude) ko.PathType {
			switch i {
			case kdexv1alpha1.TypeBACKEND:
				return ko.BackendPathType
			case kdexv1alpha1.TypeFUNCTION:
				return ko.FunctionPathType
			case kdexv1alpha1.TypePAGE:
				return ko.PagePathType
			default:
				return ko.SystemPathType
			}
		}),
	}

	hh.openapiBuilder = openapiBuilder

	hh.log.V(3).Info("[SetHost] end")
}

func (hh *HostHandler) ThemeAssetsToString() string {
	var buffer bytes.Buffer

	for _, asset := range hh.themeAssets {
		buffer.WriteString(asset.ToTag())
		buffer.WriteRune('\n')
	}

	return buffer.String()
}

func (hh *HostHandler) availableLanguages(translations *Translations) []string {
	availableLangs := make([]string, 0, len(translations.Languages()))

	for _, tag := range translations.Languages() {
		availableLangs = append(availableLangs, tag.String())
	}

	return availableLangs
}

func (hh *HostHandler) getBrandName() string {
	if hh.host == nil {
		return ""
	}
	return hh.host.BrandName
}

func (hh *HostHandler) getOrganization() string {
	if hh.host == nil {
		return ""
	}
	return hh.host.Organization
}

func (hh *HostHandler) isSecure() bool {
	return hh.scheme == schemeHTTPS
}

// issuerAddress reads hh.host and hh.scheme under hh.mu.RLock. Both are
// rewritten on every reconcile under hh.mu.Lock (SetHost), and hh.scheme is a
// string -- a two-word value the Go memory model permits to tear -- so an
// unsynchronised read is a genuine data race, not a stale-value nit.
//
// Call this ONLY from a path that holds no lock (an HTTP handler before it
// takes its own RLock, typically). A caller already holding hh.mu must call
// issuerAddressLocked instead: Go's RWMutex prohibits recursive read locking,
// and a writer queued between the two RLocks deadlocks the host. That is the
// exact shape of kdex-tech/host-manager#26 and #51, which is also why the fix
// here is a split rather than a lock inside the shared body.
func (hh *HostHandler) issuerAddress() string {
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	return hh.issuerAddressLocked()
}

// issuerAddressLocked is issuerAddress for callers that already hold hh.mu
// (read or write). Caller must hold hh.mu.
func (hh *HostHandler) issuerAddressLocked() string {
	if hh.host == nil || len(hh.host.Routing.Domains) == 0 {
		return ""
	}
	return fmt.Sprintf("%s://%s", hh.scheme, hh.host.Routing.Domains[0])
}

func (hh *HostHandler) messagePrinter(translations *Translations, tag language.Tag) *message.Printer {
	return message.NewPrinter(
		tag,
		message.Catalog(translations.Catalog()),
	)
}

func (hh *HostHandler) muxWithDefaultsLocked(registeredPaths map[string]ko.PathInfo) *http.ServeMux {
	mux := http.NewServeMux()

	hh.apitokensHandler(mux, registeredPaths)
	hh.capabilitiesHandler(mux, registeredPaths)
	hh.transferHandler(mux, registeredPaths)
	hh.authorizeHandler(mux, registeredPaths)
	hh.checkHandler(mux, registeredPaths)
	hh.discoveryHandler(mux, registeredPaths)
	hh.faviconHandler(mux, registeredPaths)
	hh.jwksHandler(mux, registeredPaths)
	hh.loginHandler(mux, registeredPaths)
	hh.navigationHandler(mux, registeredPaths)
	hh.oauthHandler(mux, registeredPaths)
	hh.openapiHandler(mux, registeredPaths)
	hh.protectedResourceHandler(mux, registeredPaths)
	hh.registerHandler(mux, registeredPaths)
	hh.schemaHandler(mux, registeredPaths)
	hh.snifferHandler(mux, registeredPaths)
	hh.stateHandler(mux, registeredPaths)
	hh.tokenHandler(mux, registeredPaths)
	hh.translationHandler(mux, registeredPaths)

	return mux
}

// unbindablePageDenyScheme is a security scheme no caller is ever granted:
// GetParsedEntitlements only ever populates the bearer/oauth2/oidc buckets, and
// base/anonymous patterns apply only under the default "bearer" scheme. A
// requirement published under it is therefore unsatisfiable for EVERY caller --
// including a wildcard (vector_stores::all) or super-wildcard (*:*:*) holder --
// because satisfaction is evaluated per scheme and this scheme is absent from
// every caller's entitlement map. It is the only fail-closed requirement value
// available in non-strict mode, where a held wildcard matches any literal
// resourceName. Reserved; must not collide with a real securityScheme name.
const unbindablePageDenyScheme = "__kdex_unbindable_placeholder_deny__"

// unbindablePageDenyRequirements is the requirement set substituted for a page
// whose security block declares a {placeholder} the page layer cannot bind. Its
// single requirement lives under unbindablePageDenyScheme, so verification
// denies every caller.
var unbindablePageDenyRequirements = []kdexv1alpha1.SecurityRequirement{
	{unbindablePageDenyScheme: {unbindablePageDenyScheme + ":deny:deny"}},
}

// parsePageRequirementsFailClosed parses a page's security requirements and
// fails closed on an unbindable {placeholder}.
//
// A page (or host-level) security requirement may reference an instance-scoped
// resource via a {placeholder}, e.g. `vector_stores:{vector_store_id}:read`.
// Unlike a KDexFunction operation, a page has NO per-request store identity and
// NO x-entitlement-binding, so the three page readers (page render,
// navigation, /-/check) never bind it -- the placeholder would verify as the
// LITERAL resourceName "{vector_store_id}", which a held wildcard
// (vector_stores::all) matches, silently admitting every wildcard holder with
// no error and no log.
//
// So probe the parsed set with an empty binding: a placeholder-free set is a
// no-op (err == nil); a placeholder-bearing one errors. On ANY bind error,
// substitute an unsatisfiable requirement so all three readers deny at one
// site. The guard is err != nil rather than errors.Is(ErrUnboundPlaceholder)
// so the future strict flip -- which makes BindRequirements also return
// ErrWildcardRequirement here -- stays fail-closed instead of falling through.
func (hh *HostHandler) parsePageRequirementsFailClosed(
	reqs []kdexv1alpha1.SecurityRequirement,
	pageName string,
	basePath string,
) entitlements.ParsedRequirements {
	parsed := hh.authChecker.ParseRequirements(reqs)
	if _, err := hh.authChecker.BindRequirements(parsed, nil); err != nil {
		hh.log.Error(err, "page security requirement declares an unbindable {placeholder}; denying all access to this page",
			"page", pageName, "basePath", basePath)
		return hh.authChecker.ParseRequirements(unbindablePageDenyRequirements)
	}
	return parsed
}

func (hh *HostHandler) pageRequirements(ph *page.PageHandler) []kdexv1alpha1.SecurityRequirement {
	var requirements []kdexv1alpha1.SecurityRequirement
	if hh.host.Security != nil {
		requirements = *hh.host.Security
	}
	if ph.Page.Security != nil {
		requirements = *ph.Page.Security
	}
	return requirements
}

func (hh *HostHandler) registerPath(path string, info ko.PathInfo, m map[string]ko.PathInfo) {
	current, ok := m[path]
	if !ok {
		if info.API.BasePath == "" {
			info.API.BasePath = path
		}
		m[path] = info
		return
	}

	ko.MergeOperations(&current.API, &info.API)

	if current.API.BasePath == "" {
		current.API.BasePath = path
	}

	m[path] = current
}

func (hh *HostHandler) renderUtilityPage(utilityType kdexv1alpha1.KDexUtilityPageType, l language.Tag, extraTemplateData map[string]any, translations *Translations) string {
	ph, ok := hh.utilityPages[utilityType]
	if !ok {
		return ""
	}

	utilityCache := hh.cacheManager.GetCache("utility", cache.CacheOptions{})
	cacheKey := ph.CacheKey(l)

	// Only attempt cache logic if there's no dynamic extra data
	if len(extraTemplateData) == 0 {
		rendered, ok, isCurrent, err := utilityCache.Get(context.Background(), cacheKey)
		if err == nil && ok {
			if isCurrent {
				return rendered // Perfect hit
			}

			// Stale Hit (vN-1): Serve fast, but migrate in background
			hh.log.Info("stale cache hit, triggering background migration", "key", cacheKey)
			go func() {
				// Hold the host's read lock for the duration of the
				// re-render so the goroutine sees consistent hh.*
				// state vs concurrent SetHost writes. Without this
				// the goroutine races on hh.host/hh.themeAssets/...
				// and an unlucky interleaving crashes the process via
				// uncaught panic in a detached goroutine (net/http's
				// per-request recover doesn't see it). Render is
				// local CPU work — holding RLock here is fine, unlike
				// the #59 case where the proxy held RLock across an
				// upstream round-trip. See kdex-tech/host-manager#73.
				hh.mu.RLock()
				defer hh.mu.RUnlock()

				// Background context to ensure it lives past the request
				bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				// Re-render to ensure any CRD changes are reflected in vN
				newRender, err := hh.L10nRender(ph, map[string]any{}, l, extraTemplateData, translations)
				if err == nil {
					_ = utilityCache.Set(bgCtx, cacheKey, newRender)
				}
			}()
			return rendered
		}
	}

	// Standard Render Path (Cache Miss or Extra Data)
	rendered, err := hh.L10nRender(ph, map[string]any{}, l, extraTemplateData, translations)
	if err != nil {
		hh.log.Error(err, "failed to render utility page", "page", ph.Name, "language", l)
		return ""
	}

	if len(extraTemplateData) == 0 {
		if err := utilityCache.Set(context.Background(), cacheKey, rendered); err != nil {
			hh.log.Error(err, "failed to set utility cache", "page", ph.Name, "language", l)
		}
	}

	return rendered
}

func (hh *HostHandler) serveError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	// Defer RUnlock so a panic anywhere on the render path (template
	// execution, cache backend, anything) releases the lock instead of
	// orphaning a reader and silently wedging every subsequent reconcile
	// on hh.mu. Same shape as the RebuildMux bug closed in #26, different
	// site. See kdex-tech/host-manager#51.
	hh.mu.RLock()
	defer hh.mu.RUnlock()

	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		l = language.Make(hh.defaultLanguage)
	}

	hh.log.V(2).Info(
		"generating error page",
		"requestURI", r.URL.Path,
		"code", code,
		"msg", msg,
		"language", l,
	)

	rendered := hh.renderUtilityPage(
		kdexv1alpha1.ErrorUtilityPageType,
		l,
		map[string]any{"ErrorCode": code, "ErrorCodeString": http.StatusText(code), "ErrorMessage": msg},
		&hh.Translations,
	)

	if rendered == "" {
		// Fallback to standard http error if no custom error page
		http.Error(w, msg, code)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Language", l.String())
	w.WriteHeader(code)
	_, _ = w.Write([]byte(rendered))
}

func (hh *HostHandler) serverAddress(r *http.Request) string {
	return fmt.Sprintf("%s://%s", hh.scheme, r.Host)
}

func toFinalPath(path string) string {
	if !strings.HasSuffix(path, "/") {
		path = path + "/"
	}
	path = path + "{$}"
	return path
}

// isSystemPath reports whether p is served by a built-in host-manager handler
// rather than a user-defined KDexPage / KDexFunction. System endpoints are
// always-on contracts (JWKS for JWT validation, OIDC/OAuth discovery, login,
// favicon, etc.) and must keep serving even when the host has no Ready pages.
// See kdex-tech/host-manager#33.
func isSystemPath(p string) bool {
	return p == "/favicon.ico" ||
		strings.HasPrefix(p, "/.well-known/") ||
		strings.HasPrefix(p, "/-/")
}

package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"net/http"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	openapi "github.com/getkin/kin-openapi/openapi3"
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

func (hh *HostHandler) RebuildMux() {
	hh.log.V(3).Info("rebuilding mux")
	hh.mu.RLock()

	if hh.host == nil {
		hh.mu.RUnlock()
		return
	}

	// copy fields that we need while under RLock
	defaultLanguageResource := hh.defaultLanguage
	translationResources := maps.Clone(hh.translationResources)

	newTranslations, err := NewTranslations(defaultLanguageResource, translationResources)
	if err != nil {
		hh.log.Error(err, "failed to rebuild translations")
		hh.mu.RUnlock()
		return
	}

	registeredPaths := map[string]ko.PathInfo{}
	maps.Copy(registeredPaths, hh.pathsCollectedInReconcile)

	mux := hh.muxWithDefaultsLocked(registeredPaths)

	pageHandlers := hh.Pages.List()

	if len(pageHandlers) == 0 && len(hh.functions) == 0 {
		mux.HandleFunc("GET /{$}", hh.notReadyHandler)
		mux.HandleFunc("GET /{l10n}/{$}", hh.notReadyHandler)

		hh.mu.RUnlock()
		hh.mu.Lock()
		defer hh.mu.Unlock()
		hh.Translations = *newTranslations
		hh.registeredPaths = registeredPaths
		hh.Mux = mux

		return
	}

	renderedPages := map[string]pageRender{}
	for _, ph := range pageHandlers {
		basePath := ph.BasePath()

		if basePath == "" {
			hh.log.V(1).Info("somehow page has empty basePath, skipping", "page", ph.Name)
			continue
		}

		// Pre-parse requirements for Power API
		if hh.authChecker != nil {
			reqs := hh.pageRequirements(&ph)
			parsed := hh.authChecker.ParseRequirements(reqs)
			hh.Pages.UpdateParsedRequirements(ph.Name, parsed)
			ph.ParsedRequirements = &parsed // Also update the local copy used for rendering
		}

		renderedPages[basePath] = pageRender{ph: ph}
	}

	functionHandlers := []functionHandler{}
	actualHandlers := map[string]*KDexFunctionHandler{}
	if hh.issuerAddress() != "" {
		for _, f := range hh.functions {
			if f.Status.State != kdexv1alpha1.KDexFunctionStateReady {
				continue
			}
			h := hh.reverseProxyHandler(&f, hh.issuerAddress())
			fh := h.(*KDexFunctionHandler)
			actualHandlers[f.Spec.API.BasePath] = fh
			functionHandlers = append(functionHandlers, functionHandler{
				basePath: f.Spec.API.BasePath,
				handler:  fh,
			})
		}
	}

	hh.mu.RUnlock()
	hh.mu.Lock()
	defer hh.mu.Unlock()

	for _, pr := range renderedPages {
		hh.addHandlerAndRegister(mux, pr, registeredPaths, newTranslations)
	}
	for _, fh := range functionHandlers {
		// Register both the exact path and the prefix path (with trailing slash)
		// to ensure all sub-paths are proxied correctly.
		mux.Handle(fh.basePath, fh.handler)
		if !strings.HasSuffix(fh.basePath, "/") {
			mux.Handle(fh.basePath+"/", fh.handler)
		}
	}

	hh.Translations = *newTranslations
	hh.registeredPaths = registeredPaths
	hh.functionHandlers = actualHandlers
	hh.Mux = mux
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

func (hh *HostHandler) SecuritySchemes() *openapi.SecuritySchemes {
	req := &openapi.SecuritySchemes{}

	if !hh.authConfig.IsAuthEnabled() {
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
					Scopes: map[string]string{
						"openid":  "standard oidc scope",
						"profile": "user profile info",
					},
					TokenURL: "/-/token",
				},
				ClientCredentials: &openapi.OAuthFlow{
					Scopes: map[string]string{
						"openid":  "standard oidc scope",
						"profile": "user profile info",
					},
					TokenURL: "/-/token",
				},
				Password: &openapi.OAuthFlow{
					Scopes: map[string]string{
						"openid":  "standard oidc scope",
						"profile": "user profile info",
					},
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
	hh.mu.RLock()
	mux := hh.Mux
	hh.mu.RUnlock()

	if hh.GetStatus() == HostStatusInitializing {
		hh.notReadyHandler(w, r)
		return
	}

	if mux == nil {
		hh.serveError(w, r, http.StatusNotFound, "not found")
		return
	}

	wrappedMux := hh.authConfig.AddAuthentication(mux, hh.authExchanger)
	wrappedMux = hh.DesignMiddleware(wrappedMux)
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
) {
	hh.log.V(3).Info("[SetHost] about to lock")

	hh.mu.Lock()
	defer func() {
		hh.mu.Unlock()
		hh.RebuildMux()
	}()

	hh.log.V(3).Info("[SetHost] obtained lock")

	hh.checksum = ""
	hh.defaultLanguage = host.DefaultLang
	hh.functions = functions
	hh.host = host
	hh.importmap = importmap
	hh.packageReferences = packageReferences
	hh.pathsCollectedInReconcile = paths
	hh.reconcileTime = time.Now()
	hh.scheme = scheme
	hh.scripts = scripts
	hh.status = status
	hh.themeAssets = themeAssets

	if err := hh.cacheManager.Cycle(hh.Checksum(), true); err != nil {
		hh.log.Error(err, "failed to cycle cache manager")
	}

	favicon := ico.NewICO(host.FaviconSVGTemplate, render.TemplateData{
		BrandName:       host.BrandName,
		DefaultLanguage: host.DefaultLang,
		Organization:    host.Organization,
	})
	favicon.SetReconcileTime(hh.reconcileTime)
	hh.favicon = favicon

	var snif *sniffer.RequestSniffer
	if host.DevMode {
		snif = &sniffer.RequestSniffer{
			BasePathRegex:   (&kdexv1alpha1.API{}).BasePathRegex(),
			Client:          hh.client,
			Functions:       functions,
			HostName:        hh.Name,
			ItemPathRegex:   (&kdexv1alpha1.API{}).ItemPathRegex(),
			OpenAPIBuilder:  hh.openapiBuilder,
			Namespace:       hh.Namespace,
			ReconcileTime:   hh.reconcileTime,
			SecuritySchemes: hh.SecuritySchemes(),
		}
	}
	hh.sniffer = snif

	hh.log.V(3).Info("[SetHost] authConfig has been set")

	if authConfig != nil {
		hh.authConfig = authConfig
		hh.authChecker = auth.NewAuthorizationChecker(authConfig.AnonymousEntitlements, hh.log.WithName("authChecker"))
		hh.authExchanger = authExchanger
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
	return hh.scheme == "https"
}

func (hh *HostHandler) issuerAddress() string {
	if len(hh.host.Routing.Domains) == 0 {
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
	hh.authorizeHandler(mux, registeredPaths)
	hh.checkHandler(mux, registeredPaths)
	hh.discoveryHandler(mux, registeredPaths)
	hh.faviconHandler(mux, registeredPaths)
	hh.jwksHandler(mux, registeredPaths)
	hh.loginHandler(mux, registeredPaths)
	hh.navigationHandler(mux, registeredPaths)
	hh.oauthHandler(mux, registeredPaths)
	hh.openapiHandler(mux, registeredPaths)
	hh.schemaHandler(mux, registeredPaths)
	hh.snifferHandler(mux, registeredPaths)
	hh.stateHandler(mux, registeredPaths)
	hh.tokenHandler(mux, registeredPaths)
	hh.translationHandler(mux, registeredPaths)

	return mux
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
	hh.mu.RLock()
	l, err := kdexhttp.GetLang(r, hh.defaultLanguage, hh.Translations.Languages())
	if err != nil {
		l = language.Make(hh.defaultLanguage)
	}

	// collect stacktrace
	stacktrace := string(debug.Stack())

	hh.log.V(2).Info("generating error page", "requestURI", r.URL.Path, "code", code, "msg", msg, "language", l, "stacktrace", stacktrace)

	rendered := hh.renderUtilityPage(
		kdexv1alpha1.ErrorUtilityPageType,
		l,
		map[string]any{"ErrorCode": code, "ErrorCodeString": http.StatusText(code), "ErrorMessage": msg},
		&hh.Translations,
	)
	hh.mu.RUnlock()

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

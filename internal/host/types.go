package host

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/host/ico"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/sniffer"
	"golang.org/x/text/language"
	"golang.org/x/text/message/catalog"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	kdexUIMetaTemplate = `<meta
	name="kdex-ui"
	data-navigation-endpoint="/-/navigation/{name}/{l10n}/{basePathMinusLeadingSlash...}"
	data-openapi-endpoint="/-/openapi"
	data-page-basepath="%s"
	data-path-check="/-/check"
	data-path-login="/-/login"
	data-path-logout="/-/logout"
	data-path-patternpath="%s"
	data-path-state="/-/state"
	data-path-separator="/-/"
	data-path-translations="/-/translation/{l10n}"
	/>
	`
)

// ProxyTimeouts holds the http.Transport timeout knobs used when proxying
// to KDexFunction backends. Zero-value fields fall back to defaults at
// transport-construction time (see newProxyTransport in proxy.go), so
// callers can leave any subset unset.
type ProxyTimeouts struct {
	// DialTimeout caps the connection-establishment phase (TCP + TLS).
	DialTimeout time.Duration
	// ResponseHeaderTimeout caps the wait between sending the request and
	// receiving the first response byte from the backend. This is the knob
	// that matters for scale-from-zero Knative cold starts.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout caps how long an unused keep-alive connection lingers
	// in the transport's pool before being closed.
	IdleConnTimeout time.Duration
}

type HostHandler struct {
	Mux          *http.ServeMux
	Name         string
	Namespace    string
	Pages        *page.PageStore
	Translations Translations

	analysisCache *AnalysisCache
	authChecker   interface {
		CalculateRequirements(string, string, []kdexv1alpha1.SecurityRequirement, ...string) ([]kdexv1alpha1.SecurityRequirement, error)
		CheckAccess(context.Context, string, string, []kdexv1alpha1.SecurityRequirement, ...string) (bool, error)
		BindRequirements(entitlements.ParsedRequirements, entitlements.Binding) (entitlements.ParsedRequirements, error)
		GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements
		ParseRequirements([]kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements
		VerifyResourceParsedEntitlements(string, string, entitlements.ParsedEntitlements, entitlements.ParsedRequirements, ...string) (bool, error)
	}
	authConfig                *auth.Config
	authExchanger             *auth.Exchanger
	cacheManager              cache.CacheManager
	checksum                  string
	client                    client.Client
	defaultLanguage           string
	favicon                   *ico.Ico
	functions                 []kdexv1alpha1.KDexFunction
	functionHandlers          map[string]*KDexFunctionHandler
	host                      *kdexv1alpha1.KDexHostSpec
	importmap                 string
	log                       logr.Logger
	mu                        sync.RWMutex
	openapiBuilder            ko.Builder
	packageReferences         []kdexv1alpha1.PackageReference
	pathsCollectedInReconcile map[string]ko.PathInfo
	proxyTimeouts             ProxyTimeouts
	reconcileTime             time.Time
	registeredPaths           map[string]ko.PathInfo
	registerLimiter           *registerLimiter
	registerLimiterOnce       sync.Once
	scheme                    string
	scripts                   []kdexv1alpha1.ScriptDef
	sniffer                   interface {
		Analyze(*http.Request) (*sniffer.AnalysisResult, error)
		DocsHandler(http.ResponseWriter, *http.Request)
	}
	status               *kdexv1alpha1.KDexObjectStatus
	themeAssets          []kdexv1alpha1.Asset
	translationResources map[string]kdexv1alpha1.KDexTranslationSpec
	utilityPages         map[kdexv1alpha1.KDexUtilityPageType]page.PageHandler
}

type HostStatus string

const (
	HostStatusInitializing HostStatus = "Initializing"
	HostStatusReady        HostStatus = "Ready"
	HostStatusDegraded     HostStatus = "Degraded"
	HostStatusProgressing  HostStatus = "Progressing"
)

func NewHostHandler(c client.Client, name string, namespace string, log logr.Logger, cacheManager cache.CacheManager) *HostHandler {
	hh := &HostHandler{
		Mux:          nil,
		Name:         name,
		Namespace:    namespace,
		Pages:        nil,
		Translations: Translations{},

		analysisCache:             NewAnalysisCache(),
		authConfig:                nil,
		authExchanger:             nil,
		cacheManager:              cacheManager,
		client:                    c,
		defaultLanguage:           "en",
		favicon:                   nil,
		functions:                 []kdexv1alpha1.KDexFunction{},
		functionHandlers:          map[string]*KDexFunctionHandler{},
		host:                      nil,
		importmap:                 "",
		log:                       log,
		packageReferences:         []kdexv1alpha1.PackageReference{},
		pathsCollectedInReconcile: map[string]ko.PathInfo{},
		reconcileTime:             time.Now(),
		registeredPaths:           map[string]ko.PathInfo{},
		scheme:                    "",
		scripts:                   []kdexv1alpha1.ScriptDef{},
		themeAssets:               []kdexv1alpha1.Asset{},
		translationResources:      map[string]kdexv1alpha1.KDexTranslationSpec{},
		utilityPages:              map[kdexv1alpha1.KDexUtilityPageType]page.PageHandler{},
	}

	translations, err := NewTranslations(hh.defaultLanguage, map[string]kdexv1alpha1.KDexTranslationSpec{})
	if err != nil {
		panic(err)
	}

	hh.Translations = *translations
	hh.Pages = page.NewPageStore(
		name,
		hh.RebuildMux,
		hh.log.WithName("pages"),
	)
	hh.RebuildMux()
	return hh
}

// SetProxyTimeouts replaces the HostHandler's proxy transport timeouts.
// Method-chain return makes it composable with NewHostHandler. Zero-valued
// fields fall back to defaults inside newProxyTransport.
func (hh *HostHandler) SetProxyTimeouts(t ProxyTimeouts) *HostHandler {
	hh.proxyTimeouts = t
	return hh
}

type Translations struct {
	catalog *catalog.Builder
	keys    []string
}

func (t *Translations) Catalog() *catalog.Builder {
	return t.catalog
}

func (t *Translations) Keys() []string {
	return t.keys
}

func (t *Translations) Languages() []language.Tag {
	return t.catalog.Languages()
}

type functionHandler struct {
	basePath string
	handler  http.Handler
}

type KDexFunctionHandler struct {
	Function           *kdexv1alpha1.KDexFunction
	Handler            http.Handler
	parsedRequirements map[string]entitlements.ParsedRequirements
	// bindingSpecs holds each route's x-entitlement-binding declaration, keyed
	// identically to parsedRequirements (method + " " + pattern). Parsed once at
	// mux-build, not per request. A route with no declaration is absent, and its
	// placeholders (if any) bind by path identity match.
	bindingSpecs map[string]bindingSpec
	patternMux   *http.ServeMux
	// acceptsAPIKey is set at handler-build time when at least one operation
	// on the function's API declares an apiKey* security scheme (apiKeyCookie /
	// apiKeyHeader / apiKeyQuery). It opts the per-function handler into the
	// PASETO->authContext bridge so the global hot path pays no PASETO cost.
	// See kdex-tech/host-manager#103.
	acceptsAPIKey bool
	// oauth2Protected is set at handler-build time when this function declares the
	// built-in "oauth2" security scheme on any operation. Like acceptsAPIKey it
	// opts the handler into the PASETO->authContext bridge, but the token is
	// validated against the function's RESOURCE audience (oauth2Resource) rather
	// than the host audience — enforcing RFC 8707 audience binding at the gate.
	oauth2Protected bool
	// oauth2Resource is the RFC 8707 resource URI (issuer + basePath) a PAT must
	// be bound to for this oauth2-protected function. Empty when not protected.
	oauth2Resource string
	// issuer is the host's issuer address, captured at handler-build time.
	issuer string
	// mintTokenEnabled opts this (oauth2-protected) MCP function into the AS
	// mint_token augmentation: tools/call name=mint_token is handled locally
	// and tools/list responses gain the mint_token descriptor. See #280.
	mintTokenEnabled bool
}

func (h *KDexFunctionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler.ServeHTTP(w, r)
}

type pageRender struct {
	ph page.PageHandler
}

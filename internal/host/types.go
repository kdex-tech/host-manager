package host

import (
	"context"
	"net/http"
	"slices"
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

// PageDenialMode selects how the page gate renders FORBIDDEN to a browser.
// It governs the HTML rendering ONLY -- a non-HTML caller gets 403 in every
// mode, because the knob is about presentation, not about the contract.
type PageDenialMode string

const (
	// PageDenialDiscover sends a browser to the first page it can reach,
	// carrying ?denied=<path>. Preserves the behaviour that predates the
	// denial contract. Default.
	PageDenialDiscover PageDenialMode = "discover"
	// PageDenialForbid renders the 403 error page instead.
	PageDenialForbid PageDenialMode = "forbid"
)

// PageDenialModes is every value --page-denial-mode accepts.
var PageDenialModes = []PageDenialMode{PageDenialDiscover, PageDenialForbid}

// IsValid reports whether m is a recognised mode. Callers that ACCEPT a mode
// from an operator must check this and refuse to start otherwise:
// SetPageDenialMode's coercion resolves an unrecognised value to the LESS
// strict mode, so a typo would otherwise buy the opposite of what was asked
// for with no diagnostic anywhere.
func (m PageDenialMode) IsValid() bool {
	return slices.Contains(PageDenialModes, m)
}

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
	pageDenialMode            PageDenialMode
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
	routeCollisions      []RouteCollision
	status               *kdexv1alpha1.KDexObjectStatus
	themeAssets          []kdexv1alpha1.Asset
	translationResources map[string]kdexv1alpha1.KDexTranslationSpec
	utilityPages         map[kdexv1alpha1.KDexUtilityPageType]page.PageHandler
}

// RouteCollision records a page registration refused during the most recent
// RebuildMux because a DIFFERENT, earlier-claimed page already owns the
// literal "METHOD /path" ServeMux pattern it wanted.
//
// This is the enumerated-per-language-prefix collision class: replacing the
// old "/{l10n}" wildcard with one literal route per supported language means
// a page whose basePath equals "/<lang>" (or "/<lang>/...") produces the
// SAME pattern as another, independently-authored page's own language-
// prefixed (or bare, for text-mime pages) route. E.g. with "en" (default)
// and "fr" supported, the home page (basePath "/") registers "GET /fr/{$}"
// as its French route, and a page at basePath "/fr" wants that exact
// pattern for its own bare route.
//
// The winner is whichever page registration-time ordering (basePath-sorted,
// see rebuildMuxSnapshot) processes first; the loser's route is refused
// outright rather than silently served or silently dropped -- see
// RouteCollisions.
type RouteCollision struct {
	// Pattern is the "METHOD /path" ServeMux pattern both pages wanted.
	Pattern string
	// WinnerName / WinnerBasePath identify the page that keeps the route.
	WinnerName     string
	WinnerBasePath string
	// LoserName / LoserBasePath identify the page whose registration for
	// Pattern was refused.
	LoserName     string
	LoserBasePath string
}

// RouteCollisions returns the page-vs-page route collisions detected by the
// most recent RebuildMux. Empty when none were found. Callers (e.g. the
// KDexInternalHost reconciler) use this to surface a Degraded status
// condition -- registration itself never silently serves or drops a
// colliding route without recording it here.
func (hh *HostHandler) RouteCollisions() []RouteCollision {
	hh.mu.RLock()
	defer hh.mu.RUnlock()
	return slices.Clone(hh.routeCollisions)
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

// SetPageDenialMode replaces the HostHandler's page-denial rendering mode.
// An empty or unrecognised value resolves to PageDenialDiscover.
//
// This coercion is a SAFETY NET, not the validation. It resolves to the LESS
// strict mode, so an operator typo reaching here would silently buy the
// opposite of what was asked for -- which is why cmd/main.go refuses to start
// on anything that is not exactly "discover" or "forbid", and why a coercion
// that does happen is logged at V(0): reaching it means something bypassed
// that check.
func (hh *HostHandler) SetPageDenialMode(m PageDenialMode) *HostHandler {
	if m != PageDenialForbid && m != PageDenialDiscover {
		hh.log.V(0).Info("unrecognised page denial mode; coercing to the default",
			"value", string(m), "coercedTo", string(PageDenialDiscover))
	}
	if m != PageDenialForbid {
		m = PageDenialDiscover
	}
	hh.pageDenialMode = m
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
	// oauth2Scopes is the de-duplicated union of the oauth2 scheme's scopes
	// across this function's operations -- the same union
	// oauth2ProtectedResources() already computes. Named in an
	// insufficient_scope challenge so a client can step up rather than
	// dead-end. Empty when the function is not oauth2-protected.
	oauth2Scopes []string
	// issuer is the host's issuer address, captured at handler-build time.
	issuer string
	// asToolsEnabled opts this (oauth2-protected) MCP function into the AS tool
	// augmentation: a tools/call for an AS-provided tool is answered locally and
	// never forwarded, and tools/list responses gain that tool's descriptor.
	//
	// It currently covers BOTH mint_token and whoami (see whoami.go), and is
	// still driven by spec.auth.mintToken.enabled -- so disabling mint_token
	// also removes whoami. That coupling is deliberate for now (they are peers
	// on one interception path and share one splice) but it is NOT obvious from
	// the CR field name, so an operator turning mint_token off should expect
	// whoami to disappear with it.
	asToolsEnabled bool
}

func (h *KDexFunctionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler.ServeHTTP(w, r)
}

type pageRender struct {
	ph page.PageHandler
}

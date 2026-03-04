package host

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/entitlements"
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
	data-path-translations="/-/translations/{l10n}"
	/>
	`
)

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
	host                      *kdexv1alpha1.KDexHostSpec
	importmap                 string
	log                       logr.Logger
	mu                        sync.RWMutex
	openapiBuilder            ko.Builder
	packageReferences         []kdexv1alpha1.PackageReference
	pathsCollectedInReconcile map[string]ko.PathInfo
	reconcileTime             time.Time
	registeredPaths           map[string]ko.PathInfo
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
	Function *kdexv1alpha1.KDexFunction
	Handler  http.Handler
}

func (h *KDexFunctionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Handler.ServeHTTP(w, r)
}

type pageRender struct {
	ph page.PageHandler
}

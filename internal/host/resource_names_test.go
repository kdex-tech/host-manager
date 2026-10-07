package host

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openapi "github.com/getkin/kin-openapi/openapi3"
	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	ko "github.com/kdex-tech/host-manager/internal/openapi"
	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// ownerCall records what the declaring function's route received.
type ownerCall struct {
	method, rawQuery, sub string
	hit                   bool
}

type namesFixture struct {
	mux   *http.ServeMux
	hh    *HostHandler
	owner *ownerCall
	// ownerStatus / ownerBody are what the stand-in for the owning function's
	// route answers (its gate + upstream).
	ownerStatus int
	ownerBody   string
}

func listingPath(resource string) ko.PathInfo {
	return ko.PathInfo{
		Type: ko.FunctionPathType,
		API: ko.OpenAPI{Paths: map[string]ko.PathItem{
			"/api/v1/" + resource: {Get: &openapi.Operation{
				Extensions: map[string]any{kdexResourceListingExtension: map[string]any{"resource": resource}},
			}},
		}},
	}
}

func newNamesFixture(t *testing.T) *namesFixture {
	t.Helper()
	cm, err := cache.NewCacheManager("", "names-test", nil)
	require.NoError(t, err)
	hh := NewHostHandler(nil, "test-host", "default", logr.Discard(), cm)
	hh.scheme = "https"
	hh.host = &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{"names.example"}}}
	hh.authChecker = auth.NewAuthorizationChecker(nil, logr.Discard())

	ready := func(name, basePath string, internal bool) kdexv1alpha1.KDexFunction {
		return kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       kdexv1alpha1.KDexFunctionSpec{API: kdexv1alpha1.API{BasePath: basePath}, Internal: internal},
			Status:     kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady},
		}
	}
	hh.functions = []kdexv1alpha1.KDexFunction{
		ready("roles", "/api/v1/roles", false),
		ready("files", "/api/v1/files", false),
		ready("secret", "/api/v1/secret", true), // internal: never exposed
	}

	gated := func(name, label, basePath string) page.PageHandler {
		return page.PageHandler{Name: name,
			Page:               &kdexv1alpha1.KDexPageSpec{Label: label, Paths: kdexv1alpha1.Paths{BasePath: basePath}},
			ParsedRequirements: &entitlements.ParsedRequirements{}}
	}
	hh.Pages.Set(gated("public", "Welcome", "/public"))
	hh.Pages.Set(gated("gated", "Members Area", "/gated"))
	hh.Pages.Set(gated("hidden", "Back Office", "/hidden"))
	// Pages.Set rebuilds the mux, which replaces registeredPaths: set them
	// afterwards.
	hh.registeredPaths = map[string]ko.PathInfo{"/api/v1/roles": listingPath("roles")}

	f := &namesFixture{hh: hh, owner: &ownerCall{}, ownerStatus: http.StatusOK,
		ownerBody: `{"items":[{"name":"analysts","label":"Data Analysts"},{"name":"engineers"}],"next":"c2"}`}
	f.mux = http.NewServeMux()
	f.mux.HandleFunc("GET /api/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		f.owner.hit = true
		f.owner.method = r.Method
		f.owner.rawQuery = r.URL.RawQuery
		if ac, ok := auth.GetAuthContext(r.Context()); ok {
			f.owner.sub, _ = ac.GetSubject()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.ownerStatus)
		_, _ = w.Write([]byte(f.ownerBody))
	})
	paths := map[string]ko.PathInfo{}
	hh.resourceNamesHandler(f.mux, paths)
	assert.Contains(t, paths, resourceNamesPath)
	return f
}

type namesBody struct {
	Items []struct {
		Name  string `json:"name"`
		Label string `json:"label,omitempty"`
	} `json:"items"`
	Next string `json:"next,omitempty"`
}

func (f *namesFixture) get(t *testing.T, target string, held []string) (int, namesBody) {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	if held != nil {
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": "tester", "entitlements": held}))
	}
	rr := httptest.NewRecorder()
	f.mux.ServeHTTP(rr, req)
	var body namesBody
	if rr.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body), rr.Body.String())
		assert.Contains(t, rr.Header().Get("Cache-Control"), "private")
	}
	return rr.Code, body
}

// names returns the items' names (the resourceNames).
func names(b namesBody) []string {
	out := []string{}
	for _, i := range b.Items {
		out = append(out, i.Name)
	}
	return out
}

// An owned resource is listed by re-dispatching to the declaring function's
// route WITH THE CALLER'S CREDENTIALS (its own gate runs), forwarding only q
// and cursor.
func TestResourceNames_OwnedIsDispatchedToTheOwner(t *testing.T) {
	f := newNamesFixture(t)
	code, body := f.get(t, "/-/entitlements/resources/roles/names?q=a&cursor=c1&limit=2&verb=&smuggled=1", []string{"x"})
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"analysts", "engineers"}, names(body))
	assert.Equal(t, "Data Analysts", body.Items[0].Label)
	assert.Empty(t, body.Items[1].Label, "label is optional")
	assert.Equal(t, "c2", body.Next)

	assert.True(t, f.owner.hit)
	assert.Equal(t, http.MethodGet, f.owner.method)
	assert.Equal(t, "cursor=c1&limit=2&q=a", f.owner.rawQuery, "only q, cursor and limit reach the owner")
	assert.Equal(t, "tester", f.owner.sub, "the owner sees the caller, not the host")
}

// ?verb= narrows the owner's page to names the caller can grant for that verb.
func TestResourceNames_VerbClampsToGrantableNames(t *testing.T) {
	f := newNamesFixture(t)
	code, body := f.get(t, "/-/entitlements/resources/roles/names?verb=assign", []string{"roles:analysts:assign"})
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, []string{"analysts"}, names(body))
	assert.Equal(t, "c2", body.Next, "the owner's cursor still pages the unfiltered list")

	_, body = f.get(t, "/-/entitlements/resources/roles/names?verb=assign", []string{"roles::all"})
	assert.Equal(t, []string{"analysts", "engineers"}, names(body))
}

func TestResourceNames_OwnerDenialPassesThrough(t *testing.T) {
	f := newNamesFixture(t)
	f.ownerStatus = http.StatusForbidden
	f.ownerBody = "Forbidden"
	code, _ := f.get(t, "/-/entitlements/resources/roles/names", []string{"x"})
	assert.Equal(t, http.StatusForbidden, code)
}

func TestResourceNames_MalformedOwnerResponseIsBadGateway(t *testing.T) {
	f := newNamesFixture(t)
	f.ownerBody = `{"items":[{"label":"no name"}]}`
	code, _ := f.get(t, "/-/entitlements/resources/roles/names", []string{"x"})
	assert.Equal(t, http.StatusBadGateway, code)
}

func TestResourceNames_UnknownResourceIs404(t *testing.T) {
	f := newNamesFixture(t)
	code, _ := f.get(t, "/-/entitlements/resources/invoices/names", []string{"x"})
	assert.Equal(t, http.StatusNotFound, code)
	assert.False(t, f.owner.hit)
}

// Two functions declaring a listing for one resource is a configuration fault:
// neither is chosen silently.
func TestResourceNames_ConflictingDeclarationsFailClosed(t *testing.T) {
	f := newNamesFixture(t)
	other := listingPath("roles")
	other.API.Paths = map[string]ko.PathItem{"/api/v1/files/roles": other.API.Paths["/api/v1/roles"]}
	f.hh.registeredPaths["/api/v1/files/roles"] = other
	code, _ := f.get(t, "/-/entitlements/resources/roles/names", []string{"x"})
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.False(t, f.owner.hit)
}

func TestResourceNames_AnonymousIsChallenged(t *testing.T) {
	f := newNamesFixture(t)
	code, _ := f.get(t, "/-/entitlements/resources/roles/names", nil)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.False(t, f.owner.hit)
}

// pages are answered by the host: a page is listed when the caller passes its
// gate (the page gate's own rule), labelled with the page label, sorted by
// label.
func TestResourceNames_PagesAreHostNative(t *testing.T) {
	f := newNamesFixture(t)
	held := []string{"pages:/gated:read", "pages:/public:read"}

	_, body := f.get(t, "/-/entitlements/resources/pages/names", held)
	assert.Equal(t, []string{"/gated", "/public"}, names(body), "/hidden is gated and not held; sorted by label")
	assert.Equal(t, "Members Area", body.Items[0].Label)
	assert.Equal(t, "Welcome", body.Items[1].Label)

	_, body = f.get(t, "/-/entitlements/resources/pages/names?verb=read", []string{"pages:/gated:read"})
	assert.Equal(t, []string{"/gated"}, names(body))
}

// q is a type-ahead: a case-insensitive substring of EITHER the name (the
// name) or the label.
func TestResourceNames_TypeAheadMatchesEitherField(t *testing.T) {
	f := newNamesFixture(t)
	held := []string{"pages::read"}
	for q, want := range map[string][]string{
		"area": {"/gated"},                       // label, mid-word, case-insensitive
		"BACK": {"/hidden"},                      // label, case-insensitive
		"/pub": {"/public"},                      // resourceName
		"e":    {"/hidden", "/gated", "/public"}, // Back Office, Members Area, Welcome
		"zzz":  {},
	} {
		code, body := f.get(t, "/-/entitlements/resources/pages/names?q="+q, held)
		require.Equal(t, http.StatusOK, code, q)
		assert.Equal(t, want, names(body), "q=%s", q)
	}
}

// Results are paged: limit (default 50, at most 200) bounds a page, and the
// opaque next cursor resumes after its last item.
func TestResourceNames_Paging(t *testing.T) {
	f := newNamesFixture(t)
	held := []string{"pages::read"}

	_, p1 := f.get(t, "/-/entitlements/resources/pages/names?limit=2", held)
	assert.Equal(t, []string{"/hidden", "/gated"}, names(p1), "Back Office, Members Area")
	require.NotEmpty(t, p1.Next)

	_, p2 := f.get(t, "/-/entitlements/resources/pages/names?limit=2&cursor="+p1.Next, held)
	assert.Equal(t, []string{"/public"}, names(p2))
	assert.Empty(t, p2.Next, "the last page has no next")

	for _, bad := range []string{"limit=0", "limit=201", "limit=x", "cursor=not-a-cursor"} {
		code, _ := f.get(t, "/-/entitlements/resources/pages/names?"+bad, held)
		assert.Equal(t, http.StatusBadRequest, code, bad)
	}
}

// An owner must honour limit: more items than asked for is a broken contract.
func TestResourceNames_OwnerExceedingLimitIsBadGateway(t *testing.T) {
	f := newNamesFixture(t)
	code, _ := f.get(t, "/-/entitlements/resources/roles/names?limit=1", []string{"x"})
	assert.Equal(t, http.StatusBadGateway, code)
}

// functions are answered by the host: ready, non-internal functions whose
// identity (functions:<basePath>:read) the caller passes.
func TestResourceNames_FunctionsAreHostNative(t *testing.T) {
	f := newNamesFixture(t)
	_, body := f.get(t, "/-/entitlements/resources/functions/names", []string{"functions:/api/v1/roles:read"})
	assert.Equal(t, []string{"/api/v1/roles"}, names(body))
	assert.Equal(t, "roles", body.Items[0].Label, "a function is labelled with its KDexFunction name")

	_, body = f.get(t, "/-/entitlements/resources/functions/names", []string{"functions::read"})
	assert.Equal(t, []string{"/api/v1/files", "/api/v1/roles"}, names(body), "internal functions are never listed; sorted by label")
}

// A function cannot claim a host-native resource.
func TestResourceNames_HostNativeResourcesCannotBeClaimed(t *testing.T) {
	f := newNamesFixture(t)
	f.hh.registeredPaths["/api/v1/pages"] = listingPath("pages")
	_, body := f.get(t, "/-/entitlements/resources/pages/names", []string{"pages::read"})
	assert.Equal(t, []string{"/hidden", "/gated", "/public"}, names(body))
	assert.False(t, f.owner.hit)
}
